"""Controlli macOS su file system, pacchetti (Homebrew), kernel e log (sola lettura).

Completano collectors/macos.py: con questi anche `filesystem`, `packages`, `kernel` e
`logging` hanno una versione per macOS invece di risultare "non applicabili".

- filesystem: spazio sul volume dei dati, file scrivibili da tutti nelle cartelle dei
  programmi e di avvio, SUID fuori dal sistema, permessi di /etc/sudoers e delle home;
- packages: pacchetti Homebrew da aggiornare (dalla cache locale, senza rete);
- kernel: inoltro IP, estensioni del kernel di terze parti caricate;
- logging: log del firewall applicativo, file di log scrivibili da tutti.

I file di sistema di macOS stanno su un volume in sola lettura protetto da SIP (vedi il
controllo `protections`), quindi qui si guardano solo le cartelle modificabili.
"""
from __future__ import annotations

import json
import re

from risk_assessor.collectors._platform import unverifiable
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.collectors.macos import SOCKETFILTERFW, _f
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import host_info
from risk_assessor.models import Confidence, Finding, Severity

# Cartelle modificabili in cui un file scrivibile da tutti permette di cambiare ciò che
# viene eseguito (programmi di terze parti, elementi di avvio).
_WRITABLE_DIRS = ["/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin", "/opt/homebrew/sbin",
                  "/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/StartupItems", "/private/etc"]
# Su macOS /etc e /var/log sono link a /private/...: si usano i percorsi reali (e find -H).
_LOG_DIRS = ["/private/var/log", "/Library/Logs"]
_SUID_DIRS = ["/usr/local", "/opt", "/Library"]
_DATA_VOLUMES = ("/System/Volumes/Data", "/")
_MAX_SHOWN = 15


def _existing(executor: BaseExecutor, dirs: list[str]) -> list[str]:
    out, _, _ = executor.execute_command(
        ["sh", "-c", 'for d in "$@"; do [ -d "$d" ] && printf "%s\\n" "$d"; done; exit 0', "sh", *dirs])
    return [d for d in out.splitlines() if d in dirs]


def _find(executor: BaseExecutor, dirs: list[str], *expr: str) -> list[str] | None:
    """Percorsi trovati da find (BSD) nelle cartelle esistenti; None se find non ha funzionato."""
    dirs = _existing(executor, dirs)
    if not dirs:
        return []
    res = run_privileged(executor, ["find", "-H", *dirs, "-xdev", *expr])
    if res.status in ("absent",):
        return None
    if not res.ok and not res.out.strip():
        return None
    return [ln.strip() for ln in res.out.splitlines() if ln.strip().startswith("/")]


# ------------------------------------------------------------------------ file system
class MacFilesystemCollector:
    name = "filesystem"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._disk(executor)
        writable = _find(executor, _WRITABLE_DIRS, "-maxdepth", "2", "-type", "f", "-perm", "-0002")
        if writable is None:
            findings.append(unverifiable(
                "File scrivibili da tutti non verificabili", "find non ha potuto leggere le cartelle dei programmi.",
                ", ".join(_WRITABLE_DIRS), "filesystem:world-writable-unverifiable", "filesystem"))
        elif writable:
            findings.append(_f(
                f"File scrivibili da tutti in cartelle di programmi o di avvio: {len(writable)}", Severity.HIGH,
                "Qualsiasi utente può modificare questi file: se sono programmi o elementi di avvio, può far "
                "eseguire il proprio codice a chi li lancia (anche root).", "\n".join(writable[:_MAX_SHOWN]),
                "Togliere il permesso di scrittura agli altri utenti (chmod o-w).",
                "filesystem:world-writable", "filesystem", command=""))
        suid = _find(executor, _SUID_DIRS, "-maxdepth", "6", "-type", "f", "-perm", "-4000")
        if suid is None:
            findings.append(unverifiable(
                "Programmi SUID non verificabili", "find non ha potuto leggere le cartelle dei programmi.",
                ", ".join(_SUID_DIRS), "filesystem:suid-unverifiable", "filesystem"))
        elif suid:
            findings.append(_f(
                f"Programmi SUID fuori dal sistema: {len(suid)}", Severity.MEDIUM,
                "Programmi di terze parti che girano con i privilegi del proprietario (spesso root): una loro "
                "vulnerabilità diventa un modo per ottenere root.", "\n".join(suid[:_MAX_SHOWN]),
                "Verificare che ognuno serva davvero e venga da una fonte affidabile.",
                "filesystem:suid", "filesystem", Confidence.MEDIUM))
        findings += self._sudoers(executor)
        findings += self._homes(executor)
        return findings

    @staticmethod
    def _disk(executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["df", "-P", "-k"])
        if rc != 0:
            return []
        for wanted in _DATA_VOLUMES:            # il volume dei dati, se c'è (APFS), altrimenti /
            for line in out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 6 and parts[-1] == wanted:
                    try:
                        pct = int(parts[-2].rstrip("%"))
                    except ValueError:
                        return []
                    if pct >= 90:
                        return [_f(f"Disco quasi pieno: {wanted} ({pct}%)", Severity.MEDIUM,
                                   "Con il disco pieno i log e gli aggiornamenti smettono di funzionare.",
                                   line.strip(), "Liberare spazio.", "filesystem:disk-usage", "filesystem")]
                    return []
        return []

    @staticmethod
    def _sudoers(executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["stat", "-f", "%Lp %Su", "/etc/sudoers"])
        m = re.fullmatch(r"([0-7]{3,4}) (\S+)", out.strip()) if rc == 0 else None
        if not m:
            return []
        mode, owner = int(m.group(1), 8), m.group(2)
        if owner != "root" or mode & 0o022:
            return [_f("Permessi di /etc/sudoers non sicuri", Severity.HIGH,
                       "Chi può modificare /etc/sudoers può darsi i privilegi di root.",
                       f"/etc/sudoers: {m.group(1)} {owner}", "Ripristinare proprietario root e permessi 440.",
                       "filesystem:sudoers-perms", "filesystem",
                       command="sudo chown root:wheel /etc/sudoers && sudo chmod 440 /etc/sudoers")]
        return []

    @staticmethod
    def _homes(executor) -> list[Finding]:
        out, _, rc = executor.execute_command(
            ["sh", "-c", 'for d in /Users/*; do [ -d "$d" ] && stat -f "%Lp %N" "$d"; done; exit 0'])
        if rc != 0:
            return []
        open_homes = []
        for line in out.splitlines():
            m = re.fullmatch(r"([0-7]{3,4}) (/Users/[^/]+)", line.strip())
            if not m or m.group(2) in ("/Users/Shared", "/Users/Guest"):
                continue
            if int(m.group(1), 8) & 0o007:
                open_homes.append(f"{m.group(2)} ({m.group(1)})")
        if not open_homes:
            return []
        return [_f(f"Cartelle home accessibili agli altri utenti: {len(open_homes)}", Severity.LOW,
                   "Gli altri utenti del Mac possono vedere il contenuto di queste cartelle home.",
                   "\n".join(open_homes), "Impostare i permessi a 700 o 750.",
                   "filesystem:home-perms", "filesystem", Confidence.MEDIUM)]


# ------------------------------------------------------------------------ Homebrew
class MacPackagesCollector:
    name = "packages"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        brew = (host_info(executor).commands or {}).get("brew")
        if not brew:
            return [_f("Homebrew non installato", Severity.INFO,
                       "Nessun gestore di pacchetti di terze parti: gli aggiornamenti di macOS sono nel controllo "
                       "'updates'.", "brew non trovato", "Nessuna azione richiesta.",
                       "packages:brew-absent", "packages")]
        env = ["env", "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_ENV_HINTS=1"]
        out, err, rc = executor.execute_command([*env, brew, "outdated", "--json=v2"], timeout=180)
        try:
            data = json.loads(out) if rc == 0 else None
        except ValueError:
            data = None
        if not isinstance(data, dict):
            return [unverifiable(
                "Pacchetti Homebrew non verificabili",
                "brew outdated non ha risposto (per esempio perché Homebrew appartiene a un altro utente: "
                "non va mai eseguito come root).", (err or out).strip()[:300],
                "packages:brew-unverifiable", "packages")]
        rows = []
        for kind in ("formulae", "casks"):
            for item in data.get(kind) or []:
                if not isinstance(item, dict):
                    continue
                installed = ", ".join(str(v) for v in (item.get("installed_versions") or [])[:2])
                rows.append(f"{item.get('name', '?')}: {installed} → {item.get('current_version', '?')}"
                            + (" (bloccato)" if item.get("pinned") else ""))
        if not rows:
            return []
        return [_f(f"Pacchetti Homebrew da aggiornare: {len(rows)}", Severity.MEDIUM,
                   "Programmi installati con Homebrew hanno versioni più recenti, che spesso correggono "
                   "vulnerabilità. Il confronto usa l'ultimo elenco scaricato da Homebrew (nessun accesso alla rete "
                   "durante il controllo).", "\n".join(rows[:_MAX_SHOWN]),
                   "Aggiornare con brew upgrade (come utente proprietario di Homebrew, non con sudo).",
                   "packages:brew-outdated", "packages", Confidence.MEDIUM, command="brew update && brew upgrade")]


# --------------------------------------------------------------------------- kernel
_KEXT_RE = re.compile(r"\s((?:[A-Za-z0-9_-]+\.){2,}[A-Za-z0-9_-]+)\s+\(")


def parse_loaded_kexts(text: str) -> list[str]:
    """Bundle ID delle estensioni del kernel nell'output di `kmutil showloaded` (o kextstat)."""
    seen: list[str] = []
    for line in text.splitlines():
        m = _KEXT_RE.search(line)
        if m and m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


class MacKernelCollector:
    name = "kernel"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["sysctl", "-n", "net.inet.ip.forwarding"])
        if rc == 0 and out.strip() == "1":
            findings.append(_f(
                "Inoltro IP attivo", Severity.MEDIUM,
                "Il Mac inoltra pacchetti tra le reti come un router: se non è voluto (condivisione Internet, "
                "macchine virtuali), può far passare traffico tra reti che dovrebbero restare separate.",
                "net.inet.ip.forwarding = 1", "Disattivarlo se non serve.",
                "kernel:ip-forwarding", "kernel", command="sudo sysctl -w net.inet.ip.forwarding=0"))
        out, _, rc = executor.execute_command(["kmutil", "showloaded", "--list-only"], timeout=60)
        if rc != 0:
            out, _, rc = executor.execute_command(["kextstat", "-l"], timeout=60)
        if rc != 0:
            findings.append(unverifiable(
                "Estensioni del kernel non verificabili",
                "Né kmutil né kextstat hanno risposto: non si sa quali estensioni sono caricate.",
                out.strip()[:200], "kernel:kexts-unverifiable", "kernel"))
            return findings
        kexts = parse_loaded_kexts(out)
        third = [k for k in kexts if not k.startswith("com.apple.")]
        if third:
            findings.append(_f(
                f"Estensioni del kernel di terze parti caricate: {len(third)}", Severity.LOW,
                "Codice di terze parti che gira con i massimi privilegi: un suo difetto compromette tutto il "
                "sistema. Apple consiglia le estensioni di sistema, che girano fuori dal kernel.",
                "\n".join(third[:_MAX_SHOWN]), "Rimuovere quelle che non servono o che non si riconoscono.",
                "kernel:third-party-kexts", "kernel", Confidence.MEDIUM))
        return findings


# ----------------------------------------------------------------------------- log
class MacLoggingCollector:
    name = "logging"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command([SOCKETFILTERFW, "--getloggingmode"])
        low = out.lower()
        if "usage:" in low:
            pass    # macOS 26 non ha più --getloggingmode: il log del firewall non si configura così
        elif rc != 0 or not re.search(r"\b(on|off)\b", low):
            findings.append(unverifiable(
                "Log del firewall non verificabile", "socketfilterfw non ha detto se il log è attivo.",
                out.strip()[:200], "logging:firewall-log-unknown", "logging"))
        elif re.search(r"\boff\b", low):
            findings.append(_f(
                "Log del firewall disattivato", Severity.LOW,
                "Le connessioni bloccate dal firewall non vengono registrate: dopo un incidente manca una traccia.",
                out.strip(), "Attivare il log del firewall.", "logging:firewall-log-off", "logging",
                command=f"sudo {SOCKETFILTERFW} --setloggingmode on"))
        writable = _find(executor, _LOG_DIRS, "-maxdepth", "2", "-type", "f", "-perm", "-0002")
        if writable is None:
            findings.append(unverifiable(
                "Permessi dei log non verificabili", "find non ha potuto leggere le cartelle dei log.",
                ", ".join(_LOG_DIRS), "logging:logs-unverifiable", "logging"))
        elif writable:
            findings.append(_f(
                f"File di log scrivibili da tutti: {len(writable)}", Severity.MEDIUM,
                "Qualsiasi utente può modificare o cancellare questi log, anche per nascondere le proprie tracce.",
                "\n".join(writable[:_MAX_SHOWN]), "Togliere il permesso di scrittura agli altri utenti.",
                "logging:world-writable-logs", "logging"))
        return findings

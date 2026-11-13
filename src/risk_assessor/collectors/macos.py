"""Controlli nativi per macOS (sola lettura).

Stessi nomi dei controlli Linux, così `--tools firewall` vale su entrambi; ognuno usa gli
strumenti di macOS:

- linux (sistema): sw_vers, architettura;
- users: amministratori, root abilitato, account ospite, accesso automatico, UID 0;
- ssh_config: Accesso remoto (sshd) e, se attivo, gli stessi controlli di Linux;
- firewall: firewall applicativo (socketfilterfw) e modalità stealth;
- services: porte in ascolto (netstat) e condivisioni attive (schermo, file, eventi remoti);
- auth_policy: policy delle password (pwpolicy) e regole sudo;
- updates: aggiornamenti automatici e aggiornamenti in attesa (dalle preferenze di sistema,
  senza contattare Apple: è veloce e non usa la rete);
- persistence: LaunchDaemons/LaunchAgents di terze parti, crontab, chiavi SSH autorizzate;
- protections: SIP, FileVault, Gatekeeper.

Le preferenze vengono lette con `plutil -convert xml1` e interpretate con plistlib, che
rifiuta le entità XML: il contenuto arriva dal target ed è trattato come non fidato.
"""
from __future__ import annotations

import plistlib
import re

from risk_assessor.collectors._platform import unverifiable
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.collectors.auth_policy import AuthPolicyCollector
from risk_assessor.collectors.persistence import suspicious_reason
from risk_assessor.collectors.services import ANY_ADDRESS, DANGEROUS_PORTS, INTERNAL_PORTS
from risk_assessor.collectors.ssh_config import SSHConfigCollector
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Confidence, Finding, Severity

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
SOFTWARE_UPDATE_PLIST = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
LOGINWINDOW_PLIST = "/Library/Preferences/com.apple.loginwindow.plist"

# Servizi di condivisione di macOS (etichette di launchd) e quanto pesano se attivi.
SHARING_SERVICES = {
    "com.apple.screensharing": ("Condivisione schermo (VNC)", Severity.MEDIUM,
                                "Chi ha le credenziali può controllare il Mac da remoto; VNC è un bersaglio frequente."),
    "com.apple.AEServer": ("Eventi Apple remoti", Severity.MEDIUM,
                           "Permette ad altri computer di comandare le applicazioni di questo Mac."),
    "com.apple.ftpd": ("Server FTP", Severity.HIGH, "FTP trasmette credenziali e file in chiaro."),
    "com.apple.smbd": ("Condivisione file (SMB)", Severity.LOW,
                       "Cartelle condivise in rete: verificare che servano e a chi sono accessibili."),
    "com.apple.RemoteDesktop.agent": ("Gestione remota (Apple Remote Desktop)", Severity.MEDIUM,
                                      "Controllo completo del Mac da remoto."),
}


def _f(title, sev, desc, evidence, reco, source, category, conf=Confidence.HIGH, command=""):
    return Finding(title=title, category=category, severity=sev, description=desc,
                   evidence=evidence[:500], recommendation=reco, source=source,
                   confidence=conf, command=command)


def read_plist(executor: BaseExecutor, path: str, privileged: bool = False) -> dict | None:
    """Contenuto di un file plist (binario o XML) del target, o None se non leggibile."""
    cmd = ["plutil", "-convert", "xml1", "-o", "-", path]
    if privileged:
        res = run_privileged(executor, cmd)
        text, ok = res.out, res.ok
    else:
        text, _, rc = executor.execute_command(cmd)
        ok = rc == 0
    if not ok or not text.strip():
        return None
    try:
        data = plistlib.loads(text.encode("utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def launchd_overrides(executor: BaseExecutor) -> dict[str, bool] | None:
    """Servizi di sistema abilitati/disabilitati esplicitamente (`launchctl print-disabled system`).

    None se launchctl non ha risposto: in quel caso non si sa nulla dei servizi.
    """
    out, _, rc = executor.execute_command(["launchctl", "print-disabled", "system"])
    result: dict[str, bool] = {}
    if rc != 0:
        return None
    for m in re.finditer(r'"([^"]+)"\s*=>\s*(enabled|disabled|true|false)', out):
        result[m.group(1)] = m.group(2) in ("enabled", "false")   # "false" = non disabilitato
    return result


def parse_bsd_netstat(text: str) -> list[tuple[str, str, str]]:
    """Righe di `netstat -an` di macOS -> [(tcp|udp, indirizzo, porta)] in ascolto."""
    result = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or not parts[0].startswith(("tcp", "udp")):
            continue
        proto = "tcp" if parts[0].startswith("tcp") else "udp"
        if proto == "tcp" and (len(parts) < 6 or parts[5] != "LISTEN"):
            continue
        local = parts[3]
        addr, sep, port = local.rpartition(".")
        if not sep or not port.isdigit():
            continue
        result.append((proto, addr, port))
    return result


# --------------------------------------------------------------------------- sistema
class MacSystemCollector:
    name = "linux"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        out, _, rc = executor.execute_command(["sw_vers"])
        if rc != 0:
            return []
        info = {}
        for line in out.splitlines():
            key, _, value = line.partition(":")
            if value.strip():
                info[key.strip()] = value.strip()
        arch = executor.execute_command(["uname", "-m"])[0].strip()
        host = executor.execute_command(["hostname"])[0].strip()
        summary = f"{info.get('ProductName', 'macOS')} {info.get('ProductVersion', '')} " \
                  f"(build {info.get('BuildVersion', '?')}), {arch}"
        evidence = "\n".join(f"{k}: {v}" for k, v in
                             [*info.items(), ("architecture", arch), ("hostname", host)] if v)
        return [_f("Informazioni di sistema", Severity.INFO, f"Sistema rilevato: {summary}",
                   evidence, "Nessuna azione richiesta.", "macos:system", "system_info")]


# ---------------------------------------------------------------------------- utenti
class MacUsersCollector:
    name = "users"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["dscl", ".", "-list", "/Users", "UniqueID"])
        if rc == 0:
            uid0 = [ln.split()[0] for ln in out.splitlines()
                    if len(ln.split()) == 2 and ln.split()[1] == "0" and ln.split()[0] != "root"]
            if uid0:
                findings.append(_f(
                    f"Account con UID 0 oltre a root: {', '.join(uid0)}", Severity.CRITICAL,
                    "Un account con UID 0 ha gli stessi poteri di root.", "\n".join(uid0),
                    "Verificare e rimuovere gli account non autorizzati.", "macos:uid0", "users"))

        out, _, rc = executor.execute_command(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"])
        if rc == 0 and ":" in out:
            admins = [u for u in out.split(":", 1)[1].split() if u not in ("root", "_mbsetupuser")]
            findings.append(_f(
                f"Amministratori: {', '.join(admins) or 'nessuno oltre a root'}",
                Severity.LOW if len(admins) > 3 else Severity.INFO,
                "Gli amministratori possono installare software e cambiare qualsiasi impostazione."
                + (" Sono molti: ogni account è un possibile accesso completo." if len(admins) > 3 else ""),
                ", ".join(admins), "Lasciare i privilegi di amministratore solo a chi li usa davvero.",
                "macos:admins", "users", Confidence.HIGH))

        out, err, rc = executor.execute_command(["dscl", ".", "-read", "/Users/root", "AuthenticationAuthority"])
        if rc == 0 and "ShadowHash" in out:
            findings.append(_f(
                "Account root abilitato", Severity.MEDIUM,
                "Su macOS root è disattivato di default: abilitarlo crea un account con poteri totali e "
                "una password in più da proteggere.", "root ha una password (AuthenticationAuthority)",
                "Disattivare root (Utility Directory) e usare sudo da un amministratore.",
                "macos:root-enabled", "users", command="sudo dsenableroot -d"))

        login = read_plist(executor, LOGINWINDOW_PLIST) or {}
        if login.get("GuestEnabled") in (True, 1):
            findings.append(_f(
                "Account ospite attivo", Severity.LOW,
                "Chiunque può accedere al Mac come ospite senza password.", "GuestEnabled = 1",
                "Disattivare l'account ospite (Impostazioni > Utenti e gruppi).",
                "macos:guest-enabled", "users",
                command="sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"))
        auto = login.get("autoLoginUser")
        if isinstance(auto, str) and auto:
            findings.append(_f(
                f"Accesso automatico attivo ({auto})", Severity.MEDIUM,
                "All'accensione il Mac entra da solo in questo account: chiunque abbia il computer in mano "
                "ha i suoi dati e le sue sessioni.", f"autoLoginUser = {auto}",
                "Disattivare l'accesso automatico (Impostazioni > Utenti e gruppi).",
                "macos:autologin", "users",
                command="sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"))
        return findings


# ------------------------------------------------------------------------------- SSH
class MacSSHCollector:
    name = "ssh_config"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        overrides = launchd_overrides(executor)
        state = overrides.get("com.openssh.sshd") if overrides is not None else None
        evidence = f"com.openssh.sshd => {'enabled' if state else 'disabled'}"
        if state is None:
            # Nessuna voce in launchctl: lo chiede a systemsetup (serve root).
            res = run_privileged(executor, ["systemsetup", "-getremotelogin"])
            m = re.search(r"Remote Login:\s*(On|Off)", res.out, re.IGNORECASE) if res.ok else None
            if m:
                state, evidence = m.group(1).lower() == "on", res.out.strip()
            elif overrides is not None:
                # launchctl ha risposto ma sshd non c'è: impostazione di fabbrica (spento).
                state, evidence = False, "com.openssh.sshd non abilitato (impostazione di fabbrica)"
            else:
                return [unverifiable(
                    "Accesso remoto (SSH) non verificabile",
                    "Né launchctl né systemsetup hanno risposto: non si sa se il server SSH è attivo.",
                    (res.err or res.out).strip()[:200], "macos:ssh-unknown", "authentication")]
        if not state:
            return [_f("Accesso remoto (SSH) disattivato", Severity.INFO,
                       "Il server SSH di macOS non è attivo: nessun accesso da remoto via SSH.",
                       evidence, "Nessuna azione richiesta.",
                       "macos:ssh-off", "authentication")]
        findings = [_f("Accesso remoto (SSH) attivo", Severity.INFO,
                       "Il Mac accetta connessioni SSH: valgono i controlli sulla configurazione qui sotto.",
                       evidence, "Disattivarlo se non serve.",
                       "macos:ssh-on", "authentication",
                       command="sudo systemsetup -f -setremotelogin off")]
        findings.extend(SSHConfigCollector().collect(executor))
        return findings


# -------------------------------------------------------------------------- firewall
class MacFirewallCollector:
    name = "firewall"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        out, _, rc = executor.execute_command([SOCKETFILTERFW, "--getglobalstate"])
        if rc != 0 or "state" not in out.lower():
            return [unverifiable("Stato del firewall non determinabile",
                                 "socketfilterfw non ha risposto: non si sa se il firewall è attivo.",
                                 (out or "").strip()[:200], "macos:firewall-unknown", "firewall")]
        m = re.search(r"State\s*=\s*(\d)", out)
        state = m.group(1) if m else ("1" if "enabled" in out.lower() else "0")
        if state == "0":
            return [_f(
                "Firewall di macOS disattivato", Severity.MEDIUM,
                "Il firewall applicativo è spento: qualsiasi programma può accettare connessioni dalla rete.",
                out.strip(), "Attivare il firewall (Impostazioni > Rete > Firewall), con la modalità stealth.",
                "macos:firewall-off", "firewall",
                command=f"sudo {SOCKETFILTERFW} --setglobalstate on && sudo {SOCKETFILTERFW} --setstealthmode on")]
        findings = [_f("Firewall di macOS attivo", Severity.INFO, "Il firewall applicativo è acceso.",
                       out.strip(), "Nessuna azione richiesta.", "macos:firewall-on", "firewall")]
        stealth, _, src = executor.execute_command([SOCKETFILTERFW, "--getstealthmode"])
        if src == 0 and ("off" in stealth.lower() or "disabled" in stealth.lower()):
            findings.append(_f(
                "Modalità stealth del firewall disattivata", Severity.LOW,
                "Il Mac risponde a ping e sonde di rete: è più facile da scoprire in una rete ostile.",
                stealth.strip(), "Attivare la modalità stealth.", "macos:stealth-off", "firewall",
                command=f"sudo {SOCKETFILTERFW} --setstealthmode on"))
        return findings


# --------------------------------------------------------------------- servizi/porte
class MacServicesCollector:
    name = "services"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        overrides = launchd_overrides(executor)
        if overrides is None:
            findings.append(unverifiable(
                "Condivisioni non verificabili",
                "launchctl non ha risposto: non si sa quali servizi di condivisione sono attivi.",
                "launchctl print-disabled system: errore", "macos:sharing-unknown", "services"))
        for label, (name, severity, why) in SHARING_SERVICES.items():
            if overrides and overrides.get(label) is True:
                findings.append(_f(
                    f"Condivisione attiva: {name}", severity, why, f"{label} => enabled",
                    "Disattivarla se non serve (Impostazioni > Generali > Condivisione).",
                    f"macos:sharing-{label.rsplit('.', 1)[-1]}", "services"))

        sockets = []
        answered = False
        for proto in ("tcp", "udp"):
            out, _, rc = executor.execute_command(["netstat", "-an", "-p", proto])
            if rc == 0:
                answered = True
                sockets.extend(parse_bsd_netstat(out))
        if not answered:
            findings.append(unverifiable(
                "Porte in ascolto non verificabili",
                "netstat non ha risposto: le porte aperte non sono state controllate.",
                "netstat -an: errore", "services:ports-unverifiable", "network"))
            return findings
        if not sockets:
            return findings
        dangerous = sorted({(pr, p) for pr, _, p in sockets if (pr, p) in DANGEROUS_PORTS},
                           key=lambda x: (int(x[1]), x[0]))
        if dangerous:
            findings.append(_f(
                f"Porte pericolose in ascolto: {', '.join(f'{p}/{pr}' for pr, p in dangerous)}", Severity.HIGH,
                "Sono in ascolto porte associate a servizi non cifrati o deprecati.",
                "\n".join(f"Porta {p}/{pr} ({DANGEROUS_PORTS[(pr, p)]}) in ascolto" for pr, p in dangerous),
                "Disattivare i servizi associati.", "services:dangerous-ports", "network", Confidence.MEDIUM))
        for proto, addr, port in sockets:
            if proto == "tcp" and port in INTERNAL_PORTS and addr in ANY_ADDRESS:
                label, severity, why = INTERNAL_PORTS[port]
                findings.append(_f(
                    f"{label} in ascolto su tutte le interfacce (porta {port})", severity,
                    f"{why} Il servizio non è limitato a localhost.", f"netstat: {addr}.{port} LISTEN",
                    "Farlo ascoltare solo su 127.0.0.1 e/o bloccarlo con il firewall.",
                    f"services:exposed-{port}", "network", Confidence.MEDIUM))
        return findings


# ------------------------------------------------------------------ password e sudo
class MacAuthPolicyCollector:
    name = "auth_policy"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["pwpolicy", "getaccountpolicies"])
        policies: object = None
        if rc == 0 and "<plist" in out:
            try:
                start = out.index("<?xml") if "<?xml" in out else out.index("<plist")
                policies = plistlib.loads(out[start:].encode("utf-8"))
            except Exception:
                policies = None
        if rc != 0 or not isinstance(policies, dict) and "<plist" in out:
            findings.append(unverifiable(
                "Policy delle password non verificabile",
                "pwpolicy non ha restituito una policy leggibile.",
                (out or "").strip()[:200], "macos:password-policy-unknown", "authentication"))
        else:
            items = policies.get("policyCategoryPasswordContent") if isinstance(policies, dict) else None
            contents = [str(p.get("policyContent", "")) for p in
                        (items if isinstance(items, list) else []) if isinstance(p, dict)]
            lengths = [int(m.group(1)) for c in contents for m in re.finditer(r"\.\{(\d+),", c)]
            allows_empty = any("^$|" in c for c in contents)
            minimum = max(lengths) if lengths else None
            if not contents:
                findings.append(_f(
                    "Nessuna policy di sistema sulle password", Severity.LOW,
                    "Non è impostata una policy globale sulle password: la robustezza dipende solo dai "
                    "controlli di base di macOS.", (out or "").strip()[:300] or "pwpolicy getaccountpolicies",
                    "Impostare una lunghezza minima di almeno 12 caratteri (profilo di configurazione o pwpolicy).",
                    "macos:password-policy-none", "authentication", Confidence.MEDIUM))
            elif allows_empty or (minimum is not None and minimum < 8):
                findings.append(_f(
                    "Policy delle password debole", Severity.MEDIUM,
                    "La policy di sistema accetta password corte" + (" o vuote" if allows_empty else "") + ".",
                    "; ".join(contents)[:300] or "pwpolicy getaccountpolicies",
                    "Impostare una lunghezza minima di almeno 12 caratteri (profilo di configurazione o pwpolicy).",
                    "macos:password-policy", "authentication", Confidence.MEDIUM))
        findings.extend(AuthPolicyCollector()._sudoers(executor))
        return findings


# --------------------------------------------------------------------- aggiornamenti
class MacUpdatesCollector:
    name = "updates"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        prefs = read_plist(executor, SOFTWARE_UPDATE_PLIST)
        if prefs is None:
            return [unverifiable("Aggiornamenti non verificabili",
                                 "Le preferenze di Aggiornamento Software non sono leggibili.",
                                 SOFTWARE_UPDATE_PLIST, "macos:updates-unknown", "packages")]
        findings: list[Finding] = []

        def off(key: str, default: bool = True) -> bool:
            value = prefs.get(key, default)
            return value in (False, 0)

        sched, _, _ = executor.execute_command(["softwareupdate", "--schedule"])
        if "off" in sched.lower() or off("AutomaticCheckEnabled"):
            findings.append(_f(
                "Controllo automatico degli aggiornamenti disattivato", Severity.MEDIUM,
                "macOS non cerca aggiornamenti da solo: le correzioni di sicurezza arrivano solo se "
                "qualcuno controlla a mano.", sched.strip() or "AutomaticCheckEnabled = 0",
                "Attivare il controllo automatico.", "macos:auto-check-off", "packages",
                command="sudo softwareupdate --schedule on"))
        security_off = [k for k in ("CriticalUpdateInstall", "ConfigDataInstall") if off(k)]
        if security_off:
            findings.append(_f(
                "Aggiornamenti di sicurezza automatici disattivati", Severity.MEDIUM,
                "Le risposte rapide di sicurezza e i dati di protezione (XProtect) non vengono installati "
                "da soli.", ", ".join(f"{k} = 0" for k in security_off),
                "Attivare 'Installa risposte di sicurezza e file di sistema' in Aggiornamento Software.",
                "macos:security-updates-off", "packages",
                command=" && ".join(f"sudo defaults write {SOFTWARE_UPDATE_PLIST[:-6]} {k} -bool true"
                                    for k in security_off)))
        if off("AutomaticallyInstallMacOSUpdates", default=False):
            findings.append(_f(
                "Aggiornamenti di macOS non installati automaticamente", Severity.LOW,
                "Gli aggiornamenti del sistema vanno installati a mano.",
                "AutomaticallyInstallMacOSUpdates = 0", "Valutare l'installazione automatica.",
                "macos:auto-install-off", "packages", Confidence.MEDIUM))

        pending = [u for u in prefs.get("RecommendedUpdates") or [] if isinstance(u, dict)]
        if pending:
            names = [f"{u.get('Display Name', '?')} {u.get('Display Version', '')}".strip() for u in pending]
            findings.append(_f(
                f"Aggiornamenti disponibili: {len(pending)}", Severity.MEDIUM,
                "Aggiornamento Software ha trovato aggiornamenti non ancora installati (all'ultimo controllo "
                "automatico).", "\n".join(names[:10]), "Installare gli aggiornamenti.",
                "macos:updates-pending", "packages", command="sudo softwareupdate -i -a"))
        return findings


# ----------------------------------------------------------------------- persistenza
class MacPersistenceCollector:
    name = "persistence"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        items, suspicious = self._launch_items(executor)
        if suspicious:
            findings.append(_f(
                f"Elementi di avvio sospetti ({len(suspicious)})", Severity.HIGH,
                "LaunchDaemons/LaunchAgents eseguono file temporanei o comandi tipici della persistenza "
                "di un attaccante.", "\n".join(suspicious[:10]),
                "Controllare i file indicati e rimuovere quelli non autorizzati (launchctl bootout).",
                "macos:launch-suspicious", "persistence"))
        if items:
            findings.append(_f(
                f"Elementi di avvio di terze parti: {len(items)}", Severity.INFO,
                "Programmi non Apple avviati automaticamente: ognuno deve essere riconosciuto.",
                "\n".join(items[:15]), "Rimuovere quelli che non si riconoscono.",
                "macos:launch-items", "persistence", Confidence.MEDIUM))

        hits = []
        for cmd in (["crontab", "-l"],):
            out, _, rc = executor.execute_command(cmd)
            if rc == 0:
                hits.extend(f"crontab: {ln.strip()[:160]}  [{why}]"
                            for ln in out.splitlines() if (why := suspicious_reason(ln)))
        root_cron = run_privileged(executor, ["crontab", "-l", "-u", "root"])
        if root_cron.ok:
            hits.extend(f"crontab root: {ln.strip()[:160]}  [{why}]"
                        for ln in root_cron.out.splitlines() if (why := suspicious_reason(ln)))
        if hits:
            findings.append(_f(
                f"Attività pianificata sospetta in cron ({len(hits)})", Severity.HIGH,
                "Righe di cron che eseguono file temporanei o comandi tipici di un attaccante.",
                "\n".join(hits[:10]), "Verificare e rimuovere le righe non autorizzate.",
                "persistence:cron-suspicious", "persistence"))
        findings.extend(self._authorized_keys(executor))
        return findings

    @staticmethod
    def _launch_items(executor) -> tuple[list[str], list[str]]:
        items: list[str] = []
        suspicious: list[str] = []
        out, _, rc = executor.execute_command(
            ["find", "/Library/LaunchDaemons", "/Library/LaunchAgents", "-maxdepth", "1", "-name", "*.plist"])
        paths = [p.strip() for p in out.splitlines() if p.strip().endswith(".plist")] if rc in (0, 1) else []
        for path in paths[:60]:
            label = path.rsplit("/", 1)[-1][:-6]
            if label.startswith("com.apple."):
                continue
            plist = read_plist(executor, path) or {}
            args = plist.get("ProgramArguments") or ([plist["Program"]] if plist.get("Program") else [])
            command = " ".join(str(a) for a in args)[:200]
            items.append(f"{path}: {command or '(programma non indicato)'}")
            why = suspicious_reason(command) or (
                "esegue un file in una cartella temporanea" if re.match(r"^(/tmp|/private/tmp|/var/tmp|/Users/Shared)/",
                                                                         command) else None)
            if why:
                suspicious.append(f"{path}: {command}  [{why}]")
        return items, suspicious

    @staticmethod
    def _authorized_keys(executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["dscl", ".", "-list", "/Users", "NFSHomeDirectory"])
        if rc != 0:
            return []
        summary, evidence, findings = [], [], []
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2 or not re.fullmatch(r"/(Users/[A-Za-z0-9._-]+|var/root)", parts[1].strip()):
                continue
            user, home = parts[0], parts[1].strip()
            path = f"{home}/.ssh/authorized_keys"
            res = run_privileged(executor, ["cat", path])
            if not res.ok:
                continue
            keys = [k for k in res.out.splitlines() if k.strip() and not k.lstrip().startswith("#")]
            if keys:
                summary.append(f"{user} ({len(keys)})")
                evidence.extend(f"{user}: {k.strip()[:100]}" for k in keys[:3])
        if summary:
            findings.append(_f(
                "Chiavi SSH autorizzate: " + ", ".join(summary), Severity.INFO,
                "Utenti che possono entrare con una chiave: ogni chiave deve essere riconosciuta.",
                "\n".join(evidence[:15]), "Rimuovere le chiavi che non si riconoscono.",
                "persistence:authorized-keys", "persistence"))
        return findings


# ----------------------------------------------------------------------- protezioni
class MacProtectionsCollector:
    name = "protections"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["csrutil", "status"])
        text = out.strip().lower()
        if rc == 0 and "disabled" in text:
            findings.append(_f(
                "System Integrity Protection (SIP) disattivata", Severity.HIGH,
                "Senza SIP anche root può modificare i file di sistema e caricare estensioni del kernel: "
                "un malware con privilegi di amministratore può nascondersi nel sistema.", out.strip(),
                "Riattivare SIP dalla modalità di ripristino (csrutil enable).",
                "macos:sip-disabled", "protections"))
        elif rc == 0 and "enabled" in text:
            findings.append(_f("SIP attiva", Severity.INFO, "System Integrity Protection è attiva.",
                               out.strip(), "Nessuna azione richiesta.", "macos:sip-enabled", "protections"))

        out, _, rc = executor.execute_command(["fdesetup", "status"])
        if rc == 0 and "is off" in out.lower():
            findings.append(_f(
                "FileVault disattivato", Severity.MEDIUM,
                "Il disco non è cifrato: chi ha il Mac in mano (furto, smarrimento) può leggere tutti i dati.",
                out.strip(), "Attivare FileVault (Impostazioni > Privacy e sicurezza).",
                "macos:filevault-off", "protections", command="sudo fdesetup enable"))
        elif rc == 0 and "is on" in out.lower():
            findings.append(_f("FileVault attivo", Severity.INFO, "Il disco di sistema è cifrato.",
                               out.strip().splitlines()[0], "Nessuna azione richiesta.",
                               "macos:filevault-on", "protections"))

        out, _, rc = executor.execute_command(["spctl", "--status"])
        if "disabled" in out.lower():
            findings.append(_f(
                "Gatekeeper disattivato", Severity.HIGH,
                "macOS esegue qualsiasi programma, anche non firmato o non verificato da Apple.",
                out.strip(), "Riattivare Gatekeeper.", "macos:gatekeeper-off", "protections",
                command="sudo spctl --master-enable"))
        return findings

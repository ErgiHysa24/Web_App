"""Segni di persistenza o attività sospetta: cron, unit systemd, chiavi SSH autorizzate,
LD_PRELOAD globale, processi in esecuzione da file cancellati.

Solo lettura. Sono indizi, non prove: i risultati hanno confidenza MEDIUM e spiegano cosa
controllare. I percorsi letti sui file di casa vengono dal target e si usano solo se hanno
una forma "normale" (niente `..`, niente caratteri strani).
"""
from __future__ import annotations

import re

from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Confidence, Finding, Severity

_PATTERNS = (
    (re.compile(r"(?:^|[\s;|&(=\"'])(?:/tmp|/var/tmp|/dev/shm)/"), "esegue o usa un file in una cartella temporanea"),
    (re.compile(r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), "scarica ed esegue codice dalla rete"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b"), "decodifica ed esegue dati base64"),
    (re.compile(r"/dev/(?:tcp|udp)/"), "apre una connessione di rete da shell (tipico delle reverse shell)"),
    (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-[A-Za-z]*e\b"), "netcat con esecuzione di comandi"),
    (re.compile(r"\bbash\s+-i\b"), "shell interattiva (tipico delle reverse shell)"),
)
_HOME_OK = re.compile(r"/[A-Za-z0-9_./-]{1,100}")
_TMP_TARGET = re.compile(r"^(?:/tmp|/var/tmp|/dev/shm)/")


def suspicious_reason(line: str) -> str | None:
    if line.lstrip().startswith("#"):
        return None
    for rx, why in _PATTERNS:
        if rx.search(line):
            return why
    return None


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.MEDIUM, category="persistence"):
    return Finding(title=title, category=category, severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source, confidence=conf)


class PersistenceCollector:
    name = "persistence"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._cron(executor))
        findings.extend(self._systemd(executor))
        findings.extend(self._ld_preload(executor))
        findings.extend(self._deleted_binaries(executor))
        findings.extend(self._boot_scripts(executor))
        findings.extend(self._authorized_keys(executor))
        return findings

    # -------------------------------------------------------------------- cron
    def _cron_files(self, executor) -> tuple[list[tuple[str, str]], bool]:
        files: list[tuple[str, str]] = []
        denied = False
        out, _, rc = executor.execute_command(["cat", "/etc/crontab"])
        if rc == 0:
            files.append(("/etc/crontab", out))
        lst = executor.execute_command(["find", "/etc/cron.d", "-maxdepth", "1", "-type", "f"])[0]
        recent = executor.execute_command(
            ["find", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
             "-maxdepth", "1", "-type", "f", "-mtime", "-14"])[0]
        for path in (lst.split() + recent.split())[:60]:
            if re.fullmatch(r"/etc/cron\.[a-z]+(?:/[A-Za-z0-9._-]+)?", path):
                r = executor.execute_command(["cat", path])
                if r[2] == 0:
                    files.append((path, r[0]))
        # /etc/crontabs: crond di BusyBox (Alpine)
        for d in ("/var/spool/cron/crontabs", "/var/spool/cron", "/etc/crontabs"):
            res = run_privileged(executor, ["find", d, "-maxdepth", "1", "-type", "f"])
            if res.status == "denied":
                denied = True
            for path in res.out.split()[:40]:
                if re.fullmatch(r"(?:/var/spool/cron(?:/crontabs)?|/etc/crontabs)/[A-Za-z0-9._-]+", path):
                    r = run_privileged(executor, ["cat", path])
                    if r.ok:
                        files.append((path, r.out))
        return files, denied

    def _cron(self, executor) -> list[Finding]:
        files, denied = self._cron_files(executor)
        hits: list[str] = []
        for path, text in files:
            for line in text.splitlines():
                why = suspicious_reason(line)
                if why:
                    hits.append(f"{path}: {line.strip()[:160]}  [{why}]")
        res: list[Finding] = []
        if hits:
            res.append(_f(
                f"Attività pianificata sospetta in cron ({len(hits)})", Severity.HIGH,
                "Alcune righe di cron eseguono file in cartelle temporanee o usano tecniche tipiche della "
                "persistenza di un attaccante (download ed esecuzione, reverse shell, base64).",
                "\n".join(hits[:10]),
                "Verificare chi ha creato queste righe e cosa eseguono; rimuoverle se non autorizzate.",
                "persistence:cron-suspicious"))
        if denied:
            res.append(_f(
                "Crontab degli utenti non verificabili", Severity.INFO,
                "I crontab personali sono leggibili solo da root: sono stati controllati solo i file di sistema.",
                "/var/spool/cron non leggibile", "Rieseguire con sudo senza password.",
                "persistence:cron-unreadable", Confidence.LOW))
        return res

    # ----------------------------------------------------------------- systemd
    def _systemd(self, executor) -> list[Finding]:
        out, _, _ = executor.execute_command(
            ["grep", "-rEs", "^Exec(Start|StartPre|StartPost)=", "/etc/systemd/system"])
        hits = []
        for line in out.splitlines():
            why = suspicious_reason(line.split(":", 1)[-1])
            if why:
                hits.append(f"{line.strip()[:200]}  [{why}]")
        if not hits:
            return []
        return [_f(
            f"Unit systemd sospette ({len(hits)})", Severity.HIGH,
            "Servizi definiti in /etc/systemd/system eseguono file temporanei o comandi tipici della persistenza.",
            "\n".join(hits[:10]),
            "Controllare le unit indicate (systemctl cat <unit>) e disabilitare quelle non autorizzate.",
            "persistence:systemd-suspicious")]

    def _boot_scripts(self, executor) -> list[Finding]:
        """Script eseguiti all'avvio fuori da systemd: rc.local e /etc/local.d (OpenRC, Alpine)."""
        out, _, _ = executor.execute_command(
            ["grep", "-rsH", "", "/etc/rc.local", "/etc/local.d"])
        hits = []
        for line in out.splitlines()[:2000]:
            path, _, content = line.partition(":")
            why = suspicious_reason(content)
            if why:
                hits.append(f"{path}: {content.strip()[:160]}  [{why}]")
        if not hits:
            return []
        return [_f(
            f"Script di avvio sospetti ({len(hits)})", Severity.HIGH,
            "Script eseguiti all'avvio (rc.local o /etc/local.d) lanciano file temporanei o comandi tipici "
            "della persistenza di un attaccante.",
            "\n".join(hits[:10]),
            "Controllare gli script indicati e rimuovere le righe non autorizzate.",
            "persistence:boot-script-suspicious")]

    # --------------------------------------------------------------- LD_PRELOAD
    def _ld_preload(self, executor) -> list[Finding]:
        if executor.execute_command(["test", "-s", "/etc/ld.so.preload"])[2] != 0:
            return []
        content = executor.execute_command(["cat", "/etc/ld.so.preload"])[0].strip()
        return [_f(
            "Libreria precaricata globalmente (/etc/ld.so.preload)", Severity.HIGH,
            "Le librerie elencate vengono caricate in ogni programma: è una tecnica classica dei rootkit "
            "per nascondere file e processi. Può essere legittimo solo per software di sicurezza noto.",
            content[:300], "Verificare ogni libreria elencata; se non è riconosciuta, indagare subito.",
            "persistence:ld-preload")]

    # --------------------------------------------------------- file cancellati
    def _deleted_binaries(self, executor) -> list[Finding]:
        res = run_privileged(executor, [
            "find", "/proc", "-maxdepth", "2", "-name", "exe", "-lname", "*(deleted)",
            "-printf", "%p -> %l\\n"])
        rows = []
        for line in res.out.splitlines():
            m = re.fullmatch(r"/proc/(\d+)/exe -> (.+?)(?: \(deleted\))?", line.strip())
            if m:
                rows.append((m.group(1), m.group(2)))
        if not rows:
            return []
        # memfd: e anon_inode: sono file solo in memoria (sandbox, runtime, JIT): non sono
        # né programmi cancellati da disco né file sostituiti da un aggiornamento.
        rows = [(pid, t) for pid, t in rows if not t.startswith(("/memfd:", "memfd:", "anon_inode:"))]
        tmp = [(pid, t) for pid, t in rows if _TMP_TARGET.match(t)]
        other = [(pid, t) for pid, t in rows if not _TMP_TARGET.match(t)]
        findings: list[Finding] = []
        if tmp:
            findings.append(_f(
                f"Processi in esecuzione da un file cancellato in una cartella temporanea ({len(tmp)})",
                Severity.HIGH,
                "Un programma avviato da /tmp o /dev/shm e poi cancellato dal disco è un comportamento tipico "
                "del malware che prova a non lasciare tracce.",
                "\n".join(f"PID {p}: {t}" for p, t in tmp[:10]),
                "Indagare subito sul processo (ls -l /proc/<pid>/exe, /proc/<pid>/cmdline) e isolare la macchina se non riconosciuto.",
                "persistence:deleted-exe-tmp"))
        if other:
            progs = sorted({t for _, t in other})
            findings.append(_f(
                f"Processi che usano file sostituiti da un aggiornamento ({len(other)})", Severity.LOW,
                "Questi processi sono ancora avviati con la versione precedente del programma: di solito significa "
                "che dopo un aggiornamento non sono stati riavviati, quindi usano ancora codice vecchio.",
                "\n".join(progs[:10]),
                "Riavviare i servizi interessati (o il sistema) per usare i file aggiornati.",
                "persistence:deleted-exe-updated", Confidence.MEDIUM, category="packages"))
        return findings

    # ----------------------------------------------------------- authorized_keys
    def _login_users(self, executor) -> list[tuple[str, str]]:
        out, _, rc = executor.execute_command(["cat", "/etc/passwd"])
        if rc != 0:
            return []
        users = []
        for line in out.splitlines():
            f = line.split(":")
            if len(f) >= 7 and not f[6].endswith(("nologin", "false")) and f[5]:
                home = f[5]
                if _HOME_OK.fullmatch(home) and ".." not in home:
                    users.append((f[0], home))
        return users

    def _authorized_keys(self, executor) -> list[Finding]:
        summary: list[str] = []
        evidence: list[str] = []
        findings: list[Finding] = []
        denied = False
        for user, home in self._login_users(executor)[:40]:
            path = f"{home}/.ssh/authorized_keys"
            r = run_privileged(executor, ["cat", path])
            if r.status == "denied":
                denied = True
                continue
            if not r.ok:
                continue
            keys = [ln for ln in r.out.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
            if not keys:
                continue
            summary.append(f"{user} ({len(keys)})")
            fp = run_privileged(executor, ["ssh-keygen", "-lf", path])
            lines = fp.out.splitlines() if fp.ok else keys
            evidence.extend(f"{user}: {ln.strip()[:120]}" for ln in lines[:5])
            if user == "root" and any(not k.lstrip().startswith(("command=", "from=")) for k in keys):
                findings.append(_f(
                    "root accetta accessi SSH con chiave senza restrizioni", Severity.LOW,
                    "Ci sono chiavi autorizzate per root senza `from=` né `command=`: chi possiede una di quelle "
                    "chiavi può entrare come root da qualsiasi indirizzo.",
                    "\n".join(f"root: {k.strip()[:100]}" for k in keys[:3]),
                    "Lasciare solo le chiavi necessarie, con `from=`, oppure usare un utente normale con sudo.",
                    "persistence:root-authorized-keys"))
            st = run_privileged(executor, ["stat", "-c", "%a", path, f"{home}/.ssh"])
            for mode in st.out.split():
                if mode.isdigit() and int(mode, 8) & 0o022:
                    findings.append(_f(
                        f"authorized_keys modificabile da altri utenti ({user})", Severity.HIGH,
                        "Il file (o la cartella .ssh) è scrivibile da gruppo o altri: chiunque può aggiungere una "
                        "chiave e ottenere accesso come questo utente.",
                        f"{path}: permessi {mode}", f"chmod 700 {home}/.ssh && chmod 600 {path}".replace(home, "~"),
                        "persistence:authorized-keys-perms", Confidence.HIGH))
                    break
        if summary:
            findings.append(_f(
                "Chiavi SSH autorizzate: " + ", ".join(summary), Severity.INFO,
                "Elenco degli utenti che possono entrare con una chiave. Controllare che ogni chiave "
                "sia riconosciuta: una chiave sconosciuta è un accesso permanente per un attaccante.",
                "\n".join(evidence[:15]), "Rimuovere le chiavi che non si riconoscono.",
                "persistence:authorized-keys", Confidence.HIGH))
        if denied:
            findings.append(_f(
                "Chiavi SSH autorizzate non verificabili", Severity.INFO,
                "I file authorized_keys di alcuni utenti non sono leggibili senza privilegi di root.",
                "permesso negato", "Rieseguire con sudo senza password.",
                "persistence:authorized-keys-unreadable", Confidence.LOW))
        return findings

"""Filesystem security collector."""
from __future__ import annotations
from risk_assessor.collectors._platform import unverifiable
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Finding, Severity, Confidence


SUID_DIRS = [
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/local/bin", "/usr/local/sbin",
]
WORLD_WRITABLE_DIRS = ["/etc", "/var/tmp", "/tmp", "/var/spool/cron"]
_TEMP_DIRS = ("/tmp/", "/var/tmp/")


_READONLY_DEVICES = ("/dev/sr", "/dev/cdrom", "/dev/loop")

# Programmi che hanno il bit SUID di serie nelle distribuzioni comuni: segnalarli come
# problema su ogni sistema sarebbe solo rumore. Un SUID fuori da questo elenco (o in
# /usr/local) è invece da guardare.
STANDARD_SUID = frozenset({
    "passwd", "su", "sudo", "sudoedit", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd",
    "chage", "expiry", "pkexec", "ping", "ping6", "traceroute6.iputils", "fusermount", "fusermount3",
    "unix_chkpwd", "ssh-keysign", "dbus-daemon-launch-helper", "polkit-agent-helper-1", "crontab",
    "at", "Xorg.wrap", "snap-confine", "newuidmap", "newgidmap", "pam_timestamp_check", "staprun",
    "userhelper", "usernetctl", "mount.nfs", "mount.cifs", "doas", "bwrap", "chromium-sandbox",
    "chrome-sandbox", "vmware-user-suid-wrapper", "ntfs-3g", "write", "wall", "ssh-agent",
    "grub2-set-bootflag", "utempter", "lockdev", "mount.ecryptfs_private", "sg", "suexec",
    "pppd", "kismet_cap_linux_wifi", "exim4", "procmail", "Xorg",
})
_EXISTING = 'for d in "$@"; do [ -d "$d" ] && printf "%s\\n" "$d"; done; exit 0'


def _octal(text: str | None) -> int | None:
    """"640" -> 0o640; None se non è un modo ottale valido."""
    if not text or not text.strip().isdigit() or any(c in "89" for c in text.strip()):
        return None
    return int(text.strip(), 8)


class FilesystemCollector:
    name = "filesystem"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        self._incomplete: list[str] = []
        findings: list[Finding] = []
        findings.extend(self._check_suid(executor))
        findings.extend(self._check_sgid(executor))
        findings.extend(self._check_world_writable(executor))
        findings.extend(self._check_critical_perms(executor))
        findings.extend(self._check_disk_usage(executor))
        if self._incomplete:
            findings.append(unverifiable(
                "Controllo dei file incompleto",
                "Alcune cartelle non erano leggibili (servono root o sudo senza password): i risultati "
                "su SUID e file scrivibili da tutti possono essere parziali.",
                "; ".join(self._incomplete)[:400], "filesystem:partial", "filesystem"))
        return findings

    def _find(self, executor, dirs: list[str], perm: str) -> list[str]:
        """File con quel permesso nelle cartelle che esistono.

        `find` esce con 1 anche quando trova i file ma una cartella non è leggibile o non
        esiste: i risultati trovati si tengono sempre, e un'esecuzione parziale viene
        annotata (finding filesystem:partial) invece di diventare "nessun file".
        """
        out, _, _ = executor.execute_command(["sh", "-c", _EXISTING, "sh", *dirs])
        existing = [d for d in (out or "").splitlines() if d in dirs]
        if not existing:
            return []
        res = run_privileged(executor, ["find", *existing, "-xdev", "-type", "f", "-perm", perm])
        if not res.ok and res.status != "absent":
            err = (res.err or "").strip().splitlines()
            self._incomplete.append(f"find -perm {perm}: " + (err[0][:120] if err else res.status))
        return [ln.strip() for ln in (res.out or "").splitlines() if ln.strip().startswith("/")]

    def _check_suid(self, executor) -> list[Finding]:
        files = self._find(executor, SUID_DIRS, "-4000")
        if not files:
            return []
        unusual = [f for f in files if f.rsplit("/", 1)[-1] not in STANDARD_SUID or f.startswith("/usr/local/")]
        standard = [f for f in files if f not in unusual]
        findings: list[Finding] = []
        if unusual:
            findings.append(Finding(
                title=f"Programmi SUID non standard: {len(unusual)}",
                category="filesystem",
                severity=Severity.MEDIUM,
                description=("Programmi che girano con i privilegi del proprietario (di solito root) e che non "
                             "fanno parte di quelli presenti di serie nelle distribuzioni: una loro vulnerabilità "
                             "diventa un modo per ottenere root."),
                evidence="\n".join(unusual[:20])[:500],
                recommendation="Verificare che ognuno serva davvero e venga da un pacchetto affidabile; "
                               "altrimenti togliere il bit (chmod u-s).",
                source="filesystem:suid",
                confidence=Confidence.MEDIUM,
            ))
        if standard:
            findings.append(Finding(
                title=f"Programmi SUID di sistema: {len(standard)}",
                category="filesystem",
                severity=Severity.INFO,
                description="Programmi con il bit SUID previsti dalla distribuzione (passwd, sudo, mount…).",
                evidence="\n".join(standard[:20])[:500],
                recommendation="Nessuna azione richiesta; tenerli aggiornati.",
                source="filesystem:suid-standard",
                confidence=Confidence.HIGH,
            ))
        return findings

    def _check_sgid(self, executor) -> list[Finding]:
        files = self._find(executor, SUID_DIRS, "-2000")
        if not files:
            return []
        return [Finding(
            title=f"File SGID trovati: {len(files)}",
            category="filesystem",
            severity=Severity.LOW,
            description="File con bit SGID impostato.",
            evidence="\n".join(files[:20])[:500],
            recommendation="Verificare che ogni file SGID sia necessario.",
            source="filesystem:sgid",
            confidence=Confidence.LOW,
        )]

    def _check_world_writable(self, executor) -> list[Finding]:
        files = self._find(executor, WORLD_WRITABLE_DIRS, "-0002")
        if not files:
            return []
        temp = [f for f in files if f.startswith(_TEMP_DIRS)]
        critical = [f for f in files if f not in temp]
        findings: list[Finding] = []
        if critical:
            findings.append(Finding(
                title=f"File scrivibili da tutti in cartelle di sistema: {len(critical)}",
                category="filesystem",
                severity=Severity.HIGH,
                description=("Qualsiasi utente può modificare questi file di configurazione o di pianificazione: "
                             "in /etc o nei cron significa poter far eseguire comandi a root."),
                evidence="\n".join(critical[:20])[:500],
                recommendation="Togliere il permesso di scrittura agli altri utenti (chmod o-w).",
                source="filesystem:world-writable",
                confidence=Confidence.HIGH,
            ))
        if temp:
            findings.append(Finding(
                title=f"File scrivibili da tutti nelle cartelle temporanee: {len(temp)}",
                category="filesystem",
                severity=Severity.LOW,
                description=("Nelle cartelle temporanee è comune, ma se uno di questi file viene letto o eseguito "
                             "da un servizio o da uno script di root, chiunque può cambiarne il contenuto."),
                evidence="\n".join(temp[:20])[:500],
                recommendation="Verificare che nessuno script privilegiato usi questi file.",
                source="filesystem:world-writable-tmp",
                confidence=Confidence.MEDIUM,
            ))
        return findings

    def _stat_mode(self, executor, path: str) -> str | None:
        out, _, rc = executor.execute_command(["stat", "-c", "%a", path])
        if rc != 0:
            return None
        return out.strip()

    def _check_critical_perms(self, executor) -> list[Finding]:
        """Permessi di /etc/shadow e /etc/passwd, valutati sui bit (non su stringhe esatte).

        `stat -c %a` scrive "0" per 0000 (il valore di RHEL, Fedora e derivate, dove nemmeno
        il proprietario ha permessi: root li ignora), "640" su Debian, "600" altrove: sono
        tutti corretti. Conta solo che gli altri utenti non possano leggere o scrivere.
        """
        findings: list[Finding] = []

        mode = _octal(self._stat_mode(executor, "/etc/shadow"))
        if mode is not None and mode & 0o027:
            readable = bool(mode & 0o004)
            findings.append(Finding(
                title=f"Permessi errati su /etc/shadow: {mode:o}",
                category="filesystem",
                severity=Severity.CRITICAL if mode & 0o006 else Severity.HIGH,
                description=("/etc/shadow contiene gli hash delle password: "
                             + ("qualsiasi utente può leggerli e provare a decifrarli."
                                if readable else "utenti diversi da root possono modificarlo.")),
                evidence=f"stat -c %a /etc/shadow -> {mode:o}",
                recommendation="Impostare permessi 640 root:shadow (Debian), 600 o 000 root:root.",
                source="filesystem:shadow-perms",
                confidence=Confidence.HIGH,
                command="sudo chmod o-rwx,g-wx /etc/shadow",
            ))

        mode = _octal(self._stat_mode(executor, "/etc/passwd"))
        if mode is not None and mode & 0o022:
            findings.append(Finding(
                title=f"Permessi errati su /etc/passwd: {mode:o}",
                category="filesystem",
                severity=Severity.HIGH,
                description=("/etc/passwd è scrivibile da utenti diversi da root: chi lo modifica può "
                             "creare un account con UID 0."),
                evidence=f"stat -c %a /etc/passwd -> {mode:o}",
                recommendation="Impostare permessi 644 root:root.",
                source="filesystem:passwd-perms",
                confidence=Confidence.HIGH,
                command="sudo chmod 644 /etc/passwd",
            ))

        return findings

    def _check_disk_usage(self, executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["df", "-P"])
        if rc != 0 or not out.strip():
            return []

        findings: list[Finding] = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 6:
                continue
            # Le ultime due colonne sono sempre "Capacity%" e "Mounted on".
            # Non usare indici fissi: il campo "Filesystem" può contenere spazi
            # (es. "C:/Program Files/Git" su Git Bash).
            pct_str = parts[-2].rstrip("%")
            mount = parts[-1]
            # Supporti sempre pieni e in sola lettura (CD/ISO, snap, loop): non sono un problema.
            if parts[0].startswith(_READONLY_DEVICES) or mount.startswith("/snap/"):
                continue
            try:
                pct = int(pct_str)
            except ValueError:
                continue
            if pct >= 90:
                findings.append(Finding(
                    title=f"Disco quasi pieno: {mount} ({pct}%)",
                    category="filesystem",
                    severity=Severity.MEDIUM,
                    description=f"Il mount {mount} è utilizzato al {pct}%.",
                    evidence=line.strip()[:500],
                    recommendation="Liberare spazio o estendere il filesystem.",
                    source="filesystem:disk-usage",
                    confidence=Confidence.HIGH,
                ))
        return findings

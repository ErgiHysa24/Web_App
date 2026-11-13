"""Aggiornamenti automatici, data dell'ultimo aggiornamento e riavvio necessario (sola lettura).

Ogni famiglia ha i suoi strumenti:
- Debian/Ubuntu: unattended-upgrades, /var/log/apt/history.log, /run/reboot-required;
- Fedora/RHEL: dnf-automatic (anche dnf5), database rpm, needs-restarting;
- SUSE, Arch, Alpine: non esiste un meccanismo standard di aggiornamento automatico (su Arch
  è sconsigliato), quindi non lo si pretende; data dell'ultimo aggiornamento dal database
  dei pacchetti e riavvio necessario se i moduli del kernel in uso non ci sono più.
"""
from __future__ import annotations

import re

from risk_assessor.collectors._platform import enable_hint, install_hint, join_hints, upgrade_hint
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.models import Confidence, Finding, Severity

# File che cambiano a ogni installazione o aggiornamento, per famiglia (il primo che esiste).
_PACKAGE_DB = {
    "debian": ("/var/log/apt/history.log", "/var/lib/dpkg/status"),
    "fedora": ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"),
    "rhel": ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"),
    "suse": ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"),
    "arch": ("/var/log/pacman.log", "/var/lib/pacman/local"),
    "alpine": ("/lib/apk/db/installed",),
}
# Età del file più recente tra i candidati, in giorni (vuoto se nessuno esiste).
_AGE_SCRIPT = ('now=$(date +%s); for f in "$@"; do if [ -e "$f" ]; then '
               'echo $(( (now - $(stat -c %Y "$f")) / 86400 )); exit 0; fi; done; exit 1')


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.MEDIUM, command=""):
    return Finding(title=title, category="packages", severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source,
                   confidence=conf, command=command)


class UpdatesCollector:
    name = "updates"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        host = host_info(executor)
        findings: list[Finding] = []
        family = host.family
        if family == "unknown" and host.commands is None:
            family = "debian" if self._legacy_has(executor, "apt-get") else \
                "rhel" if self._legacy_has(executor, "dnf") else "unknown"
        if family == "debian":
            findings.extend(self._apt(executor))
        elif family in ("fedora", "rhel"):
            findings.extend(self._dnf(executor, host))
        findings.extend(self._stale(executor, host, family))
        findings.extend(self._reboot(executor, host, family))
        return findings

    @staticmethod
    def _legacy_has(executor, name: str) -> bool:
        from risk_assessor.host import has_command
        return has_command(executor, name)

    # ------------------------------------------------------------------- Debian
    def _apt(self, executor) -> list[Finding]:
        out, _, rc = executor.execute_command(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
        installed = rc == 0 and "install ok installed" in out
        conf, _, crc = executor.execute_command(["cat", "/etc/apt/apt.conf.d/20auto-upgrades"])
        enabled = crc == 0 and re.search(r'Unattended-Upgrade\s+"1"', conf) is not None
        if installed and enabled:
            return []
        why = "pacchetto unattended-upgrades non installato" if not installed else "20auto-upgrades non lo abilita"
        return [_f(
            "Aggiornamenti di sicurezza automatici non attivi", Severity.MEDIUM,
            "Le correzioni di sicurezza non vengono applicate da sole: la macchina resta vulnerabile "
            "finché qualcuno non aggiorna a mano.",
            why, "Installare unattended-upgrades e abilitare gli aggiornamenti di sicurezza automatici.",
            "updates:no-auto-updates",
            command="sudo apt-get install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")]

    # ---------------------------------------------------------------------- RHEL
    def _dnf(self, executor, host: HostInfo) -> list[Finding]:
        if host.init not in ("systemd", "unknown"):
            return []
        timers = ("dnf-automatic-install.timer", "dnf-automatic.timer", "dnf5-automatic.timer")
        out, err, rc = executor.execute_command(["systemctl", "is-enabled", *timers])
        states = [s.strip() for s in out.splitlines() if s.strip()]
        if "enabled" in states:
            return []
        if not states:
            # Con systemd attivo, nessuna riga vuol dire che i timer non esistono (dnf-automatic
            # non installato: "No such file" su stderr). Senza systemd non si conclude nulla.
            usable = (host.init == "systemd" and rc != 127
                      and "not been booted" not in err and "No such file" in err)
            if not usable:
                return []
        return [_f(
            "Aggiornamenti di sicurezza automatici non attivi", Severity.MEDIUM,
            "dnf-automatic non è abilitato: le correzioni di sicurezza non vengono applicate da sole.",
            "timer dnf-automatic non abilitati: " + ", ".join(timers),
            "Installare dnf-automatic e abilitare il timer che applica gli aggiornamenti.",
            "updates:no-auto-updates",
            command=join_hints(install_hint(host, "auto-updates"),
                               enable_hint(host, "dnf-automatic-install.timer")))]

    # ------------------------------------------------- ultimo aggiornamento
    def _stale(self, executor, host: HostInfo, family: str) -> list[Finding]:
        paths = _PACKAGE_DB.get(family)
        if not paths:
            return []
        out, _, rc = executor.execute_command(["sh", "-c", _AGE_SCRIPT, "sh", *paths])
        try:
            days = int(out.strip()) if rc == 0 else None
        except ValueError:
            days = None
        if days is None or days <= 30:
            return []
        return [_f(
            f"Nessun aggiornamento dei pacchetti da {days} giorni",
            Severity.HIGH if days > 90 else Severity.MEDIUM,
            "L'ultima installazione o aggiornamento di pacchetti risale a molto tempo fa: "
            "probabilmente mancano correzioni di sicurezza.",
            f"database dei pacchetti modificato {days} giorni fa",
            "Aggiornare i pacchetti e valutare gli aggiornamenti automatici.",
            "updates:stale", Confidence.MEDIUM,
            command=upgrade_hint(host))]

    # -------------------------------------------------------------------- reboot
    def _reboot(self, executor, host: HostInfo, family: str) -> list[Finding]:
        for flag in ("/var/run/reboot-required", "/run/reboot-required"):
            if executor.execute_command(["test", "-f", flag])[2] == 0:
                pk, _, prc = executor.execute_command(["cat", flag + ".pkgs"])
                pkgs = " ".join(pk.split()[:10]) if prc == 0 else ""
                return [self._reboot_finding(f"{flag}" + (f" — pacchetti: {pkgs}" if pkgs else ""))]
        if host.container:
            return []   # in un container il kernel è quello dell'host: niente da dedurre
        if family in ("fedora", "rhel"):
            # needs-restarting -r: esce con 1 se serve un riavvio (dnf-utils / dnf5).
            for cmd in (["needs-restarting", "-r"], ["dnf", "needs-restarting", "-r"]):
                out, _, rc = executor.execute_command(cmd)
                if rc == 1 and "reboot" in out.lower():
                    return [self._reboot_finding(out.strip().splitlines()[0][:200])]
                if rc == 0:
                    return []
        if family in ("arch", "suse", "alpine"):
            # Kernel aggiornato ma non ancora in uso: i suoi moduli non esistono più.
            out, _, rc = executor.execute_command(
                ["sh", "-c", 'r=$(uname -r); [ -d "/lib/modules/$r" ] || [ -d "/usr/lib/modules/$r" ] '
                             '|| echo "$r"'])
            if rc == 0 and out.strip():
                return [self._reboot_finding(
                    f"i moduli del kernel in uso ({out.strip()}) non sono più installati")]
        return []

    @staticmethod
    def _reboot_finding(evidence: str) -> Finding:
        return _f(
            "Riavvio necessario per applicare gli aggiornamenti", Severity.LOW,
            "Sono stati installati aggiornamenti (spesso del kernel) che si attivano solo dopo un riavvio.",
            evidence, "Pianificare un riavvio del sistema.", "updates:reboot-required",
            Confidence.HIGH)

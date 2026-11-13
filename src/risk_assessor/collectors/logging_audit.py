"""Registri, audit e protezione attiva: auditd, syslog/journald persistente, fail2ban, permessi dei log.

Solo lettura. Funziona con systemd, OpenRC e runit; se l'init non è riconoscibile
(container) lo stato dei servizi non si può verificare e il report lo dice.
"""
from __future__ import annotations

import re

from risk_assessor.collectors._platform import (
    enable_hint, install_hint, join_hints, service_active, unverifiable,
)
from risk_assessor.collectors._privileged import run_privileged
from risk_assessor.host import host_info
from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Confidence, Finding, Severity


def _f(title, sev, desc, evidence, reco, source, conf=Confidence.MEDIUM, command=""):
    return Finding(title=title, category="logging", severity=sev, description=desc,
                   evidence=evidence, recommendation=reco, source=source,
                   confidence=conf, command=command)


class LoggingCollector:
    name = "logging"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        findings: list[Finding] = []
        if service_active(executor, "auditd") is None:
            host = host_info(executor)
            findings.append(unverifiable(
                "Servizi di log e audit non verificabili",
                "Non c'è un init system riconoscibile (tipico di un container): non si può sapere se "
                "auditd, syslog o fail2ban sono attivi.",
                f"init: {host.init}" + (f", container {host.container}" if host.container else ""),
                "logging:unverifiable", "logging"))
        else:
            findings.extend(self._auditd(executor))
            findings.extend(self._persistent_logs(executor))
            findings.extend(self._bruteforce_protection(executor))
        findings.extend(self._log_permissions(executor))
        return findings

    @staticmethod
    def _active(executor, *units: str) -> bool:
        return bool(service_active(executor, *units))

    @staticmethod
    def _install_cmd(executor, generic: str, unit: str) -> str:
        host = host_info(executor)
        return join_hints(install_hint(host, generic), enable_hint(host, unit))

    def _auditd(self, executor) -> list[Finding]:
        if self._active(executor, "auditd"):
            return []
        return [_f(
            "auditd non attivo", Severity.LOW,
            "Il sistema di audit del kernel non è in esecuzione: accessi privilegiati, modifiche ai file "
            "sensibili e comandi eseguiti non vengono registrati in modo tracciabile.",
            "servizio auditd non attivo",
            "Installare e attivare auditd, con regole almeno per /etc/passwd, /etc/shadow, sudoers e sshd_config.",
            "logging:auditd-inactive",
            command=self._install_cmd(executor, "auditd", "auditd"))]

    def _persistent_logs(self, executor) -> list[Finding]:
        # rsyslog/syslog-ng ovunque; "syslog" è il syslogd di BusyBox su Alpine (scrive su disco).
        if self._active(executor, "rsyslog", "syslog-ng", "syslog", "syslogd"):
            return []
        if host_info(executor).init not in ("systemd", "unknown"):
            return [_f(
                "Nessun servizio di log attivo", Severity.MEDIUM,
                "Non è attivo alcun servizio syslog: gli eventi di sistema non vengono registrati su disco.",
                "rsyslog, syslog-ng e syslog non attivi",
                "Attivare un servizio syslog (rsyslog o syslog-ng, o il syslogd di BusyBox).",
                "logging:no-persistent-logs",
                command=self._install_cmd(executor, "rsyslog", "rsyslog"))]
        _, _, rc = executor.execute_command(["test", "-d", "/var/log/journal"])
        if rc == 0:
            return []
        conf, _, crc = executor.execute_command(["cat", "/etc/systemd/journald.conf"])
        if crc == 0 and re.search(r"^\s*Storage\s*=\s*persistent", conf, re.MULTILINE | re.IGNORECASE):
            return []
        return [_f(
            "Nessun registro persistente dei log", Severity.MEDIUM,
            "Non c'è rsyslog né syslog-ng attivo e il journal di systemd è solo in memoria: dopo un riavvio "
            "i log spariscono, e dopo un'intrusione non resta nulla da analizzare.",
            "rsyslog/syslog-ng non attivi, /var/log/journal assente",
            "Attivare rsyslog oppure impostare Storage=persistent in /etc/systemd/journald.conf.",
            "logging:no-persistent-logs",
            command="sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal"
                    " && sudo systemctl restart systemd-journald")]

    def _bruteforce_protection(self, executor) -> list[Finding]:
        if not self._active(executor, "ssh", "sshd"):
            return []
        if self._active(executor, "fail2ban", "sshguard", "crowdsec"):
            return []
        return [_f(
            "Nessuna protezione contro il brute force su SSH", Severity.LOW,
            "SSH è attivo ma nessuno strumento (fail2ban, sshguard, crowdsec) blocca gli indirizzi che "
            "provano molte password.",
            "ssh attivo; fail2ban/sshguard/crowdsec non attivi",
            "Installare fail2ban o sshguard, oppure usare solo l'autenticazione a chiave e limitare l'accesso con il firewall.",
            "logging:no-bruteforce-protection",
            command=self._install_cmd(executor, "fail2ban", "fail2ban"))]

    def _log_permissions(self, executor) -> list[Finding]:
        res = run_privileged(executor, ["find", "/var/log", "-maxdepth", "2", "-type", "f", "-perm", "-o+w"])
        paths = [p for p in res.out.splitlines() if p.startswith("/var/log/")]
        if not paths:
            return []
        return [_f(
            f"File di log scrivibili da tutti ({len(paths)})", Severity.MEDIUM,
            "Un utente qualsiasi può modificare questi log e cancellare o falsificare le tracce.",
            "\n".join(paths[:15]), "Togliere la scrittura agli altri: chmod o-w sui file indicati.",
            "logging:world-writable-logs", Confidence.HIGH)]

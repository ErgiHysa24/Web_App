"""Servizi e porte in ascolto (sola lettura), con systemd, OpenRC o runit.

- servizi in errore e servizi insicuri attivi (telnet, rsh, FTP...);
- porte in ascolto: servizi in chiaro e servizi pensati per la rete interna (database,
  cache, API di Docker) raggiungibili su tutte le interfacce.

Se l'init non è riconoscibile (container) o mancano sia `ss` sia `netstat`, il report
lo dice con un finding informativo invece di tacere.
"""
from __future__ import annotations

from risk_assessor.collectors._platform import listening_sockets, unverifiable
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import host_info
from risk_assessor.models import Confidence, Finding, Severity


# Servizi noti per essere insicuri o deprecati
DANGEROUS_SERVICES = {
    "telnet": ("Telnet", Severity.HIGH, "Telnet trasmette credenziali in chiaro. Usare SSH."),
    "telnetd": ("Telnet server", Severity.HIGH, "Telnet trasmette credenziali in chiaro. Usare SSH."),
    "rsh": ("rsh", Severity.HIGH, "rsh non cifra il traffico. Usare SSH."),
    "rlogin": ("rlogin", Severity.HIGH, "rlogin non cifra il traffico. Usare SSH."),
    "rexec": ("rexec", Severity.HIGH, "rexec non cifra il traffico. Usare SSH."),
    "vsftpd": ("FTP server", Severity.MEDIUM, "FTP non cifra il traffico. Usare SFTP/FTPS."),
    "proftpd": ("FTP server", Severity.MEDIUM, "FTP non cifra il traffico. Usare SFTP/FTPS."),
    "pure-ftpd": ("FTP server", Severity.MEDIUM, "FTP non cifra il traffico. Usare SFTP/FTPS."),
    "tftp": ("TFTP", Severity.MEDIUM, "TFTP non ha autenticazione. Usare SFTP."),
    "finger": ("finger", Severity.LOW, "finger espone informazioni sugli utenti."),
    "rpcbind": ("rpcbind", Severity.LOW, "rpcbind espone servizi RPC. Limitare l'accesso."),
}

# Porte note pericolose (porta: nome servizio)
# Servizi non cifrati o deprecati, per (protocollo, porta): la stessa porta può avere
# significati diversi (514/tcp è rsh, 514/udp è syslog; tftp è solo 69/udp).
DANGEROUS_PORTS = {
    ("tcp", "23"): "telnet",
    ("tcp", "21"): "ftp",
    ("tcp", "514"): "rsh",
    ("tcp", "513"): "rlogin",
    ("tcp", "512"): "rexec",
    ("udp", "69"): "tftp",
    ("tcp", "79"): "finger",
}

# Servizi pensati per la rete interna: su tutte le interfacce sono esposti a chiunque
# raggiunga la macchina (il firewall può ancora bloccarli, da qui la confidenza media).
INTERNAL_PORTS = {
    "2375": ("API di Docker senza TLS", Severity.CRITICAL,
             "Chi raggiunge questa porta controlla Docker, e quindi la macchina, senza autenticazione."),
    "6379": ("Redis", Severity.HIGH, "Redis spesso non ha password: dati leggibili e modificabili da remoto."),
    "27017": ("MongoDB", Severity.HIGH, "Un MongoDB raggiungibile dall'esterno è un bersaglio frequente di furti di dati."),
    "11211": ("Memcached", Severity.HIGH, "Memcached non ha autenticazione e può essere usato per attacchi di amplificazione."),
    "9200": ("Elasticsearch", Severity.HIGH, "Elasticsearch esposto può permettere di leggere o cancellare gli indici."),
    "5432": ("PostgreSQL", Severity.MEDIUM, "Il database accetta connessioni da qualsiasi rete."),
    "3306": ("MySQL/MariaDB", Severity.MEDIUM, "Il database accetta connessioni da qualsiasi rete."),
}
# Indirizzi "tutte le interfacce" da RICONOSCERE nell'output di ss/netstat (qui non si apre
# nessuna porta: per questo l'avviso di Bandit sull'ascolto su 0.0.0.0 non si applica).
ANY_ADDRESS = frozenset({"0.0.0.0", "*", "::", "[::]", ""})  # nosec B104


class ServicesCollector:
    name = "services"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        host = host_info(executor)
        findings: list[Finding] = []
        init = host.init
        if init == "unknown" and host.commands is None:
            init = "systemd"   # rilevamento fallito: si prova comunque con systemctl
        if init == "systemd":
            findings.extend(self._check_failed_systemd(executor))
            findings.extend(self._check_dangerous_systemd(executor))
        elif init == "openrc":
            findings.extend(self._check_openrc(executor))
        elif init == "runit":
            findings.extend(self._check_dangerous_runit(executor))
        else:
            findings.append(unverifiable(
                "Stato dei servizi non verificabile",
                "Non c'è un init system riconoscibile (tipico di un container): non si può sapere "
                "quali servizi sono attivi o in errore.",
                f"init: {init}" + (f", container {host.container}" if host.container else ""),
                "services:unverifiable", "services"))
        findings.extend(self._check_listening_ports(executor))
        return findings

    # ------------------------------------------------------------------ systemd
    def _check_failed_systemd(self, executor) -> list[Finding]:
        """Rileva unit systemd in stato failed."""
        out, _, rc = executor.execute_command(
            ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"]
        )
        if rc != 0:
            return []
        failed_units = [line.strip() for line in out.splitlines() if line.strip()]
        return self._failed_finding(failed_units, "systemd", "systemctl status <unit>")

    def _check_dangerous_systemd(self, executor) -> list[Finding]:
        """Un solo comando per tutti i servizi: una riga di stato per ciascuno, nello stesso ordine."""
        names = list(DANGEROUS_SERVICES)
        out, _, _ = executor.execute_command(["systemctl", "is-active", *names])
        states = [s.strip().lower() for s in out.splitlines()]
        if len(states) != len(names):
            return []
        return [self._dangerous(n, f"systemctl is-active {n}: active")
                for n, state in zip(names, states) if state == "active"]

    # -------------------------------------------------------------------- OpenRC
    def _check_openrc(self, executor) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["rc-status", "--crashed"])
        if rc == 0:
            crashed = [ln.strip() for ln in out.splitlines() if ln.strip()]
            findings.extend(self._failed_finding(crashed, "OpenRC", "rc-service <servizio> status"))
        out, _, rc = executor.execute_command(["rc-status", "--all"])
        if rc == 0:
            started = {ln.split()[0] for ln in out.splitlines()
                       if "started" in ln.lower() and ln.split()}
            findings.extend(self._dangerous(n, f"rc-status: {n} started")
                            for n in DANGEROUS_SERVICES if n in started)
        return findings

    # --------------------------------------------------------------------- runit
    def _check_dangerous_runit(self, executor) -> list[Finding]:
        findings: list[Finding] = []
        for name in DANGEROUS_SERVICES:
            out, _, rc = executor.execute_command(["sv", "status", name])
            if rc == 0 and out.lstrip().startswith("run:"):
                findings.append(self._dangerous(name, f"sv status {name}: run"))
        return findings

    # -------------------------------------------------------------------- comuni
    @staticmethod
    def _failed_finding(units: list[str], init: str, how: str) -> list[Finding]:
        if not units:
            return []
        return [Finding(
            title=f"Servizi {init} in errore: {len(units)}",
            category="services",
            severity=Severity.MEDIUM,
            description=f"Sono presenti {len(units)} servizi in errore.",
            evidence="\n".join(units[:10])[:500],
            recommendation=f"Investigare i servizi in errore con '{how}'.",
            source="services:systemd-failed" if init == "systemd" else "services:failed",
            confidence=Confidence.HIGH,
        )]

    @staticmethod
    def _dangerous(svc: str, evidence: str) -> Finding:
        label, severity, reco = DANGEROUS_SERVICES[svc]
        return Finding(
            title=f"Servizio pericoloso attivo: {label}",
            category="services",
            severity=severity,
            description=f"Il servizio '{svc}' è attivo.",
            evidence=evidence,
            recommendation=reco,
            source=f"services:dangerous-{svc}",
            confidence=Confidence.HIGH,
        )

    def _check_listening_ports(self, executor) -> list[Finding]:
        """Porte in ascolto note per essere pericolose o pensate per la sola rete interna."""
        listening = listening_sockets(executor)
        if listening is None:
            return [unverifiable(
                "Porte in ascolto non verificabili",
                "Sul sistema non ci sono né `ss` né `netstat`: le porte aperte non sono state controllate.",
                "ss e netstat non trovati", "services:ports-unverifiable", "network")]
        sockets, used = listening
        findings: list[Finding] = []

        found_ports: dict[str, str] = {}
        exposed: dict[str, str] = {}
        for proto, addr, port in sockets:
            if (proto, port) in DANGEROUS_PORTS:
                found_ports[f"{port}/{proto}"] = DANGEROUS_PORTS[(proto, port)]
            if proto == "tcp" and port in INTERNAL_PORTS and addr.strip("[]") in ANY_ADDRESS:
                exposed[port] = addr or "*"

        if found_ports:
            lines = [f"Porta {p} ({svc}) in ascolto" for p, svc in found_ports.items()]
            findings.append(Finding(
                title=f"Porte pericolose in ascolto: {', '.join(found_ports.keys())}",
                category="network",
                severity=Severity.HIGH,
                description="Sono in ascolto porte associate a servizi non cifrati o deprecati.",
                evidence="\n".join(lines)[:500],
                recommendation="Disabilitare i servizi associati o limitarli con firewall.",
                source="services:dangerous-ports",
                confidence=Confidence.MEDIUM,
            ))
        for port, addr in sorted(exposed.items(), key=lambda kv: int(kv[0])):
            label, severity, why = INTERNAL_PORTS[port]
            findings.append(Finding(
                title=f"{label} in ascolto su tutte le interfacce (porta {port})",
                category="network",
                severity=severity,
                description=f"{why} Il servizio non è limitato a localhost o a una rete interna.",
                evidence=f"{used}: {addr}:{port} in ascolto",
                recommendation=("Farlo ascoltare solo su 127.0.0.1 (o sulla rete interna dei container) "
                                "e/o bloccare la porta con il firewall; attivare l'autenticazione."),
                source=f"services:exposed-{port}",
                confidence=Confidence.MEDIUM,
            ))
        return findings

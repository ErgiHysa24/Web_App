"""Parser for Nmap XML output.

Trasforma l'output XML di Nmap (nmap -oX -) in Finding normalizzati.
Non esegue Nmap: riceve solo la stringa XML.
"""
from __future__ import annotations
# stdlib ET solo per i tipi (Element); il parsing passa da defusedxml (SafeET)
import xml.etree.ElementTree as ET  # nosec B405

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from dataclasses import dataclass

from risk_assessor.models import Finding, Severity, Confidence


# Porte con semantica di sicurezza nota.
# (porta, protocollo) -> (label, severità, raccomandazione)
RISKY_PORTS: dict[tuple[int, str], tuple[str, Severity, str]] = {
    (23, "tcp"):    ("Telnet", Severity.CRITICAL, "Disabilitare Telnet e usare SSH."),
    (21, "tcp"):    ("FTP", Severity.HIGH, "Usare SFTP/FTPS o disabilitare FTP."),
    (69, "udp"):    ("TFTP", Severity.HIGH, "Disabilitare TFTP se non necessario."),
    (445, "tcp"):   ("SMB", Severity.HIGH, "Limitare SMB con firewall o disabilitare."),
    (139, "tcp"):   ("NetBIOS", Severity.MEDIUM, "Limitare NetBIOS con firewall."),
    (3389, "tcp"):  ("RDP", Severity.HIGH, "Limitare RDP a VPN o disabilitare."),
    (5900, "tcp"):  ("VNC", Severity.HIGH, "Proteggere VNC con password forte o disabilitare."),
    (3306, "tcp"):  ("MySQL", Severity.HIGH, "Restringere MySQL con firewall o bind locale."),
    (5432, "tcp"):  ("PostgreSQL", Severity.HIGH, "Restringere PostgreSQL con firewall."),
    (6379, "tcp"):  ("Redis", Severity.HIGH, "Proteggere Redis con password o bind locale."),
    (27017, "tcp"): ("MongoDB", Severity.HIGH, "Restringere MongoDB con firewall."),
    (9200, "tcp"):  ("Elasticsearch", Severity.HIGH, "Proteggere Elasticsearch con auth."),
    (2375, "tcp"):  ("Docker daemon (no TLS)", Severity.CRITICAL, "Non esporre Docker daemon senza TLS/auth."),
}


@dataclass
class NmapHost:
    address: str
    hostnames: list[str]
    open_ports: list[tuple[int, str, str, str]]  # port, proto, service, state
    state: str


def _not_completed(reason: str, evidence: str) -> Finding:
    return Finding(
        title="Nmap: scansione non completata",
        category="network",
        severity=Severity.INFO,
        description=(f"{reason} Le porte aperte non sono state verificate: non significa che "
                     "siano tutte chiuse."),
        evidence=evidence[:500],
        recommendation="Eseguire nmap a mano sul sistema per vedere l'errore.",
        source="nmap:failed",
        confidence=Confidence.LOW,
    )


def parse_nmap_xml(xml_text: str) -> list[Finding]:
    """Parse Nmap XML e restituisce Finding normalizzati.

    Mai un falso "nessuna porta": XML vuoto, illeggibile o troncato e host che non
    risponde diventano "scansione non completata"; nessuna porta aperta su un host attivo
    è detto esplicitamente (nmap:summary).
    """
    if not xml_text or not xml_text.strip():
        return [_not_completed("Nmap non ha prodotto output.", "")]

    try:
        root = SafeET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException) as e:
        return [_not_completed("L'output di Nmap non è leggibile (interrotto o troncato).",
                               f"{type(e).__name__}: {e}")]

    findings: list[Finding] = []
    up = 0
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host is None or host.state != "up":
            continue
        up += 1
        findings.extend(_host_to_findings(host))
    if not up:
        # Il motivo, se nmap lo scrive: <finished exit="error" errormsg="..."/>, <hosts up= down=/>
        details = []
        for el in root.iter():
            tag = el.tag.rsplit("}", 1)[-1]
            if tag == "finished" and (el.get("errormsg") or el.get("exit") == "error"):
                details.append(f"errore di nmap: {el.get('errormsg') or el.get('summary') or 'exit=error'}")
            elif tag == "hosts":
                details.append(f"host: up={el.get('up', '?')} down={el.get('down', '?')} total={el.get('total', '?')}")
            elif tag == "status" and el.get("state"):
                details.append(f"stato: {el.get('state')} ({el.get('reason', '')})")
        return [_not_completed("L'host non ha risposto alla scansione.",
                               "; ".join(details)[:300] or "nessun host attivo nel risultato")]
    return findings


def extract_open_ports(xml_text: str) -> set[tuple[int, str]]:
    """Insieme (porta, protocollo) delle porte aperte; vuoto se l'XML non è valido."""
    if not xml_text or not xml_text.strip():
        return set()
    try:
        root = SafeET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        return set()
    ports: set[tuple[int, str]] = set()
    for host_el in root.findall("host"):
        host = _parse_host(host_el)
        if host is not None and host.state == "up":
            ports.update((p, proto) for p, proto, _svc, _st in host.open_ports)
    return ports


def _parse_host(host_el: ET.Element) -> NmapHost | None:
    status = host_el.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    address = ""
    addr_el = host_el.find("address")
    if addr_el is not None:
        address = addr_el.get("addr", "")

    hostnames: list[str] = []
    for h in host_el.findall("hostnames/hostname"):
        name = h.get("name")
        if name:
            hostnames.append(name)

    open_ports: list[tuple[int, str, str, str]] = []
    for port_el in host_el.findall("ports/port"):
        portid = port_el.get("portid")
        proto = port_el.get("protocol", "tcp")
        state_el = port_el.find("state")
        port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        if port_state != "open":
            continue
        svc_el = port_el.find("service")
        service = ""
        if svc_el is not None:
            name = svc_el.get("name", "")
            product = svc_el.get("product", "")
            version = svc_el.get("version", "")
            service = " ".join(p for p in (name, product, version) if p).strip()
        try:
            port_num = int(portid)
        except (TypeError, ValueError):
            continue
        open_ports.append((port_num, proto, service, port_state))

    return NmapHost(address=address, hostnames=hostnames, open_ports=open_ports, state=state)


def _host_to_findings(host: NmapHost) -> list[Finding]:
    findings: list[Finding] = []
    label = host.hostnames[0] if host.hostnames else host.address or "unknown"

    # Filtra porte rischiose
    for port, proto, service, _state in host.open_ports:
        key = (port, proto)
        if key in RISKY_PORTS:
            p_label, severity, reco = RISKY_PORTS[key]
            evidence = f"{port}/{proto} open"
            if service:
                evidence += f" {service}"
            findings.append(Finding(
                title=f"Servizio rischioso esposto: {p_label}",
                category="network",
                severity=severity,
                description=(
                    f"Porta {port}/{proto} aperta su {label} — servizio {p_label}"
                    + (f" ({service})" if service else "")
                    + "."
                ),
                evidence=evidence,
                recommendation=reco,
                source=f"nmap:port-{port}",
                confidence=Confidence.HIGH,
            ))

    if not host.open_ports:
        findings.append(Finding(
            title=f"Nessuna porta aperta su {label} (servizi più comuni)",
            category="network",
            severity=Severity.INFO,
            description=(f"Nmap ha analizzato le 100 porte più comuni di {label} e non ne ha trovate "
                         "aperte."),
            evidence="nmap -sV -F: 0 porte aperte",
            recommendation="Nessuna azione richiesta.",
            source="nmap:summary",
            confidence=Confidence.HIGH,
        ))

    # Info generale: quante porte aperte
    if host.open_ports:
        port_list = "\n".join(
            f"{p}/{proto} {svc}".strip() for p, proto, svc, _ in host.open_ports[:20]
        )
        findings.append(Finding(
            title=f"Porte aperte su {label}: {len(host.open_ports)}",
            category="network",
            severity=Severity.INFO,
            description=f"Rilevate {len(host.open_ports)} porte aperte sull'host {label}.",
            evidence=port_list[:500],
            recommendation="Verificare che ogni porta aperta sia necessaria.",
            source="nmap:open-ports",
            confidence=Confidence.HIGH,
        ))

    return findings

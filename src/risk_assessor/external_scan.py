"""Scansione Nmap "dall'esterno": eseguita sul PC dell'operatore verso l'host da valutare.

Mostra ciò che un attaccante in rete vede davvero (firewall, NAT, port forwarding inclusi),
a differenza della scansione interna che gira su 127.0.0.1 del bersaglio.

Sicurezza:
- usa l'nmap GIÀ installato sul PC dell'operatore: non installa nulla;
- il bersaglio è UN solo host (nome o IP) validato; intervalli, reti CIDR e valori che
  iniziano con "-" (opzioni) vengono rifiutati;
- la scansione parte solo se l'operatore l'ha richiesta esplicitamente (--external-scan).
"""
from __future__ import annotations

import platform
import re
import shutil
from dataclasses import replace

from risk_assessor.executor import BaseExecutor, LocalExecutor
from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.parsers.nmap import extract_open_ports, parse_nmap_xml
from risk_assessor.sanitize import clean_text

_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}")
EXTERNAL_TIMEOUT = 600


def _install_hint(system: str | None = None) -> str:
    """Come installare nmap sul PC dell'operatore, in base al suo sistema."""
    system = system or platform.system()
    if system == "Windows":
        return "installalo con 'winget install Insecure.Nmap' o da https://nmap.org/download.html"
    if system == "Darwin":
        return "installalo con 'brew install nmap'"
    return "installalo, ad esempio con 'sudo apt install nmap'"


def valid_external_host(host: str) -> bool:
    """True per un singolo host (IP o nome); False per opzioni, reti o intervalli."""
    if not host or not _HOST_RE.fullmatch(host):
        return False
    return "/" not in host and ".." not in host


def _fmt(ports: set[tuple[int, str]], limit: int = 20) -> str:
    items = sorted(ports)
    txt = ", ".join(f"{p}/{proto}" for p, proto in items[:limit])
    return txt + (f" … (+{len(items) - limit})" if len(items) > limit else "")


def _relabel(f: Finding) -> Finding:
    return replace(
        f,
        title=f"Dall'esterno: {f.title}",
        source=f.source.replace("nmap:", "nmap-external:", 1),
        description=f"[Scansione dall'esterno] {f.description}",
    )


def compare_ports(external: set[tuple[int, str]],
                  internal: set[tuple[int, str]] | None) -> list[Finding]:
    """Confronta le porte viste dall'esterno con quelle viste dall'interno."""
    if internal is None:
        return []
    out: list[Finding] = []
    hidden = internal - external
    if hidden:
        out.append(Finding(
            title=f"Porte in ascolto non raggiungibili dall'esterno ({len(hidden)})",
            category="network", severity=Severity.INFO,
            description="Queste porte sono aperte sul sistema ma non risultano raggiungibili dalla rete: "
                        "bloccate da un firewall oppure in ascolto solo su localhost. È la situazione desiderata "
                        "per i servizi che non devono essere pubblici.",
            evidence=_fmt(hidden),
            recommendation="Nessuna azione, se i servizi sono davvero privati.",
            source="nmap-external:filtered", confidence=Confidence.MEDIUM))
    extra = external - internal
    if extra:
        out.append(Finding(
            title=f"Porte raggiungibili dall'esterno ma non viste dall'interno ({len(extra)})",
            category="network", severity=Severity.LOW,
            description="Dall'esterno rispondono porte che la scansione interna non ha trovato. Succede con "
                        "NAT o port forwarding su un altro dispositivo, con scansioni interne parziali "
                        "o con servizi che compaiono solo a tratti.",
            evidence=_fmt(extra),
            recommendation="Verificare a quale macchina o servizio corrispondono queste porte.",
            source="nmap-external:extra", confidence=Confidence.MEDIUM))
    return out


def run_external_scan(
    host: str,
    internal_ports: set[tuple[int, str]] | None = None,
    executor: BaseExecutor | None = None,
    which=shutil.which,
) -> tuple[list[Finding], str | None]:
    """Esegue nmap dal PC locale verso `host`. Ritorna (findings, errore o None)."""
    if not valid_external_host(host):
        return [], f"scansione esterna: host non valido ({clean_text(host)[:60]})"
    path = which("nmap")
    if not path:
        return [], ("scansione esterna: nmap non è installato sul PC da cui lanci il tool "
                    f"({_install_hint()}) e riprova")
    ex = executor or LocalExecutor()
    out, err, rc = ex.execute_command(
        [path, "-sV", "-T4", "-F", "-Pn", "-oX", "-", host], timeout=EXTERNAL_TIMEOUT)
    if not out.strip():
        return [], clean_text(f"scansione esterna: nmap senza risultati (rc={rc}) {err.strip()[:150]}")
    parsed = parse_nmap_xml(out)
    failed = next((f for f in parsed if f.source == "nmap:failed"), None)
    if failed is not None:
        return [], clean_text(f"scansione esterna: {failed.description.split('.')[0]} "
                              f"(rc={rc}) {failed.evidence[:120]}")
    # "nessuna porta" lo dice già nmap-external:none qui sotto
    findings = [_relabel(f) for f in parsed if f.source != "nmap:summary"]
    ports = extract_open_ports(out)
    findings.extend(compare_ports(ports, internal_ports))
    if not ports:
        findings.append(Finding(
            title="Nessuna porta raggiungibile dall'esterno", category="network",
            severity=Severity.INFO,
            description="La scansione dei servizi più comuni dal tuo PC non ha trovato porte aperte "
                        "(host protetto da firewall, spento o non raggiungibile).",
            evidence=f"nmap -F verso {host}",
            recommendation="Se ti aspettavi servizi raggiungibili, controlla firewall e rete.",
            source="nmap-external:none", confidence=Confidence.MEDIUM))
    return findings, None

"""Macro-aree del report: raggruppano le categorie dei finding in pochi argomenti.

Servono alla heatmap del report HTML (macro-aree × severità) e al dettaglio di ogni
area (controlli × severità, con l'elenco dei finding). L'area si ricava dalla categoria
del finding e, se la categoria non è nota, dall'origine (`source`).
"""
from __future__ import annotations

from collections import OrderedDict

from risk_assessor.models import Finding

# id -> (nome, descrizione), nell'ordine in cui compaiono nel report.
AREAS: "OrderedDict[str, tuple[str, str]]" = OrderedDict([
    ("access", ("Accessi e privilegi",
                "Utenti, amministratori, SSH, password policy e regole sudo.")),
    ("network", ("Rete ed esposizione",
                 "Firewall, porte e servizi in ascolto, scansioni Nmap.")),
    ("vulns", ("Vulnerabilità e aggiornamenti",
               "CVE note nei pacchetti, aggiornamenti mancanti o non automatici.")),
    ("malware", ("Malware e compromissione",
                 "Rootkit, malware, meccanismi di persistenza sospetti.")),
    ("integrity", ("Integrità dei file",
                   "File di sistema modificati rispetto ai pacchetti o alla baseline.")),
    ("hardening", ("Hardening e conformità",
                   "Kernel, file system, SELinux/AppArmor, cifratura, audit Lynis e OpenSCAP.")),
    ("logging", ("Log e monitoraggio", "Log persistenti, auditd, protezione anti brute-force.")),
    ("apps", ("Applicazioni e codice",
              "Codice, segreti, librerie e configurazione delle applicazioni (rapporti polyscan importati).")),
    ("system", ("Sistema e svolgimento", "Informazioni sul sistema ed esito dei controlli.")),
])

_BY_CATEGORY = {
    "users": "access", "authentication": "access", "privileges": "access", "ssh": "access",
    "network": "network", "firewall": "network", "services": "network",
    "vulnerabilities": "vulns", "packages": "vulns", "updates": "vulns",
    "rootkit": "malware", "malware": "malware", "persistence": "malware",
    "integrity": "integrity",
    "hardening": "hardening", "kernel": "hardening", "filesystem": "hardening",
    "protections": "hardening", "compliance": "hardening",
    "logging": "logging",
    "application": "apps", "secrets": "apps", "dependencies": "apps", "app-config": "apps", "web": "apps",
    "system_info": "system", "info": "system", "assessment": "system", "error": "system",
    "fatal": "system",
}
_BY_SOURCE = {
    "users-collector": "access", "ssh-config": "access", "auth-policy": "access", "sudo": "access",
    "services": "network", "firewall": "network", "nmap": "network", "nmap-external": "network",
    "debsecan": "vulns", "trivy": "vulns", "packages": "vulns", "updates": "vulns",
    "rkhunter": "malware", "chkrootkit": "malware", "clamav": "malware", "persistence": "malware",
    "aide": "integrity", "debsums": "integrity",
    "lynis": "hardening", "openscap": "hardening", "kernel": "hardening",
    "filesystem": "hardening", "protections": "hardening",
    "logging": "logging", "polyscan": "apps",
}

# Nome leggibile del controllo che ha prodotto il finding (prefisso di `source`).
CONTROL_LABEL = {
    "users-collector": "Utenti e gruppi", "ssh-config": "Configurazione SSH",
    "auth-policy": "Password policy e sudo", "services": "Servizi e porte", "firewall": "Firewall",
    "nmap": "Nmap", "nmap-external": "Nmap dall'esterno", "debsecan": "debsecan", "trivy": "Trivy",
    "packages": "Pacchetti", "updates": "Aggiornamenti", "rkhunter": "rkhunter",
    "chkrootkit": "chkrootkit", "clamav": "ClamAV", "persistence": "Persistenza",
    "aide": "AIDE", "debsums": "debsums", "lynis": "Lynis", "openscap": "OpenSCAP",
    "kernel": "Kernel", "filesystem": "File system", "protections": "Protezioni del sistema",
    "logging": "Log e audit", "linux-check": "Informazioni di sistema",
}
_MACOS_CONTROL = {
    "users": "Utenti (macOS)", "authentication": "Accesso e password (macOS)",
    "firewall": "Firewall (macOS)", "services": "Condivisioni (macOS)", "network": "Porte (macOS)",
    "vulnerabilities": "Aggiornamenti (macOS)", "packages": "Aggiornamenti (macOS)",
    "persistence": "Persistenza (macOS)", "protections": "SIP, FileVault, Gatekeeper",
    "system_info": "Informazioni di sistema",
}


def area_of(f: Finding) -> str:
    """Id della macro-area di un finding."""
    cat = (f.category or "").lower()
    if cat in _BY_CATEGORY:
        return _BY_CATEGORY[cat]
    prefix = (f.source or "").split(":", 1)[0].lower()
    return _BY_SOURCE.get(prefix, "system")


_POLYSCAN_CONTROL = {"code": "Codice (polyscan)", "secret": "Segreti (polyscan)",
                     "dependency": "Librerie (polyscan)", "config": "Configurazione (polyscan)",
                     "runtime": "Sito in esecuzione (polyscan)"}


def control_of(f: Finding) -> str:
    """Nome leggibile del controllo (o tool) che ha prodotto il finding."""
    prefix = (f.source or "").split(":", 1)[0].lower()
    if prefix == "polyscan":
        return _POLYSCAN_CONTROL.get((f.source or "").split(":", 1)[-1].lower(), "polyscan")
    if prefix == "macos":
        return _MACOS_CONTROL.get((f.category or "").lower(), "Controlli macOS")
    return CONTROL_LABEL.get(prefix, prefix or "altro")


def group_by_area(findings: list[Finding]) -> "OrderedDict[str, list[Finding]]":
    """Finding raggruppati per macro-area, nell'ordine di AREAS (solo aree non vuote)."""
    groups: OrderedDict[str, list[Finding]] = OrderedDict((a, []) for a in AREAS)
    for f in findings:
        groups[area_of(f)].append(f)
    return OrderedDict((a, fs) for a, fs in groups.items() if fs)

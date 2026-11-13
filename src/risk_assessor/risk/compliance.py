"""Riferimenti normativi dei finding: CIS Controls v8, ISO/IEC 27001:2022 (Annex A), NIST SP 800-53 Rev. 5.

Ogni finding è associato ai controlli che il problema riguarda, a partire dalla sua
origine (`source`). È un aiuto per l'audit, non una certificazione: un finding indica
una possibile carenza rispetto a quel controllo, e l'assenza di finding non dimostra la
conformità. I CIS *Benchmarks* (le guide di configurazione per sistema operativo) sono
coperti da OpenSCAP e Lynis; qui si usano i CIS *Controls*, comuni a tutti i sistemi.

Le regole sono valutate in ordine: vince la prima il cui prefisso corrisponde alla
`source` del finding (i prefissi più specifici stanno prima).
"""
from __future__ import annotations

from risk_assessor.models import Finding

FRAMEWORKS = {
    "cis": "CIS Controls v8",
    "iso27001": "ISO/IEC 27001:2022",
    "nist": "NIST SP 800-53 Rev. 5",
}

# Titoli dei controlli usati (per i report).
TITLES = {
    "cis": {
        "2.7": "Allowlist authorized scripts",
        "3.3": "Configure data access control lists",
        "3.6": "Encrypt data on end-user devices",
        "3.11": "Encrypt sensitive data at rest",
        "4.1": "Establish and maintain a secure configuration process",
        "4.4": "Implement and manage a firewall on servers",
        "4.5": "Implement and manage a firewall on end-user devices",
        "4.7": "Manage default accounts on enterprise assets and software",
        "4.8": "Uninstall or disable unnecessary services",
        "5.1": "Establish and maintain an inventory of accounts",
        "5.2": "Use unique passwords",
        "5.4": "Restrict administrator privileges to dedicated administrator accounts",
        "7.1": "Establish and maintain a vulnerability management process",
        "7.3": "Perform automated operating system patch management",
        "7.5": "Perform automated vulnerability scans of internal enterprise assets",
        "8.2": "Collect audit logs",
        "8.3": "Ensure adequate audit log storage",
        "10.1": "Deploy and maintain anti-malware software",
        "16.12": "Implement code-level security checks",
    },
    "iso27001": {
        "A.5.15": "Access control",
        "A.5.16": "Identity management",
        "A.5.17": "Authentication information",
        "A.8.2": "Privileged access rights",
        "A.8.3": "Information access restriction",
        "A.8.5": "Secure authentication",
        "A.8.6": "Capacity management",
        "A.8.7": "Protection against malware",
        "A.8.8": "Management of technical vulnerabilities",
        "A.8.9": "Configuration management",
        "A.8.15": "Logging",
        "A.8.16": "Monitoring activities",
        "A.8.19": "Installation of software on operational systems",
        "A.8.20": "Networks security",
        "A.8.24": "Use of cryptography",
        "A.8.26": "Application security requirements",
        "A.8.28": "Secure coding",
    },
    "nist": {
        "AC-2": "Account Management",
        "AC-3": "Access Enforcement",
        "AC-6": "Least Privilege",
        "AC-7": "Unsuccessful Logon Attempts",
        "AC-17": "Remote Access",
        "AU-2": "Event Logging",
        "AU-4": "Audit Log Storage Capacity",
        "AU-9": "Protection of Audit Information",
        "AU-12": "Audit Record Generation",
        "CM-6": "Configuration Settings",
        "CM-7": "Least Functionality",
        "IA-2": "Identification and Authentication (Organizational Users)",
        "IA-5": "Authenticator Management",
        "RA-5": "Vulnerability Monitoring and Scanning",
        "SA-11": "Developer Testing and Evaluation",
        "SC-7": "Boundary Protection",
        "SC-28": "Protection of Information at Rest",
        "SI-2": "Flaw Remediation",
        "SI-3": "Malicious Code Protection",
        "SI-4": "System Monitoring",
        "SI-7": "Software, Firmware, and Information Integrity",
    },
}


def _m(cis=(), iso=(), nist=()) -> dict[str, tuple[str, ...]]:
    return {"cis": tuple(cis), "iso27001": tuple(iso), "nist": tuple(nist)}


_ACCOUNTS = _m(["5.1", "5.4"], ["A.5.16", "A.8.2"], ["AC-2", "AC-6"])
_PASSWORDS = _m(["5.2"], ["A.5.17", "A.8.5"], ["IA-5"])
_PRIVILEGE = _m(["5.4"], ["A.8.2"], ["AC-6"])
_DEFAULT_ACCOUNTS = _m(["4.7"], ["A.5.15", "A.8.2"], ["AC-2"])
_REMOTE = _m(["4.1"], ["A.8.5", "A.8.9"], ["AC-17", "CM-6"])
_FW_SERVER = _m(["4.4"], ["A.8.20"], ["SC-7"])
_FW_DEVICE = _m(["4.5"], ["A.8.20"], ["SC-7"])
_SERVICES = _m(["4.8"], ["A.8.9", "A.8.20"], ["CM-7", "SC-7"])
_VULNS = _m(["7.1", "7.5"], ["A.8.8"], ["RA-5", "SI-2"])
_PATCHING = _m(["7.3"], ["A.8.8"], ["SI-2"])
_MALWARE = _m(["10.1"], ["A.8.7"], ["SI-3"])
_PERSISTENCE = _m(["2.7", "10.1"], ["A.8.7", "A.8.16"], ["SI-3", "SI-4"])
_INTEGRITY = _m([], ["A.8.9", "A.8.19"], ["SI-7"])
_HARDENING = _m(["4.1"], ["A.8.9"], ["CM-6"])
_FILE_ACCESS = _m(["3.3"], ["A.8.3"], ["AC-3", "CM-6"])
_ENCRYPTION = _m(["3.6", "3.11"], ["A.8.24"], ["SC-28"])
_MAC = _m(["4.1"], ["A.8.9"], ["AC-3", "CM-6"])
_LOGGING = _m(["8.2"], ["A.8.15"], ["AU-2", "AU-12"])
_LOG_STORAGE = _m(["8.3"], ["A.8.6"], ["AU-4"])
_BRUTEFORCE = _m([], ["A.8.5"], ["AC-7"])

# (prefisso della source, riferimenti). Il primo prefisso che corrisponde vince.
_RULES: list[tuple[str, dict]] = [
    # accessi
    ("users-collector:privileged-group", _PRIVILEGE),
    ("users-collector:empty-password", _PASSWORDS),
    ("users-collector:", _ACCOUNTS),
    ("auth-policy:sudo", _PRIVILEGE), ("auth-policy:nopasswd", _PRIVILEGE),
    ("auth-policy:no-lockout", _BRUTEFORCE),
    ("auth-policy:", _PASSWORDS),
    ("ssh-config:", _REMOTE),
    ("macos:uid0", _ACCOUNTS), ("macos:admins", _PRIVILEGE),
    ("macos:root-enabled", _DEFAULT_ACCOUNTS), ("macos:guest-enabled", _DEFAULT_ACCOUNTS),
    ("macos:autologin", _m(["4.1"], ["A.8.5"], ["IA-2"])),
    ("macos:password-policy", _PASSWORDS), ("macos:ssh", _REMOTE),
    # rete
    ("firewall:", _FW_SERVER),
    ("macos:firewall", _FW_DEVICE), ("macos:stealth", _FW_DEVICE),
    ("services:", _SERVICES), ("macos:sharing", _SERVICES),
    ("nmap-external:", _m(["4.4", "4.8"], ["A.8.20"], ["SC-7", "CM-7"])),
    ("nmap:", _SERVICES),
    # vulnerabilità e aggiornamenti
    ("debsecan:", _VULNS), ("trivy:", _VULNS),
    ("packages:", _PATCHING), ("updates:", _PATCHING),
    ("macos:updates", _PATCHING), ("macos:security-updates", _PATCHING),
    ("macos:auto-", _PATCHING),
    # malware e compromissione
    ("rkhunter:", _MALWARE), ("chkrootkit:", _MALWARE), ("clamav:", _MALWARE),
    ("persistence:", _PERSISTENCE), ("macos:launch", _PERSISTENCE),
    ("macos:gatekeeper", _m(["2.7", "10.1"], ["A.8.7", "A.8.19"], ["SI-3", "CM-7"])),
    # integrità
    ("aide:", _INTEGRITY), ("debsums:", _INTEGRITY), ("macos:sip", _m(["4.1"], ["A.8.9"], ["SI-7", "CM-6"])),
    # hardening
    ("protections:disk-", _ENCRYPTION), ("macos:filevault", _ENCRYPTION),
    ("protections:", _MAC),
    ("filesystem:disk-usage", _LOG_STORAGE),
    ("filesystem:", _FILE_ACCESS),
    ("kernel:", _HARDENING), ("lynis:", _HARDENING), ("openscap:", _HARDENING),
    # applicazioni (rapporti polyscan importati)
    ("polyscan:code", _m(["16.12"], ["A.8.28"], ["SA-11"])),
    ("polyscan:secret", _m([], ["A.5.17", "A.8.28"], ["IA-5"])),
    ("polyscan:dependency", _VULNS),
    ("polyscan:config", _HARDENING),
    ("polyscan:runtime", _m(["16.12"], ["A.8.26"], ["RA-5"])),
    # log
    ("logging:no-bruteforce-protection", _BRUTEFORCE),
    ("logging:world-writable-logs", _m(["3.3"], ["A.8.15"], ["AU-9"])),
    ("logging:", _LOGGING),
]

# Finding che descrivono lo svolgimento (controllo non eseguito, informazioni di sistema):
# non indicano carenze e non hanno riferimenti.
_NO_REFERENCE_SUFFIXES = ("unverifiable", "unknown", "failed", "error", "sudo-required",
                          "summary", "partial", "system", "container", "installed", "baseline-created")


def controls_for(f: Finding) -> dict[str, tuple[str, ...]]:
    """Controlli di ogni framework a cui si riferisce il finding ({} se nessuno)."""
    source = (f.source or "").lower()
    tail = source.rsplit(":", 1)[-1]
    if any(tail.endswith(s) for s in _NO_REFERENCE_SUFFIXES):
        return {}
    for prefix, refs in _RULES:
        if source.startswith(prefix):
            return {fw: ids for fw, ids in refs.items() if ids}
    return {}


def short_refs(f: Finding) -> str:
    """"CIS 4.4 · ISO A.8.20 · NIST SC-7" ("" se nessun riferimento)."""
    names = {"cis": "CIS", "iso27001": "ISO", "nist": "NIST"}
    return " · ".join(f"{names[fw]} {', '.join(ids)}" for fw, ids in controls_for(f).items())


def coverage(findings: list[Finding], framework: str) -> list[dict]:
    """Per ogni controllo con almeno un problema: quanti finding e la severità peggiore."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    rows: dict[str, dict] = {}
    for f in findings:
        if f.severity.value == "INFO":
            continue
        for cid in controls_for(f).get(framework, ()):
            row = rows.setdefault(cid, {"id": cid, "title": TITLES[framework].get(cid, ""),
                                        "count": 0, "worst": "LOW"})
            row["count"] += 1
            if order.index(f.severity.value) < order.index(row["worst"]):
                row["worst"] = f.severity.value
    return sorted(rows.values(), key=lambda r: (order.index(r["worst"]), -r["count"], _natural(r["id"])))


def _natural(cid: str):
    parts = []
    for p in cid.replace("A.", "").replace("-", ".").split("."):
        parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
    return parts

"""Parser dell'output JSON di `trivy rootfs` (solo vulnerabilità).

Un finding per pacchetto (come per debsecan), con la severità più alta tra le sue
CVE, più un riepilogo. Il comando di rimedio è proposto solo per i pacchetti di
sistema Debian/Ubuntu e RHEL-like, e solo se il nome del pacchetto è "semplice".
"""
from __future__ import annotations

import json

from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.sanitize import safe_shell_arg

_SEV = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW, "UNKNOWN": Severity.INFO,
}
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_APT_TYPES = {"debian", "ubuntu"}
_RPM_TYPES = {"redhat", "centos", "rocky", "alma", "fedora", "amazon", "oracle", "suse", "opensuse"}
_MAX_EVIDENCE_CVES = 10


def _error(reason: str, evidence: str) -> list[Finding]:
    return [Finding(
        title="Trivy: scansione non completata",
        category="vulnerabilities",
        severity=Severity.INFO,
        description=(
            f"{reason} L'assenza di segnalazioni qui NON significa che il sistema "
            "sia privo di vulnerabilità."
        ),
        evidence=evidence[:500],
        recommendation=(
            "Verificare che Trivy sia installato e aggiornato e che la macchina possa "
            "scaricare il database delle vulnerabilità (accesso a internet), poi ripetere."
        ),
        source="trivy:error",
        confidence=Confidence.LOW,
    )]


def _remedy(os_type: str, pkgs: list[str]) -> str:
    """Comando di aggiornamento: solo per nomi "semplici", al massimo 10 pacchetti."""
    args = [a for a in (safe_shell_arg(p) for p in pkgs[:10]) if a]
    if not args:
        return ""
    joined = " ".join(args)
    if os_type in _APT_TYPES:
        return f"sudo apt-get install --only-upgrade {joined}"
    if os_type in _RPM_TYPES:
        return f"sudo dnf upgrade {joined}"
    return ""


def parse_trivy(text: str) -> list[Finding]:
    if not text or not text.strip():
        return _error("Trivy non ha prodotto output.", "")
    try:
        data = json.loads(text)
    except ValueError:
        return _error("L'output di Trivy non è leggibile (probabile errore di esecuzione).",
                      text.strip())
    if not isinstance(data, dict):
        return _error("L'output di Trivy ha un formato inatteso.", text.strip()[:200])
    results = data.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        return _error("L'output di Trivy ha un formato inatteso.", str(type(results)))

    # Con --pkg-types os Trivy analizza solo i pacchetti di sistema: se non ha riconosciuto
    # il sistema operativo (niente Metadata.OS e nessun risultato "os-pkgs") non ha
    # controllato nulla, e zero vulnerabilità non vuol dire "sistema aggiornato".
    meta = data.get("Metadata") if isinstance(data.get("Metadata"), dict) else {}
    os_meta = meta.get("OS") if isinstance(meta.get("OS"), dict) else None
    has_os_pkgs = any(isinstance(r, dict) and r.get("Class") == "os-pkgs" for r in results)
    if not os_meta and not has_os_pkgs:
        return _error("Trivy non ha riconosciuto il sistema operativo, quindi non ha "
                      "analizzato i pacchetti di sistema.",
                      f"Metadata: {json.dumps(meta)[:300]}")

    # (class, target, pacchetto sorgente) -> dati aggregati. Per i pacchetti di sistema si
    # raggruppa per pacchetto SORGENTE: i pacchetti binari di una stessa famiglia (per
    # esempio linux-headers, linux-tools, linux-modules) condividono le stesse CVE e
    # non vanno contati più volte.
    groups: dict[tuple[str, str, str], dict] = {}
    totals = {k: 0 for k in _RANK}
    for res in results:
        if not isinstance(res, dict):
            continue
        cls = str(res.get("Class", ""))
        target = str(res.get("Target", ""))
        rtype = str(res.get("Type", "")).lower()
        for v in res.get("Vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            pkg = str(v.get("PkgName") or "").strip()
            cve = str(v.get("VulnerabilityID") or "").strip()
            if not pkg or not cve:
                continue
            sev = str(v.get("Severity") or "UNKNOWN").upper()
            if sev not in _RANK:
                sev = "UNKNOWN"
            src = str(v.get("SrcName") or "").strip() if cls == "os-pkgs" else ""
            g = groups.setdefault((cls, target, src or pkg), {
                "type": rtype, "installed": str(v.get("InstalledVersion") or ""),
                "cves": [], "seen": set(), "pkgs": [], "fixed": "", "best": -1,
            })
            if pkg not in g["pkgs"]:
                g["pkgs"].append(pkg)
            if cve in g["seen"]:
                continue                      # stessa CVE già contata per questo gruppo
            g["seen"].add(cve)
            g["cves"].append((cve, sev, str(v.get("FixedVersion") or "")))
            totals[sev] += 1
            fixed = str(v.get("FixedVersion") or "")
            if fixed and _RANK[sev] > g["best"]:
                g["fixed"], g["best"] = fixed, _RANK[sev]

    findings: list[Finding] = []
    for (cls, target, pkg), g in sorted(
        groups.items(), key=lambda kv: (-max(_RANK[c[1]] for c in kv[1]["cves"]), kv[0][2])
    ):
        top = max((c[1] for c in g["cves"]), key=lambda s: _RANK[s])
        n = len(g["cves"])
        where = "" if cls == "os-pkgs" else f" ({target})"
        pkgs = g["pkgs"]
        family = f" Pacchetti della stessa famiglia: {', '.join(pkgs[:8])}" + (
            f" e altri {len(pkgs) - 8}." if len(pkgs) > 8 else ".") if len(pkgs) > 1 else ""
        fixed = f" Versione corretta: {g['fixed']}." if g["fixed"] else ""
        evidence = "\n".join(
            f"{cve} [{sev}]" + (f" → {fx}" if fx else "")
            for cve, sev, fx in sorted(g["cves"], key=lambda c: -_RANK[c[1]])[:_MAX_EVIDENCE_CVES]
        )
        if n > _MAX_EVIDENCE_CVES:
            evidence += f"\n… e altre {n - _MAX_EVIDENCE_CVES}"
        findings.append(Finding(
            title=f"Trivy: {n} CVE in {pkg}{where}",
            category="vulnerabilities",
            severity=_SEV[top],
            description=(
                f"Il pacchetto '{pkg}' (versione installata {g['installed'] or 'n/d'}) "
                f"ha {n} vulnerabilità note; la più grave è {top}.{fixed}{family}"
            ),
            evidence=evidence,
            recommendation=(
                f"Aggiornare {pkg} alla versione corretta disponibile."
                if g["fixed"] else
                f"Aggiornare {pkg} appena è disponibile una versione corretta."
            ),
            source="trivy:package",
            confidence=Confidence.HIGH,
            command=_remedy(g["type"], pkgs) if cls == "os-pkgs" else "",
        ))

    total = sum(totals.values())
    if total == 0:
        summary_desc = ("Trivy non ha trovato vulnerabilità note con correzione disponibile "
                        "nei pacchetti analizzati.")
        evidence = ""
    else:
        summary_desc = f"Trivy ha trovato {total} vulnerabilità in {len(groups)} pacchetti (famiglie di pacchetti contate una volta)."
        evidence = ", ".join(f"{k}: {v}" for k, v in totals.items() if v)
    findings.append(Finding(
        title=(f"Trivy: {total} CVE totali su {len(groups)} pacchetti" if total
               else "Trivy: nessuna vulnerabilità con correzione disponibile"),
        category="vulnerabilities",
        severity=Severity.INFO,
        description=summary_desc + " Sono escluse le vulnerabilità senza correzione disponibile.",
        evidence=evidence,
        recommendation="Applicare gli aggiornamenti di sicurezza disponibili."
                       if total else "Nessuna azione richiesta.",
        source="trivy:summary",
        confidence=Confidence.HIGH,
    ))
    return findings

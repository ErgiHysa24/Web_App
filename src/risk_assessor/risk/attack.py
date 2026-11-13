"""Tecniche MITRE ATT&CK collegate ai finding e copertura di rilevamento.

Ogni finding può indicare le tecniche ATT&CK che il problema rende possibili o più facili
(per esempio "PasswordAuthentication yes" → T1110 Brute Force). La tabella è scritta a
mano: è un giudizio di WatchDog, non una mappa ufficiale di MITRE. Nomi e ID sono
verificati sui dati ufficiali ATT&CK (test `test_attack_ids_match_official_data`).

Con un layer di ATT&CK Navigator (per esempio quello di detection-engineering-lab, o
quello esportato da un SIEM) il report dice, per ogni tecnica, se esiste un rilevamento:
un problema la cui tecnica non è rilevata merita più attenzione, perché un attacco che
lo sfrutta passerebbe inosservato. Il punteggio di rischio non cambia: la copertura è
un'informazione in più, non un moltiplicatore nascosto.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from risk_assessor.models import Finding
from risk_assessor.sanitize import clean_text

ATTACK_VERSION = "20.0"

# id -> (nome, tattica principale)
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1014": ("Rootkit", "stealth"),
    "T1021.004": ("Remote Services: SSH", "lateral-movement"),
    "T1053.003": ("Scheduled Task/Job: Cron", "persistence"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1078": ("Valid Accounts", "initial-access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "initial-access"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "persistence"),
    "T1110": ("Brute Force", "credential-access"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "credential-access"),
    "T1543.001": ("Create or Modify System Process: Launch Agent", "persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "persistence"),
    "T1543.004": ("Create or Modify System Process: Launch Daemon", "persistence"),
    "T1548.001": ("Abuse Elevation Control Mechanism: Setuid and Setgid", "privilege-escalation"),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "privilege-escalation"),
    "T1553.001": ("Subvert Trust Controls: Gatekeeper Bypass", "defense-impairment"),
    "T1554": ("Compromise Host Software Binary", "persistence"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "stealth"),
    "T1685.004": ("Disable or Modify Tools: Disable or Modify Linux Audit System Log", "defense-impairment"),
    "T1685.006": ("Disable or Modify Tools: Clear Linux or Mac System Logs", "defense-impairment"),
}

# (prefisso della source, tecniche). Il primo prefisso che corrisponde vince.
_RULES: list[tuple[str, tuple[str, ...]]] = [
    # accesso remoto e credenziali
    ("ssh-config:password", ("T1110", "T1021.004")),
    ("ssh-config:empty-passwords", ("T1078.003", "T1021.004")),
    ("ssh-config:max-auth-tries", ("T1110",)),
    ("ssh-config:permit-root-login", ("T1078.003", "T1021.004")),
    ("ssh-config:permitrootlogin", ("T1078.003", "T1021.004")),
    ("ssh-config:root", ("T1078.003", "T1021.004")),
    ("ssh-config:permituserenvironment", ("T1574.006",)),
    ("ssh-config:", ("T1021.004",)),
    ("macos:ssh-on", ("T1021.004",)),
    ("users-collector:uid-zero", ("T1136.001", "T1078.003")),
    ("macos:uid0", ("T1136.001", "T1078.003")),
    ("users-collector:empty-password", ("T1078.003", "T1110")),
    ("users-collector:", ("T1078.003",)),
    ("macos:root-enabled", ("T1078.003",)), ("macos:guest-enabled", ("T1078.003",)),
    ("macos:autologin", ("T1078.003",)),
    ("auth-policy:sudo", ("T1548.003",)), ("auth-policy:nopasswd", ("T1548.003",)),
    ("auth-policy:", ("T1110",)),
    ("macos:password-policy", ("T1110",)),
    ("logging:no-bruteforce-protection", ("T1110",)),
    # difese
    ("logging:auditd", ("T1685.004",)),
    ("logging:world-writable-logs", ("T1685.006",)),
    ("macos:gatekeeper-off", ("T1553.001",)),
    # esposizione e vulnerabilità
    ("services:exposed", ("T1190",)), ("services:dangerous", ("T1190",)),
    ("nmap-external:", ("T1190",)),
    ("debsecan:package", ("T1190", "T1068")), ("trivy:", ("T1190", "T1068")),
    ("packages:", ("T1190", "T1068")), ("macos:updates-pending", ("T1190", "T1068")),
    # escalation e persistenza
    ("filesystem:suid", ("T1548.001",)), ("filesystem:sgid", ("T1548.001",)),
    ("persistence:cron", ("T1053.003",)), ("persistence:crontab", ("T1053.003",)),
    ("persistence:systemd", ("T1543.002",)),
    ("persistence:ld-preload", ("T1574.006",)), ("persistence:ld.so.preload", ("T1574.006",)),
    ("persistence:authorized-keys", ("T1098.004",)), ("persistence:root-authorized-keys", ("T1098.004",)),
    ("persistence:ssh-keys", ("T1098.004",)),
    ("macos:launch", ("T1543.001", "T1543.004")),
    # applicazioni (polyscan)
    ("polyscan:secret", ("T1552.001",)),
    ("polyscan:dependency", ("T1190",)), ("polyscan:runtime", ("T1190",)), ("polyscan:code", ("T1190",)),
    # compromissione
    ("rkhunter:rootkit", ("T1014",)), ("chkrootkit:infected", ("T1014",)),
    ("debsums:", ("T1554",)), ("aide:", ("T1554",)),
]
_PROCESS_SUFFIXES = ("unverifiable", "unreadable", "unknown", "failed", "error", "sudo-required",
                     "summary", "partial", "baseline-created", "installed")


def techniques_for(f: Finding) -> tuple[str, ...]:
    """Tecniche ATT&CK che il problema rende possibili o più facili (() se nessuna)."""
    source = (f.source or "").lower()
    if f.severity.value == "INFO" or source.rsplit(":", 1)[-1].endswith(_PROCESS_SUFFIXES):
        return ()
    for prefix, ids in _RULES:
        if source.startswith(prefix):
            return ids
    return ()


# ------------------------------------------------------------------ copertura
@dataclass(frozen=True)
class Coverage:
    name: str
    scores: dict[str, float]           # tecnica -> 0..100
    comments: dict[str, str]
    platforms: tuple[str, ...] = ()    # piattaforme del layer (filtro di Navigator), minuscole

    def applies_to(self, platform: str) -> bool:
        """False se il layer è dichiaratamente per altre piattaforme (es. solo Windows)."""
        if not self.platforms or not platform:
            return True
        return platform.lower() in self.platforms

    def status(self, technique: str) -> str:
        """covered | partial | none | unknown (non presente nel layer)."""
        score = self.scores.get(technique)
        if score is None and "." in technique:            # sotto-tecnica: vale la tecnica madre
            score = self.scores.get(technique.split(".")[0])
        if score is None:
            return "unknown"
        if score >= 100:
            return "covered"
        return "partial" if score > 0 else "none"


MAX_LAYER_BYTES = 10 * 1024 * 1024
_TECH_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_layer(path: str | Path) -> Coverage:
    """Legge un layer di ATT&CK Navigator. Solleva ValueError se non lo è.

    Il punteggio (`score`) di ogni tecnica è letto come percentuale di copertura (0 nessun
    rilevamento, 100 coperta); se manca, una tecnica presente e abilitata conta come coperta.
    """
    p = Path(path)
    try:
        if p.stat().st_size > MAX_LAYER_BYTES:
            raise ValueError(f"{path}: file troppo grande per un layer di ATT&CK Navigator")
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ValueError(f"{path}: non leggibile ({e.strerror or e})") from None
    except json.JSONDecodeError:
        raise ValueError(f"{path}: non è un file JSON") from None
    if not isinstance(data, dict) or not isinstance(data.get("techniques"), list):
        raise ValueError(f"{path}: non è un layer di ATT&CK Navigator (manca 'techniques')")
    gradient = data.get("gradient") if isinstance(data.get("gradient"), dict) else {}
    try:
        lo, hi = float(gradient.get("minValue", 0)), float(gradient.get("maxValue", 100))
    except (TypeError, ValueError):
        lo, hi = 0.0, 100.0
    scores: dict[str, float] = {}
    comments: dict[str, str] = {}
    for t in data["techniques"]:
        if not isinstance(t, dict):
            continue
        tid = str(t.get("techniqueID", "")).strip().upper()
        if not _TECH_ID.match(tid) or t.get("enabled") is False:
            continue
        raw = t.get("score")
        try:
            score = 100.0 if raw is None else (float(raw) - lo) * 100.0 / ((hi - lo) or 1.0)
        except (TypeError, ValueError):
            continue
        score = max(0.0, min(100.0, score))
        scores[tid] = min(scores.get(tid, 100.0), score)    # più tattiche: vale la peggiore
        if t.get("comment"):
            comments[tid] = clean_text(str(t["comment"]))[:300]
    filters = data.get("filters") if isinstance(data.get("filters"), dict) else {}
    platforms = tuple(clean_text(str(x)).lower() for x in (filters.get("platforms") or [])
                      if isinstance(x, str))[:20]
    return Coverage(name=clean_text(str(data.get("name", p.name)))[:120], scores=scores, comments=comments,
                    platforms=platforms)


_PLATFORM = {"linux": "linux", "darwin": "macos"}


def technique_rows(findings: list[Finding], coverage: Coverage | None = None,
                   system: str = "") -> list[dict]:
    """Tecniche toccate dai problemi: quanti finding, severità peggiore, copertura.

    `system` è la piattaforma del target (linux, darwin): un layer costruito per altre
    piattaforme (per esempio solo Windows) non dice nulla sui rilevamenti di questo sistema.
    """
    platform = _PLATFORM.get(system, system)
    if coverage is not None and not coverage.applies_to(platform):
        coverage_state = "other-platform"
    else:
        coverage_state = None
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    rows: dict[str, dict] = {}
    for f in findings:
        for tid in techniques_for(f):
            name, tactic = TECHNIQUES[tid]
            r = rows.setdefault(tid, {"id": tid, "name": name, "tactic": tactic, "count": 0,
                                      "worst": "LOW", "findings": []})
            r["count"] += 1
            r["findings"].append(f.title)
            if order.index(f.severity.value) < order.index(r["worst"]):
                r["worst"] = f.severity.value
    for r in rows.values():
        r["coverage"] = coverage_state or (coverage.status(r["id"]) if coverage else "unknown")
        if coverage and r["id"] in coverage.comments:
            r["coverage_note"] = coverage.comments[r["id"]]
    cov_rank = {"none": 0, "unknown": 1, "other-platform": 1, "partial": 2, "covered": 3}
    return sorted(rows.values(), key=lambda r: (cov_rank[r["coverage"]], order.index(r["worst"]), -r["count"], r["id"]))

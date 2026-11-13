"""Export dei risultati verso Wazuh.

Ogni assessment produce righe JSON (una per finding, più una di riepilogo) che l'agente
o il manager Wazuh legge con `<log_format>json</log_format>`: il decoder JSON integrato
le scompone e le regole di `integrations/wazuh/watchdog_rules.xml` le trasformano in
allarmi con il livello adatto alla severità. Così i risultati di WatchDog compaiono
nella dashboard di Wazuh accanto agli altri eventi, con i riferimenti normativi e le
tecniche ATT&CK.

Due modi d'uso:
- `--format wazuh`: scrive `assessment.wazuh.jsonl` nella cartella del report;
- `--wazuh-log FILE`: aggiunge le righe a un file fisso che l'agente Wazuh controlla.

Ogni riga resta sotto il limite di dimensione degli eventi di Wazuh (l'evidenza viene
accorciata) ed è su una sola riga (i JSON non contengono a capo non codificati).
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from risk_assessor.models import Assessment
from risk_assessor.reports import private_dir, private_file
from risk_assessor.risk.areas import AREAS, area_of
from risk_assessor.risk.attack import techniques_for
from risk_assessor.risk.compliance import controls_for

MAX_FIELD = 1000          # caratteri per i campi lunghi (evidenza, descrizione)
MAX_LINE = 60_000         # byte: Wazuh tronca gli eventi più lunghi di circa 64 KB
_APPEND_LOCK = threading.Lock()   # più host (fleet) possono scrivere sullo stesso file


def _line(event: dict) -> str:
    text = json.dumps({"watchdog": event}, ensure_ascii=False, separators=(",", ":"))
    if len(text.encode("utf-8")) > MAX_LINE:
        event = {**event, "evidence": "", "description": event.get("description", "")[:200]}
        text = json.dumps({"watchdog": event}, ensure_ascii=False, separators=(",", ":"))
    return text


def wazuh_lines(a: Assessment) -> list[str]:
    """Le righe JSON dell'assessment: prima il riepilogo, poi un evento per finding."""
    when = (a.finished_at or a.started_at).isoformat()
    host = a.metadata.get("host") or {}
    base = {"target": a.target, "name": a.metadata.get("name") or a.target, "mode": a.mode,
            "system": a.system_label(), "assessment_time": when}
    counts = a.counts_by_severity()
    lines = [_line({**base, "event": "summary", "source": "watchdog:summary",
                    "severity": a.risk_level, "risk_score": a.risk_score,
                    "title": f"Assessment completato: rischio {a.risk_level} ({a.risk_score}/100)",
                    "counts": counts, "incomplete_checks": len(a.errors),
                    "platform": host.get("system", "")})]
    for f in a.findings:
        refs = controls_for(f)
        lines.append(_line({
            **base, "event": "finding", "title": f.title, "severity": f.severity.value,
            "confidence": f.confidence.value, "risk": f.risk, "risk_level": f.risk_level,
            "area": AREAS[area_of(f)][0], "category": f.category, "source": f.source,
            "description": f.description[:MAX_FIELD], "evidence": f.evidence[:MAX_FIELD],
            "recommendation": f.recommendation[:MAX_FIELD],
            "cis": list(refs.get("cis", ())), "iso27001": list(refs.get("iso27001", ())),
            "nist": list(refs.get("nist", ())), "mitre": list(techniques_for(f)),
        }))
    return lines


def write_wazuh_report(a: Assessment, output_dir: Path) -> Path:
    out_dir = private_dir(output_dir)
    out = out_dir / "assessment.wazuh.jsonl"
    out.write_text("\n".join(wazuh_lines(a)) + "\n", encoding="utf-8")
    return private_file(out)


def append_wazuh_log(a: Assessment, path: str | Path) -> Path:
    """Aggiunge le righe a un file controllato da Wazuh (creato con permessi 0640 se manca)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = ("\n".join(wazuh_lines(a)) + "\n").encode("utf-8")
    with _APPEND_LOCK:
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    return p

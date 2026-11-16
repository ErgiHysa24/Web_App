"""JSON report generator."""
from __future__ import annotations
import json
from pathlib import Path
from risk_assessor.models import Assessment
from risk_assessor.reports import private_dir, private_file


def generate_json_report(assessment: Assessment, output_dir: Path) -> Path:
    """Write assessment.json into output_dir and return the path."""
    output_dir = private_dir(output_dir)
    out_file = output_dir / "assessment.json"
    with out_file.open("w", encoding="utf-8") as fh:
        json.dump(assessment.to_dict(), fh, indent=2, ensure_ascii=False)
    return private_file(out_file)

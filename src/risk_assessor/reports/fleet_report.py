"""Riepilogo di un assessment su più host (fleet.html, fleet.md, fleet.json).

Contiene una tabella per host, una heatmap host × macro-aree (ogni cella porta alla
heatmap interna di quell'area nel report del singolo host) e i problemi più diffusi.
"""
from __future__ import annotations

import html
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from risk_assessor.fleet import HostResult
from risk_assessor.models import Severity
from risk_assessor.reports import private_dir, private_file
from risk_assessor.reports.html_report import _CSS, _SEV_SINGULAR, _plural
from risk_assessor.risk.areas import AREAS, area_of
from risk_assessor.risk.compare import finding_key

_SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_LEVEL_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _e(text) -> str:
    return html.escape(str(text))


def generate_fleet_reports(results: list[HostResult], base_dir: Path, formats: list[str]) -> list[Path]:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = private_dir(Path(base_dir) / f"fleet-{ts}")
    summary = fleet_summary(results, out_dir)
    written = []
    if "json" in formats:
        f = out_dir / "fleet.json"
        f.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(private_file(f))
    if "md" in formats:
        f = out_dir / "fleet.md"
        f.write_text(_markdown(summary), encoding="utf-8")
        written.append(private_file(f))
    if "html" in formats:
        f = out_dir / "fleet.html"
        f.write_text(_html(summary), encoding="utf-8")
        written.append(private_file(f))
    return written


def _rel(path: Path | None, out_dir: Path) -> str:
    if path is None:
        return ""
    try:
        return Path(os.path.relpath(path, out_dir)).as_posix()
    except ValueError:      # dischi diversi su Windows
        return Path(path).resolve().as_uri()


def fleet_summary(results: list[HostResult], out_dir: Path) -> dict:
    """Dati del riepilogo, indipendenti dal formato (sono anche il contenuto di fleet.json)."""
    hosts, common = [], Counter()
    titles: dict[tuple[str, str], tuple[str, str]] = {}
    for r in results:
        h = {"name": r.host.label, "host": r.host.host, "port": r.host.port, "ok": r.ok,
             "seconds": round(r.seconds, 1)}
        if not r.ok:
            h["error"] = r.error
            hosts.append(h)
            continue
        a = r.assessment
        html_path = next((p for p in r.reports if p.suffix == ".html"), None)
        areas: dict[str, dict] = {}
        for f in a.findings:
            if f.severity == Severity.INFO:
                continue
            cell = areas.setdefault(area_of(f), {"count": 0, "worst": "LOW"})
            cell["count"] += 1
            if _SEVS.index(f.severity.value) < _SEVS.index(cell["worst"]):
                cell["worst"] = f.severity.value
        for key in {finding_key(f.source, f.title) for f in a.findings if f.severity != Severity.INFO}:
            common[key] += 1
        for f in a.findings:
            titles.setdefault(finding_key(f.source, f.title), (f.severity.value, f.title))
        cmp = a.metadata.get("comparison") if isinstance(a.metadata.get("comparison"), dict) else None
        h.update({
            "system": a.system_label(), "level": a.risk_level, "score": a.risk_score,
            "counts": a.counts_by_severity(), "areas": areas, "errors": len(a.errors),
            "not_applicable": len(a.not_applicable()),
            "delta": cmp.get("delta") if cmp else None,
            "report": _rel(html_path, out_dir),
        })
        hosts.append(h)
    reached = [h for h in hosts if h["ok"]]
    worst = max((h["level"] for h in reached), key=lambda lv: _LEVEL_RANK.get(lv, 0), default=None)
    top = [{"title": titles[k][1], "severity": titles[k][0], "hosts": n}
           for k, n in sorted(common.items(), key=lambda kv: (-kv[1], _SEVS.index(titles[kv[0]][0]),
                                                             titles[kv[0]][1]))[:15] if n > 1]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts_total": len(hosts), "hosts_reached": len(reached),
        "worst_level": worst,
        "average_score": round(sum(h["score"] for h in reached) / len(reached)) if reached else None,
        "hosts": hosts, "common_problems": top,
    }


# --------------------------------------------------------------------------- Markdown
def _md(text) -> str:
    text = " ".join(str(text).split()).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("|", "\\|")


def _markdown(s: dict) -> str:
    lines = ["# WatchDog — riepilogo di più host", "",
             f"**Host analizzati:** {s['hosts_reached']} su {s['hosts_total']}  ",
             f"**Livello peggiore:** {s['worst_level'] or 'n/d'}  ",
             f"**Punteggio medio:** {s['average_score'] if s['average_score'] is not None else 'n/d'}/100", "",
             "## Host", "",
             "| Host | Sistema | Livello | Punteggio | Δ | " + " | ".join(_SEVS) + " | Non completati |",
             "|---|---|---|---|---|" + "---|" * len(_SEVS) + "---|"]
    for h in s["hosts"]:
        if not h["ok"]:
            lines.append(f"| {_md(h['name'])} | — | **non raggiunto** | — | — | " + " | ".join("—" for _ in _SEVS)
                         + f" | {_md(h['error'])} |")
            continue
        delta = "" if h["delta"] is None else f"{int(h['delta']):+d}"
        lines.append(f"| {_md(h['name'])} | {_md(h['system'])} | {h['level']} | {h['score']} | {delta} | "
                     + " | ".join(str(h["counts"][sv]) for sv in _SEVS) + f" | {h['errors']} |")
    lines += ["", "## Heatmap host × aree (problemi, esclusi i finding informativi)", "",
              "| Host | " + " | ".join(AREAS[a][0] for a in AREAS) + " |",
              "|---|" + "---|" * len(AREAS)]
    for h in s["hosts"]:
        if h["ok"]:
            cells = [str(h["areas"][a]["count"]) if a in h["areas"] else "·" for a in AREAS]
            lines.append(f"| {_md(h['name'])} | " + " | ".join(cells) + " |")
    if s["common_problems"]:
        lines += ["", "## Problemi presenti su più host", ""]
        lines += [f"- **{p['hosts']} host** — {p['severity']} — {_md(p['title'])}" for p in s["common_problems"]]
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------------------ HTML
def _html(s: dict) -> str:
    reached = [h for h in s["hosts"] if h["ok"]]
    failed = [h for h in s["hosts"] if not h["ok"]]
    level = s["worst_level"] or "LOW"
    rows = []
    for h in s["hosts"]:
        if not h["ok"]:
            rows.append(f'<tr><th scope="row">{_e(h["name"])}</th><td colspan="{len(_SEVS) + 4}">'
                        f'<span class="pill sev-HIGH">non raggiunto</span> <span class="muted">{_e(h["error"])}</span></td></tr>')
            continue
        name = (f'<a href="{_e(h["report"])}">{_e(h["name"])}</a>' if h["report"] else _e(h["name"]))
        delta = "" if h["delta"] is None else (
            f' <span class="delta {"up" if h["delta"] > 0 else "down" if h["delta"] < 0 else "eq"}">'
            f'{int(h["delta"]):+d}</span>')
        counts = "".join(f'<td class="num">{h["counts"][sv] or "·"}</td>' for sv in _SEVS)
        rows.append(f'<tr><th scope="row">{name}<br><span class="muted">{_e(h["system"])}</span></th>'
                    f'<td><span class="pill sev-{_e(h["level"])}">{_e(h["level"])}</span></td>'
                    f'<td class="num">{h["score"]}{delta}</td>{counts}'
                    f'<td class="num">{h["errors"] or "·"}</td></tr>')
    top_count = max([c["count"] for h in reached for c in h["areas"].values()] + [1])
    heat_rows = []
    for h in reached:
        cells = []
        for area in AREAS:
            c = h["areas"].get(area)
            if not c:
                cells.append('<td class="hm zero">·</td>')
                continue
            share = 25 + 65 * c["count"] / top_count
            hot = " hot" if share >= 60 else ""
            link = f'{_e(h["report"])}#area-{area}' if h["report"] else ""
            inner = f'<a href="{link}">{c["count"]}</a>' if link else str(c["count"])
            cells.append(f'<td class="hm sev-{c["worst"]}{hot}" style="--hm:{share:.0f}%" '
                         f'title="{_e(AREAS[area][0])}: {c["count"]} problemi, il più grave {_SEV_SINGULAR[c["worst"]].lower()}">'
                         f'{inner}</td>')
        heat_rows.append(f'<tr><th scope="row">{_e(h["name"])}</th>{"".join(cells)}</tr>')
    heat_head = "".join(f'<th scope="col">{_e(AREAS[a][0])}</th>' for a in AREAS)
    common = "".join(
        f'<li><span class="pill sev-{_e(p["severity"])}">{_SEV_SINGULAR.get(p["severity"], "")}</span> '
        f'<strong>{p["hosts"]} host</strong> · {_e(p["title"])}</li>' for p in s["common_problems"])
    failed_note = ""
    if failed:
        failed_note = ('<div class="notice warn"><strong>Host non raggiunti</strong><p>Per questi host non c\'è '
                       'nessun risultato: non vanno letti come sicuri.</p><ul>'
                       + "".join(f"<li><strong>{_e(h['name'])}</strong>: {_e(h['error'])}</li>" for h in failed)
                       + "</ul></div>")
    head = "".join(f'<th scope="col"><span class="pill sev-{sv}">{_SEV_SINGULAR[sv]}</span></th>' for sv in _SEVS)
    body = f"""
<section class="hero lvl-{_e(level)}" aria-labelledby="sum-title">
  <div class="hero-body">
    <h2 id="sum-title">Riepilogo</h2>
    <p class="hero-level">Livello peggiore <span class="lvl-badge">{_e(s["worst_level"] or "n/d")}</span></p>
    <p class="hero-text">{_plural(s["hosts_reached"], "host analizzato", "host analizzati")} su {s["hosts_total"]}
    · punteggio medio {s["average_score"] if s["average_score"] is not None else "n/d"}/100.</p>
    <p class="hero-note">Ogni host ha il suo report completo: clicca il nome per aprirlo.</p>
  </div>
</section>
{failed_note}
<section aria-labelledby="hosts-title">
  <h2 id="hosts-title">Host</h2>
  <div class="rscroll"><table class="rtop">
    <thead><tr><th scope="col">Host</th><th scope="col">Livello</th><th scope="col">Punteggio</th>{head}<th scope="col">Non completati</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
</section>
<section aria-labelledby="heat-title">
  <h2 id="heat-title">Heatmap host × aree</h2>
  <p class="lead">Numero di problemi (esclusi i finding informativi) per host e macro-area; il colore è quello del
  problema più grave della cella. Clicca un numero per aprire la heatmap interna di quell'area nel report dell'host.</p>
  <div class="rscroll"><table class="heat">
    <thead><tr><th scope="col">Host</th>{heat_head}</tr></thead>
    <tbody>{"".join(heat_rows) or '<tr><td>Nessun host raggiunto.</td></tr>'}</tbody>
  </table></div>
</section>
{f'<section aria-labelledby="common-title"><h2 id="common-title">Problemi presenti su più host</h2><ul class="cats common">{common}</ul></section>' if common else ''}
"""
    return f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>WatchDog — riepilogo di {s["hosts_total"]} host</title>
<style>{_CSS}
.num {{ text-align: center; }} .heat a {{ color: inherit; text-decoration: none; display: block; }}
.heat a:hover {{ text-decoration: underline; }} .common li {{ display: block; }}
.heat thead th {{ white-space: normal; min-width: 90px; }}
</style>
</head>
<body>
<header class="top"><div class="wrap">
  <p class="brand">WatchDog · Risk Assessor per Linux e macOS</p>
  <h1>Riepilogo di più host</h1>
  <dl class="meta"><div><dt>Host</dt><dd>{s["hosts_total"]}</dd></div>
  <div><dt>Data</dt><dd>{_e(datetime.fromisoformat(s["generated_at"]).strftime("%d/%m/%Y %H:%M UTC"))}</dd></div></dl>
</div></header>
<main class="wrap">{body}</main>
<footer class="wrap"><p><strong>Documento riservato.</strong> Contiene dettagli sensibili sui sistemi analizzati.</p>
<p class="muted">Generato da WatchDog.</p></footer>
</body>
</html>
"""

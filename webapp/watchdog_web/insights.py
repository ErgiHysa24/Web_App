"""Pagine con i grafici: analisi d'insieme e mappa della rete."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from watchdog_web import charts
from watchdog_web import services as svc
from watchdog_web.models import User
from watchdog_web.views import _filtered_targets, fmt_dt, get_db, render, require

router = APIRouter(include_in_schema=False)
NO_TAG = "Senza tag"


def _scope(s: Session, user: User, tag: str, mine: int):
    tag = tag.strip().lower()
    targets, tags = _filtered_targets(s, user, tag, bool(mine))
    latest = svc.latest_done(s, [t.id for t in targets])
    return tag, targets, tags, latest


@router.get("/insights")
def insights(request: Request, tag: str = "", mine: int = 0, user: User = Depends(require("view")),
             s: Session = Depends(get_db)):
    tag, targets, tags, latest = _scope(s, user, tag, mine)
    history = svc.score_history(s, [t.id for t in targets])
    breakdowns = svc.area_breakdowns(s, [x.id for x in latest.values()])
    totals = {sev: 0 for sev in svc.SEVERITIES}
    by_area: dict[str, dict[str, int]] = {}
    for scan in latest.values():
        for sev, n in (scan.counts or {}).items():
            if sev in totals:
                totals[sev] += int(n)
        for area, sevs in breakdowns.get(scan.id, {}).items():
            for sev, n in sevs.items():
                by_area.setdefault(area, {}).setdefault(sev, 0)
                by_area[area][sev] += n

    analysed = [t for t in targets if t.id in latest]
    machine_rows = []
    for t in sorted(analysed, key=lambda t: (-(latest[t.id].risk_score or 0), t.name.lower())):
        scan, hist = latest[t.id], history.get(t.id, [])
        delta = hist[-1]["score"] - hist[-2]["score"] if len(hist) >= 2 else None
        machine_rows.append({
            "label": t.name, "value": scan.risk_score or 0, "href": f"/targets/{t.id}",
            "sub": f"{svc.SEVERITY_LABEL.get(scan.risk_level, scan.risk_level)}"
                   + (f", {'+' if delta > 0 else ''}{delta} dall'ultima" if delta else ""),
            "tip": [f"{scan.counts.get('CRITICAL', 0)} critici, {scan.counts.get('HIGH', 0)} alti",
                    f"{scan.incomplete} controlli non completati" if scan.incomplete else ""],
            "delta": delta, "scan": scan, "target": t})

    tag_rows = []
    for name in tags:
        members = [t for t in analysed if name in (t.tags or [])]
        if not members:
            continue
        scores = [latest[t.id].risk_score or 0 for t in members]
        avg = round(sum(scores) / len(scores), 1)
        worst = max(members, key=lambda t: latest[t.id].risk_score or 0)
        tag_rows.append({"label": name, "value": avg, "href": f"/insights?tag={name}",
                         "sub": f"{len(members)} {'macchina' if len(members) == 1 else 'macchine'}, peggiore {worst.name}",
                         "tip": ["media del rischio", f"peggiore: {worst.name} ({latest[worst.id].risk_score})"],
                         "count": len(members), "worst": worst})
    tag_rows.sort(key=lambda r: (-r["value"], r["label"]))

    trends = [{"target": t, "history": history.get(t.id, []), "chart": charts.sparkline(history.get(t.id, []),
                                                                                       width=220, height=56)}
              for t in sorted(analysed, key=lambda t: t.name.lower())]
    avg_score = round(sum(latest[t.id].risk_score or 0 for t in analysed) / len(analysed)) if analysed else None
    return render(request, "insights.html", user, tag=tag, tags=tags, mine=bool(mine), targets=targets,
                  analysed=analysed, totals=totals, avg_score=avg_score, by_area=by_area,
                  severity_chart=charts.severity_bar(totals, width=480),
                  area_chart=charts.area_severity_chart(by_area, width=480) if by_area else None,
                  machine_chart=charts.ranked_bars(machine_rows), machine_rows=machine_rows,
                  tag_chart=charts.ranked_bars(tag_rows) if len(tag_rows) >= 2 else None, tag_rows=tag_rows,
                  trends=trends)


@router.get("/map")
def network_map(request: Request, tag: str = "", mine: int = 0, user: User = Depends(require("view")),
                s: Session = Depends(get_db)):
    tag, targets, tags, latest = _scope(s, user, tag, mine)
    nodes = []
    for t in targets:
        scan = latest.get(t.id)
        nodes.append({"target": t, "scan": scan, "ports": svc.open_ports(s, scan) if scan else None})
    # Raggruppate per il primo tag (o per il tag scelto); senza tag in fondo.
    groups: dict[str, list[dict]] = {}
    for node in nodes:
        node_tags = node["target"].tags or []
        key = tag if tag else (node_tags[0] if node_tags else NO_TAG)
        groups.setdefault(key, []).append(node)
    ordered = sorted(groups.items(), key=lambda kv: (kv[0] == NO_TAG, kv[0]))
    for _, members in ordered:
        members.sort(key=lambda n: (n["scan"] is None, -(n["scan"].risk_score or 0) if n["scan"] else 0,
                                    n["target"].name.lower()))
    exposed = sum(1 for n in nodes if n["ports"] for p in n["ports"]["ports"] if p["external"])
    risky = sum(1 for n in nodes if n["ports"] for p in n["ports"]["ports"] if p["severity"])
    no_nmap = [n["target"] for n in nodes if n["scan"] and not (n["ports"] and
                                                                  (n["ports"]["ran_internal"] or n["ports"]["ran_external"]))]
    return render(request, "map.html", user, tag=tag, tags=tags, mine=bool(mine), nodes=nodes,
                  chart=charts.network_map(ordered, fmt_dt) if nodes else None, exposed=exposed, risky=risky,
                  no_nmap=no_nmap)

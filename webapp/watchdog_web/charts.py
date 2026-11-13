"""Grafici e schemi in SVG, generati dal server.

Niente librerie JavaScript né risorse esterne: l'SVG va direttamente nella pagina e
rispetta la Content-Security-Policy (colori e caratteri vengono dal CSS tramite classi).
Ogni elemento con dati ha un attributo data-tip (righe separate da "|", la prima è il
valore) che app.js mostra come tooltip al passaggio del mouse e al focus da tastiera;
gli stessi valori sono sempre anche in una tabella nella pagina.

Tutto il testo che arriva dai sistemi analizzati o dagli utenti (nomi, servizi, tag)
passa da esc(): nell'SVG non entra mai markup non controllato.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from markupsafe import Markup

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEV_LABEL = {"CRITICAL": "critico", "HIGH": "alto", "MEDIUM": "medio", "LOW": "basso", "INFO": "informazione"}


def esc(value) -> str:
    return html.escape(str(value), quote=True)


def _text_width(text: str, size: float, mono: bool = False) -> float:
    """Larghezza stimata del testo (Atkinson Hyperlegible ~0,56 em, monospazio 0,6 em)."""
    return len(text) * size * (0.6 if mono else 0.56)


def _clip(text: str, max_width: float, size: float, mono: bool = False) -> str:
    text = str(text)
    if _text_width(text, size, mono) <= max_width:
        return text
    keep = max(1, int(max_width / (size * (0.6 if mono else 0.56))) - 1)
    return text[:keep] + "…"


def _tip(*lines) -> str:
    return esc("|".join(str(x).replace("|", "/") for x in lines if x not in (None, "")))


def _bar_path(x: float, y: float, w: float, h: float, r: float = 4) -> str:
    """Barra orizzontale: squadrata sulla linea di base (a sinistra), arrotondata alla fine."""
    r = max(0.0, min(r, w, h / 2))
    return (f"M{x:.1f},{y:.1f}H{x + w - r:.1f}Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f}"
            f"V{y + h - r:.1f}Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f}H{x:.1f}Z")


def _svg(width: int, height: int, body: list[str], label: str, cls: str = "") -> Markup:
    # Unico punto in cui l'SVG diventa markup: ogni testo variabile nel body è già passato
    # da esc() (o è un numero calcolato qui). I test controllano l'escaping con nomi ostili.
    return Markup(f'<svg class="chart {cls}" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '  # nosec B704
                  f'role="img" aria-label="{esc(label)}" preserveAspectRatio="xMinYMin meet">'
                  f'<title>{esc(label)}</title>{"".join(body)}</svg>')


def _when(value: datetime | None, fmt) -> str:
    return fmt(value, True) if value else ""


# --------------------------------------------------------------------------- andamento

def sparkline(history: list[dict], width: int = 112, height: int = 30) -> Markup:
    """Rischio delle ultime scansioni di una macchina, in piccolo (righe della heatmap)."""
    if not history:
        return Markup("")
    pad = 4
    n = len(history)
    xs = [pad + (width - 2 * pad) * (i / (n - 1) if n > 1 else 1) for i in range(n)]
    ys = [pad + (height - 2 * pad) * (1 - h["score"] / 100) for h in history]
    body = [f'<line class="c-grid" x1="{pad}" x2="{width - pad}" y1="{height - pad}" y2="{height - pad}"/>']
    if n > 1:
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
        body.append(f'<polyline class="c-line" points="{pts}"/>')
    body.append(f'<circle class="c-dot" cx="{xs[-1]:.1f}" cy="{ys[-1]:.1f}" r="3.5"/>')
    scores = ", ".join(str(h["score"]) for h in history)
    return _svg(width, height, body, f"Rischio nelle ultime {n} scansioni: {scores}", "spark")


def trend_chart(history: list[dict], fmt, width: int = 760, height: int = 260) -> Markup:
    """Rischio di una macchina scansione dopo scansione, su una scala del tempo."""
    left, right, top, bottom = 40, 48, 14, 34
    pw, ph = width - left - right, height - top - bottom
    times = [(h["at"] or datetime.now(timezone.utc)).timestamp() for h in history]
    t0, t1 = min(times), max(times)
    span = (t1 - t0) or 1.0

    def x_of(t: float) -> float:
        return left + (pw * (t - t0) / span if t1 > t0 else pw / 2)

    def y_of(v: float) -> float:
        return top + ph * (1 - v / 100)

    body = []
    for v in (0, 25, 50, 75, 100):
        y = y_of(v)
        body.append(f'<line class="c-grid" x1="{left}" x2="{left + pw}" y1="{y:.1f}" y2="{y:.1f}"/>')
        body.append(f'<text class="c-axis" x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{v}</text>')
    # etichette della data: sempre la prima e l'ultima, in mezzo solo se c'è spazio (90 px)
    xs = [x_of(tm) for tm in times]
    picked = [0] + ([len(xs) - 1] if len(xs) > 1 and xs[-1] - xs[0] >= 90 else [])
    for i in range(1, len(xs) - 1):
        if all(abs(xs[i] - xs[j]) >= 90 for j in picked):
            picked.append(i)
    for i in sorted(picked):
        anchor = "start" if i == 0 else "end" if i == len(xs) - 1 else "middle"
        body.append(f'<text class="c-axis" x="{xs[i]:.1f}" y="{top + ph + 22}" text-anchor="{anchor}">'
                    f'{esc(_when(history[i]["at"], fmt))}</text>')
    pts = [(x_of(t), y_of(h["score"])) for t, h in zip(times, history)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pts[0][0]:.1f},{y_of(0):.1f} {line} {pts[-1][0]:.1f},{y_of(0):.1f}"
    body.append(f'<polygon class="c-area" points="{area}"/>')
    body.append(f'<polyline class="c-line" points="{line}"/>')
    for (x, y), h in zip(pts, history):
        hollow = " hollow" if h["incomplete"] else ""
        tip = _tip(f"{h['score']}/100", f"Scansione #{h['scan_id']}, {_when(h['at'], fmt)}",
                   f"{h['incomplete']} controlli non completati" if h["incomplete"] else "")
        body.append(f'<a href="/scans/{h["scan_id"]}" data-tip="{tip}" aria-label="{tip}">'
                    f'<circle class="c-hit" cx="{x:.1f}" cy="{y:.1f}" r="12"/>'
                    f'<circle class="c-dot{hollow}" cx="{x:.1f}" cy="{y:.1f}" r="4.5"/></a>')
    lx, ly = pts[-1]
    body.append(f'<text class="c-value" x="{lx + 10:.1f}" y="{ly + 5:.1f}">{history[-1]["score"]}</text>')
    label = "Andamento del rischio: " + ", ".join(f"{h['score']}" for h in history)
    return _svg(width, height, body, label, "trend")


# --------------------------------------------------------------------------- distribuzione

def area_severity_chart(breakdown: dict[str, dict[str, int]], scan_id: int | None = None,
                        width: int = 760) -> Markup:
    """Barre orizzontali, una per area: i problemi divisi per gravità, dal più grave."""
    from watchdog_web.services import AREA_SHORT, HEATMAP_AREAS
    label_w, value_w, row_h, bar_h, top = 118, 44, 34, 18, 4
    plot_w = width - label_w - value_w
    totals = {k: sum(breakdown.get(k, {}).get(s, 0) for s in SEV_ORDER) for k, _, _ in HEATMAP_AREAS}
    biggest = max(totals.values() or [0]) or 1
    body = []
    height = top + row_h * len(HEATMAP_AREAS)
    for i, (key, name, _desc) in enumerate(HEATMAP_AREAS):
        y = top + i * row_h
        cy = y + row_h / 2
        label = f'<text class="c-label" x="0" y="{cy + 5:.1f}">{esc(AREA_SHORT[key])}</text>'
        body.append(f'<a href="/scans/{scan_id}?area={key}#risultati" class="c-arealink">{label}</a>' if scan_id
                    else label)
        total = totals[key]
        x = float(label_w)
        segs = [(s, breakdown.get(key, {}).get(s, 0)) for s in SEV_ORDER if breakdown.get(key, {}).get(s, 0)]
        for j, (sev, n) in enumerate(segs):
            w = plot_w * n / biggest
            last = j == len(segs) - 1
            draw_w = max(1.0, w - (0 if last else 2))          # 2 px di stacco tra i pezzi
            shape = (_bar_path(x, cy - bar_h / 2, draw_w, bar_h) if last else
                     f'M{x:.1f},{cy - bar_h / 2:.1f}h{draw_w:.1f}v{bar_h}h-{draw_w:.1f}Z')
            href = f"/scans/{scan_id}?area={key}&amp;severity={sev}#risultati" if scan_id else None
            tip = _tip(f"{n} {'problema' if n == 1 else 'problemi'}", f"{AREA_SHORT[key]}, gravità {SEV_LABEL[sev]}")
            mark = f'<path class="sv-{sev}" d="{shape}"/>'
            body.append(f'<a href="{href}" data-tip="{tip}" aria-label="{tip}">{mark}</a>' if href else
                        f'<g tabindex="0" data-tip="{tip}" aria-label="{tip}">{mark}</g>')
            x += w
        body.append(f'<text class="c-value" x="{(x + 8) if total else label_w:.1f}" y="{cy + 5:.1f}">{total}</text>')
    return _svg(width, height, body, "Problemi per area e gravità", "bars")


def severity_bar(totals: dict[str, int], width: int = 760) -> Markup:
    """Barra unica divisa per gravità: quanta parte dei problemi è critica, alta, media, bassa."""
    h = 28
    total = sum(totals.get(s, 0) for s in SEV_ORDER)
    if not total:
        return Markup("")
    body, x = [], 0.0
    parts = [(s, totals.get(s, 0)) for s in SEV_ORDER if totals.get(s, 0)]
    for j, (sev, n) in enumerate(parts):
        w = width * n / total
        draw_w = max(1.0, w - (0 if j == len(parts) - 1 else 2))
        share = round(100 * n / total)
        tip = _tip(f"{n} ({share}%)", f"Gravità {SEV_LABEL[sev]}")
        body.append(f'<g tabindex="0" data-tip="{tip}" aria-label="{tip}">'
                    f'<rect class="sv-{sev}" x="{x:.1f}" y="0" width="{draw_w:.1f}" height="{h}" rx="4"/>')
        text = str(n)
        if _text_width(text, 14) + 16 <= draw_w:
            body.append(f'<text class="c-in on-{sev}" x="{x + 8:.1f}" y="19">{text}</text>')
        body.append("</g>")
        x += w
    return _svg(width, h, body, "Problemi per gravità: " + ", ".join(f"{SEV_LABEL[s]} {n}" for s, n in parts),
                "segmented")


# --------------------------------------------------------------------------- confronto

def ranked_bars(rows: list[dict], width: int = 760, max_value: float = 100, unit: str = "/100") -> Markup:
    """Barre orizzontali ordinate, un solo colore: chi è messo peggio è in alto.

    rows: label, sub (testo piccolo sotto), value, href, tip (righe aggiuntive)."""
    if not rows:
        return Markup("")
    label_w, value_w, row_h, bar_h, top = 210, 64, 40, 16, 6
    plot_w = width - label_w - value_w
    height = top + row_h * len(rows) + 18
    body = []
    for v in (0, 25, 50, 75, 100):
        x = label_w + plot_w * v / 100
        body.append(f'<line class="c-grid" x1="{x:.1f}" x2="{x:.1f}" y1="{top}" y2="{height - 18}"/>')
        body.append(f'<text class="c-axis" x="{x:.1f}" y="{height - 4}" text-anchor="middle">'
                    f'{int(max_value * v / 100)}</text>')
    for i, r in enumerate(rows):
        y = top + i * row_h
        cy = y + row_h / 2
        name = _clip(r["label"], label_w - 12, 14)
        body.append(f'<text class="c-label strong" x="0" y="{cy - 2:.1f}">{esc(name)}</text>')
        if r.get("sub"):
            body.append(f'<text class="c-axis" x="0" y="{cy + 13:.1f}">{esc(_clip(r["sub"], label_w - 12, 12))}</text>')
        w = max(2.0, plot_w * min(r["value"], max_value) / max_value)
        tip = _tip(f"{r['value']:g}{unit}", r["label"], *r.get("tip", []))
        mark = f'<path class="c-barfill" d="{_bar_path(label_w, cy - bar_h / 2, w, bar_h)}"/>'
        hit = f'<rect class="c-hit" x="0" y="{y:.1f}" width="{width}" height="{row_h}"/>'
        inner = hit + mark
        body.append(f'<a href="{esc(r["href"])}" data-tip="{tip}" aria-label="{tip}">{inner}</a>' if r.get("href")
                    else f'<g tabindex="0" data-tip="{tip}" aria-label="{tip}">{inner}</g>')
        body.append(f'<text class="c-value" x="{label_w + w + 8:.1f}" y="{cy + 5:.1f}">{r["value"]:g}</text>')
    return _svg(width, height, body, "Confronto: " + ", ".join(f"{r['label']} {r['value']:g}" for r in rows),
                "ranked")


# --------------------------------------------------------------------------- mappa della rete

CARD_W, CARD_GAP, PER_ROW = 230, 18, 4


def _port_chips(ports: list[dict], width: float) -> tuple[list[tuple[float, float, dict, str, float]], float]:
    """Disposizione delle porte su più righe dentro la scheda: (x, y, porta, testo, larghezza)."""
    chips, x, y, h, gap = [], 0.0, 0.0, 22, 6
    for p in ports:
        text = f"{p['port']} {p['service']}".strip() if p["service"] else f"{p['port']}/{p['proto']}"
        text = _clip(text, width - 16, 12, mono=True)
        w = _text_width(text, 12, mono=True) + 16
        if x and x + w > width:
            x, y = 0.0, y + h + gap
        chips.append((x, y, p, text, w))
        x += w + gap
    return chips, (y + h if chips else 0)


def network_map(groups: list[tuple[str, list[dict]]], fmt) -> Markup:
    """Schema: il computer di WatchDog in alto, sotto le macchine raggruppate per tag, ognuna
    con le porte aperte trovate da Nmap (colore = gravità del servizio, bordo = raggiungibile
    dall'esterno)."""
    width = PER_ROW * CARD_W + (PER_ROW - 1) * CARD_GAP + 40
    hub_w, hub_h = 230, 54
    hub_x = (width - hub_w) / 2
    y = 20
    body = [f'<g class="hub"><rect class="c-hub" x="{hub_x:.1f}" y="{y}" width="{hub_w}" height="{hub_h}" rx="8"/>'
            f'<text class="c-hubtext strong" x="{width / 2:.1f}" y="{y + 24}" text-anchor="middle">WatchDog</text>'
            f'<text class="c-hubtext" x="{width / 2:.1f}" y="{y + 42}" text-anchor="middle">si collega via SSH</text></g>']
    trunk_top = y + hub_h
    y += hub_h + 34
    group_tops = []
    cards_svg = []
    for name, nodes in groups:
        group_tops.append(y)
        body.append(f'<text class="c-group" x="20" y="{y + 4}">{esc(_clip(name, width - 40, 15))}</text>')
        body.append(f'<text class="c-axis" x="{width - 20}" y="{y + 4}" text-anchor="end">'
                    f'{len(nodes)} {"macchina" if len(nodes) == 1 else "macchine"}</text>')
        bus_y = y + 16
        row_top = bus_y + 18
        xs_in_group = []
        for start in range(0, len(nodes), PER_ROW):
            row = nodes[start:start + PER_ROW]
            heights = []
            for k, node in enumerate(row):
                cx = 20 + k * (CARD_W + CARD_GAP)
                svg, h = _card(node, cx, row_top, fmt)
                cards_svg.append(svg)
                heights.append(h)
                if start == 0:
                    xs_in_group.append(cx + CARD_W / 2)
                    body.append(f'<line class="c-link" x1="{cx + CARD_W / 2:.1f}" x2="{cx + CARD_W / 2:.1f}" '
                                f'y1="{bus_y}" y2="{row_top}"/>')
            row_top += max(heights) + CARD_GAP
        if xs_in_group:
            body.append(f'<line class="c-link" x1="{min(xs_in_group[0], width / 2):.1f}" '
                        f'x2="{max(xs_in_group[-1], width / 2):.1f}" y1="{bus_y}" y2="{bus_y}"/>')
        y = row_top + 22
    if group_tops:
        body.insert(1, f'<line class="c-link" x1="{width / 2:.1f}" x2="{width / 2:.1f}" y1="{trunk_top}" '
                       f'y2="{group_tops[-1] + 16}"/>')
    body.extend(cards_svg)
    count = sum(len(n) for _, n in groups)
    return _svg(width, int(y), body, f"Mappa della rete: {count} macchine", "netmap")


def _card(node: dict, x: float, y: float, fmt) -> tuple[str, float]:
    t, scan, info = node["target"], node["scan"], node["ports"]
    inner_w = CARD_W - 28
    level = scan.risk_level if scan else "NONE"
    parts = [f'<rect class="c-card" x="{x:.1f}" y="{y:.1f}" width="{CARD_W}" height="__H__" rx="6"/>',
             f'<rect class="lv-fill-{esc(level)}" x="{x:.1f}" y="{y:.1f}" width="5" height="__H__" rx="2"/>']
    ty = y + 22
    parts.append(f'<a href="/targets/{t.id}"><text class="c-label strong c-link-text" x="{x + 16:.1f}" y="{ty:.1f}">'
                 f'{esc(_clip(t.name, inner_w - 56, 14))}</text></a>')
    if scan:
        parts.append(f'<text class="c-value" x="{x + CARD_W - 12:.1f}" y="{ty:.1f}" text-anchor="end">'
                     f'{scan.risk_score}</text>')
    parts.append(f'<text class="c-mono" x="{x + 16:.1f}" y="{ty + 17:.1f}">{esc(_clip(t.host, inner_w, 12, True))}</text>')
    cy = ty + 30
    if not scan:
        parts.append(f'<text class="c-axis" x="{x + 16:.1f}" y="{cy + 12:.1f}">Mai analizzata</text>')
        h = cy + 26 - y
    elif info is None or not (info["ran_internal"] or info["ran_external"]):
        parts.append(f'<text class="c-axis" x="{x + 16:.1f}" y="{cy + 12:.1f}">Nmap non eseguito</text>')
        h = cy + 26 - y
    elif not info["ports"]:
        parts.append(f'<text class="c-axis" x="{x + 16:.1f}" y="{cy + 12:.1f}">Nessuna porta aperta trovata</text>')
        h = cy + 26 - y
    else:
        chips, ch = _port_chips(info["ports"], inner_w)
        for px, py, p, text, w in chips:
            sev = p["severity"] or "NONE"
            ext = " ext" if p["external"] else ""
            where = ("visibile dall'esterno e dall'interno" if p["external"] and p["internal"] else
                     "visibile dall'esterno" if p["external"] else "vista dalla macchina stessa")
            tip = _tip(f"{p['port']}/{p['proto']} {p['service']}".strip(), p["risk"] or "Nessun problema noto",
                       where)
            parts.append(f'<g tabindex="0" data-tip="{tip}" aria-label="{tip}">'
                         f'<rect class="chip sv-{sev}{ext}" x="{x + 16 + px:.1f}" y="{cy + py:.1f}" '
                         f'width="{w:.1f}" height="22" rx="4"/>'
                         f'<text class="c-chip on-{sev}" x="{x + 24 + px:.1f}" y="{cy + py + 15:.1f}">{esc(text)}</text></g>')
        h = cy + ch + 14 - y
    svg = "".join(parts).replace("__H__", f"{h:.1f}")
    return f'<g class="card">{svg}</g>', h

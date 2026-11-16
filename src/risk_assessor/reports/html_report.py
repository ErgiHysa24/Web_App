"""HTML report generator.

Pagina autonoma (nessuna risorsa esterna, nessuna dipendenza): CSS e JavaScript
sono inline, quindi il file si apre offline e si può inviare così com'è.

Il JavaScript è solo un miglioramento (filtri, ricerca, "espandi tutto"): senza
JS la pagina resta completa e leggibile, i dettagli sono <details> nativi.
Ogni testo proveniente dal target passa da `html.escape`.
"""
from __future__ import annotations

import html
from collections import Counter
from pathlib import Path

from risk_assessor.models import Assessment, Finding, Severity
from risk_assessor.reports import private_dir, private_file
from risk_assessor.risk.compare import Comparison, compare, find_previous, finding_key  # noqa: F401
from risk_assessor.risk.attack import techniques_for
from risk_assessor.risk.compliance import FRAMEWORKS, coverage, short_refs
from risk_assessor.risk.areas import AREAS, control_of, group_by_area
from risk_assessor.risk.matrix import (
    IMPACT_LABEL, PROBABILITY_LABEL, counts_by_level, grid, risk_level, sort_by_risk,
)

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEV_LABEL = {
    "CRITICAL": "Critici", "HIGH": "Alti", "MEDIUM": "Medi", "LOW": "Bassi", "INFO": "Informativi",
}
_SEV_SINGULAR = {
    "CRITICAL": "Critico", "HIGH": "Alto", "MEDIUM": "Medio", "LOW": "Basso", "INFO": "Info",
}
_SEV_MEANING = {
    "CRITICAL": "Problemi gravi: intervenire subito.",
    "HIGH": "Problemi importanti: risolvere a breve.",
    "MEDIUM": "Debolezze da pianificare.",
    "LOW": "Miglioramenti consigliati, impatto limitato.",
    "INFO": "Informazioni utili: non sono problemi.",
}
_LEVEL_TEXT = {
    "CRITICAL": "Sono presenti problemi critici. Il sistema richiede un intervento immediato.",
    "HIGH": "Sono presenti problemi importanti da risolvere a breve.",
    "MEDIUM": "Nessun problema grave, ma ci sono debolezze da pianificare.",
    "LOW": "Nessun problema rilevante emerso da questa analisi.",
}
_CONF_TEXT = {
    "HIGH": "Rilevato con certezza.",
    "MEDIUM": "Probabile: conviene confermarlo.",
    "LOW": "Indicativo: il controllo era incompleto o non conclusivo, verificare a mano.",
}
_CONF_LABEL = {"HIGH": "alta", "MEDIUM": "media", "LOW": "bassa"}

# Descrizione in parole semplici di ogni controllo, per chi legge il report.
_CHECK_INFO = {
    "linux": ("Informazioni di sistema", "Sistema operativo, kernel, architettura e hostname."),
    "users": ("Utenti e gruppi", "Account con UID 0, password vuote, utenti con shell di login, gruppi privilegiati."),
    "ssh_config": ("Configurazione SSH", "Impostazioni di sshd: login di root, password, X11, protocollo, porta."),
    "firewall": ("Firewall", "Presenza e stato di ufw, firewalld, nftables o iptables."),
    "services": ("Servizi e porte", "Servizi in errore e servizi o porte pericolosi in ascolto."),
    "filesystem": ("File system", "File SUID/SGID, file scrivibili da tutti, permessi dei file sensibili, spazio su disco."),
    "packages": ("Pacchetti", "Pacchetti installati e aggiornamenti disponibili."),
    "auth_policy": ("Password policy e sudoers", "Scadenza e robustezza password, blocco account, regole sudo senza password."),
    "kernel": ("Hardening del kernel", "Parametri sysctl di sicurezza (ASLR, redirect ICMP, ptrace, ecc.) e Secure Boot."),
    "logging": ("Log e audit", "auditd, log persistenti, protezione anti brute-force (fail2ban), permessi dei log."),
    "updates": ("Aggiornamenti automatici", "Aggiornamenti automatici, data dell'ultimo aggiornamento, riavvio richiesto."),
    "persistence": ("Persistenza e attività sospette", "Cron e servizi systemd sospetti, ld.so.preload, processi con eseguibile cancellato, chiavi SSH autorizzate."),
    "protections": ("Protezioni del sistema", "Linux: SELinux o AppArmor e cifratura del disco di sistema. "
                    "macOS: SIP, FileVault, Gatekeeper."),
    "nmap_external": ("Nmap dall'esterno", "Scansione delle porte raggiungibili dalla rete, eseguita dal PC dell'operatore."),
    "nmap": ("Nmap", "Porte aperte e servizi in ascolto sul sistema."),
    "lynis": ("Lynis", "Audit generale di sicurezza del sistema."),
    "rkhunter": ("rkhunter", "Ricerca di rootkit e file di sistema modificati."),
    "chkrootkit": ("chkrootkit", "Ricerca di rootkit noti."),
    "openscap": ("OpenSCAP", "Conformità a profili di sicurezza standard (SCAP)."),
    "clamav": ("ClamAV", "Scansione antimalware dei percorsi scelti."),
    "aide": ("AIDE", "Integrità dei file rispetto a una baseline."),
    "debsecan": ("debsecan", "Vulnerabilità note nei pacchetti Debian."),
    "polyscan": ("polyscan (importato)", "Codice, segreti, librerie e configurazione delle applicazioni, dai rapporti di polyscan."),
    "debsums": ("debsums", "File di sistema modificati o mancanti rispetto ai checksum dei pacchetti."),
    "trivy": ("Trivy", "Vulnerabilità note nei pacchetti del sistema (con correzione disponibile)."),
}


def generate_html_report(assessment: Assessment, output_dir: Path,
                         previous: dict | None = None) -> Path:
    """Scrive assessment.html. `previous` è il contenuto di un assessment.json precedente
    (vedi `risk.compare`): se presente, il report mostra il confronto."""
    output_dir = private_dir(output_dir)
    out_file = output_dir / "assessment.html"
    out_file.write_text(_render(assessment, previous), encoding="utf-8")
    return private_file(out_file)


def _e(text) -> str:
    return html.escape(str(text))


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4}
    return sorted(findings, key=lambda f: (rank.get(f.severity, 99), f.title))


def _duration(a: Assessment) -> str:
    if not a.finished_at:
        return ""
    secs = int((a.finished_at - a.started_at).total_seconds())
    if secs < 60:
        return f"{secs} s"
    return f"{secs // 60} min {secs % 60:02d} s"


def _date(a: Assessment) -> str:
    return a.started_at.strftime("%d/%m/%Y %H:%M UTC")


# ---------------------------------------------------------------- sezioni

def _hero(a: Assessment, counts: dict[str, int]) -> str:
    level = a.risk_level if a.risk_level in _LEVEL_TEXT else "LOW"
    score = max(0, min(100, int(a.risk_score)))
    circ = 2 * 3.14159265 * 52
    dash = circ * score / 100
    if not a.findings:
        text = "Nessun finding: l'analisi non ha prodotto segnalazioni."
    else:
        text = _LEVEL_TEXT[level]
    return f"""
<section class="hero lvl-{level}" aria-labelledby="sum-title">
  <div class="gauge" role="img" aria-label="Punteggio di rischio {score} su 100">
    <svg viewBox="0 0 120 120" width="150" height="150">
      <circle class="g-track" cx="60" cy="60" r="52" fill="none" stroke-width="10"/>
      <circle class="g-val" cx="60" cy="60" r="52" fill="none" stroke-width="10"
              stroke-linecap="round" stroke-dasharray="{dash:.1f} {circ:.1f}"
              transform="rotate(-90 60 60)"/>
    </svg>
    <div class="g-text"><span class="g-score">{score}</span><span class="g-max">/ 100</span></div>
  </div>
  <div class="hero-body">
    <h2 id="sum-title">Executive Summary</h2>
    <p class="hero-level">Rischio complessivo <span class="lvl-badge">{_e(level)}</span></p>
    <p class="hero-text">{_e(text)}</p>
    <p class="hero-note">Il livello corrisponde alla severità più alta tra i finding; il punteggio
    (0–100) somma i punti di ciascuna severità con dei tetti, così molti problemi lievi non
    nascondono quelli gravi.</p>
  </div>
</section>"""


def _comparison(cmp: Comparison | None) -> str:
    if cmp is None:
        return ""
    if cmp.delta is None:
        delta = ""
    else:
        diff = cmp.delta
        sign = "+" if diff > 0 else ""
        delta = (f'<p class="cmp-score">Punteggio di rischio: <strong>{cmp.previous_score}</strong> → '
                 f'<strong>{cmp.current_score}</strong> '
                 f'<span class="delta {"up" if diff > 0 else "down" if diff < 0 else "eq"}">'
                 f'{sign}{diff} ({cmp.trend})</span></p>')

    def items(rows, cls):
        if not rows:
            return '<li class="muted">Nessuno.</li>'
        out = [f'<li><span class="pill sev-{sev}">{_SEV_SINGULAR[sev]}</span> '
               f'<span class="{cls}">{_e(title)}</span></li>' for sev, title in rows[:10]]
        if len(rows) > 10:
            out.append(f'<li class="muted">… e altri {len(rows) - 10}.</li>')
        return "".join(out)
    new_rows = [(f.severity.value, f.title) for f in cmp.new]
    resolved_rows = [(sev, title) for sev, title, _ in cmp.resolved]
    unchecked = ""
    if cmp.not_rechecked:
        unchecked = (f'<div class="notice"><strong>Non ricontrollati: {len(cmp.not_rechecked)}</strong>'
                     '<p>Problemi della scansione precedente il cui controllo questa volta non è stato eseguito: '
                     'non sono contati tra i risolti.</p><ul>'
                     + items([(sev, title) for sev, title, _ in cmp.not_rechecked], "") + "</ul></div>")
    return f"""
<section aria-labelledby="cmp-title">
  <h2 id="cmp-title">Rispetto alla scansione precedente</h2>
  <p class="lead">Confronto con l'analisi di <code>{_e(cmp.previous_target)}</code> del {_e(cmp.previous_date)}. Contano solo i problemi (i finding informativi sono esclusi).</p>
  {delta}
  <div class="cmp">
    <div class="cmp-col"><h4>Nuovi <span class="g-count">{len(new_rows)}</span></h4><ul>{items(new_rows, "")}</ul></div>
    <div class="cmp-col"><h4>Risolti <span class="g-count">{len(resolved_rows)}</span></h4><ul>{items(resolved_rows, "struck")}</ul></div>
    <div class="cmp-col"><h4>Ancora presenti <span class="g-count">{cmp.unchanged}</span></h4>
      <p class="muted">Già presenti nella scansione precedente e non risolti.</p></div>
  </div>{unchecked}
</section>"""


def _distribution(a: Assessment, counts: dict[str, int]) -> str:
    total = len(a.findings)
    if total == 0:
        return ""
    segs = "".join(
        f'<span class="seg sev-{s}" style="flex:{counts[s]}" '
        f'title="{_SEV_SINGULAR[s]}: {counts[s]}"></span>'
        for s in _SEV_ORDER if counts[s]
    )
    cards = "".join(
        f'<button type="button" class="card sev-{s}" data-filter="{s}" '
        f'{"disabled" if not counts[s] else ""} aria-pressed="false">'
        f'<span class="card-n">{counts[s]}</span>'
        f'<span class="card-l">{_SEV_LABEL[s]}</span>'
        f'<span class="card-m">{_e(_SEV_MEANING[s])}</span></button>'
        for s in _SEV_ORDER
    )
    return f"""
<section aria-labelledby="dist-title">
  <h2 id="dist-title">Distribuzione dei finding</h2>
  <div class="bar" role="img" aria-label="Distribuzione per severità, {total} finding in totale">{segs}</div>
  <div class="cards">{cards}</div>
</section>"""


_RISK_LEVEL_IT = {"CRITICAL": "critico", "HIGH": "alto", "MEDIUM": "medio", "LOW": "basso", "INFO": "info"}


def _risk_matrix(a: Assessment) -> str:
    """Matrice rischio = impatto x probabilità, con i finding più rischiosi."""
    problems = [f for f in a.findings if f.severity != Severity.INFO]
    if not problems:
        return ""
    cells = grid(problems)
    head = "".join(
        f'<th scope="col">Probabilità {PROBABILITY_LABEL[p]} ({p})</th>' for p in (1, 2, 3))
    rows = []
    for imp in (4, 3, 2, 1):
        tds = []
        for p in (1, 2, 3):
            n = cells.get((imp, p), 0)
            lvl = risk_level(imp * p)
            tds.append(f'<td class="rm sev-{lvl}{" zero" if not n else ""}" '
                       f'title="Rischio {imp * p}: {_RISK_LEVEL_IT[lvl]}">'
                       f'<strong>{n}</strong><span>rischio {imp * p}</span></td>')
        rows.append(f'<tr><th scope="row">Impatto {IMPACT_LABEL[imp]} ({imp})</th>{"".join(tds)}</tr>')
    levels = counts_by_level(problems)
    chips = "".join(
        f'<li><span class="pill sev-{lvl}">{_RISK_LEVEL_IT[lvl].capitalize()}</span> {levels[lvl]}</li>'
        for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if levels[lvl])
    top = []
    for f in sort_by_risk(problems)[:10]:
        lvl = f.risk_level
        top.append(
            f'<tr><td><span class="pill sev-{lvl}">{_RISK_LEVEL_IT[lvl].capitalize()} {f.risk}</span></td>'
            f'<td>{f.impact}</td><td>{f.probability}</td><td>{_e(f.title)}</td></tr>')
    return f"""
<section aria-labelledby="risk-title">
  <h2 id="risk-title">Rischio = impatto × probabilità</h2>
  <p class="lead">L'<strong>impatto</strong> è la gravità del problema (da 1 a 4); la <strong>probabilità</strong>
  dice quanto è probabile che sia reale e sfruttabile (da 1 a 3, dalla confidenza del rilevamento).
  Il rischio è il prodotto: da 1 a 12. Il <em>livello</em> nel riepilogo invece è quello della severità
  più alta trovata, quindi può essere più alto del rischio massimo della matrice (per esempio un problema
  grave ma rilevato con confidenza media).</p>
  <div class="rscroll"><table class="rmatrix">
    <thead><tr><th></th>{head}</tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
  <ul class="rlevels">{chips}</ul>
  <h3 class="rtop-h">I finding più rischiosi</h3>
  <div class="rscroll"><table class="rtop">
    <thead><tr><th scope="col">Rischio</th><th scope="col">Impatto</th><th scope="col">Probabilità</th><th scope="col">Finding</th></tr></thead>
    <tbody>{"".join(top)}</tbody>
  </table></div>
</section>"""


def _priorities(findings: list[Finding]) -> str:
    urgent = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if not urgent:
        return ""
    items = []
    for f in urgent[:5]:
        sev = f.severity.value
        items.append(
            f'<li><span class="pill sev-{sev}">{_SEV_SINGULAR[sev]}</span> '
            f'<strong>{_e(f.title)}</strong><br>'
            f'<span class="muted">{_e(f.recommendation)}</span></li>'
        )
    more = ""
    if len(urgent) > 5:
        more = f'<p class="muted">… e altri {len(urgent) - 5} nella lista completa qui sotto.</p>'
    return f"""
<section aria-labelledby="prio-title">
  <h2 id="prio-title">Da fare per primi</h2>
  <p class="lead">I problemi critici e alti, con l'azione consigliata.</p>
  <ol class="prio">{''.join(items)}</ol>{more}
</section>"""


def _categories(findings: list[Finding]) -> str:
    problems = [f for f in findings if f.severity != Severity.INFO]
    if not problems:
        return ""
    counts = Counter(f.category for f in problems)
    top = max(counts.values())
    rows = "".join(
        f'<li data-cat="{_e(cat)}"><span class="cat-name">{_e(cat)}</span>'
        f'<span class="cat-bar"><span style="width:{100 * n / top:.0f}%"></span></span>'
        f'<span class="cat-n">{n}</span></li>'
        for cat, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return f"""
<section aria-labelledby="cat-title">
  <h2 id="cat-title">Dove sono i problemi</h2>
  <p class="lead">Numero di problemi (esclusi i finding informativi) per area.</p>
  <ul class="cats">{rows}</ul>
</section>"""



def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _heat_cell(n: int, sev: str, top: int, extra: str = "") -> str:
    """Cella della heatmap: colore della severità, più intenso con più finding."""
    if not n:
        return f'<td class="hm zero"{extra}>·</td>'
    share = 25 + 65 * n / max(top, 1)
    hot = " hot" if share >= 60 else ""
    return (f'<td class="hm sev-{sev}{hot}" style="--hm:{share:.0f}%"{extra} '
            f'title="{n} {_SEV_LABEL[sev].lower()}">{n}</td>')


def _heatmap(findings: list[Finding], index: dict[int, int]) -> str:
    """Heatmap macro-aree × severità; ogni area si apre in una heatmap interna per controllo."""
    if not findings:
        return ""
    groups = group_by_area(findings)
    problem_counts = [sum(1 for f in fs if f.severity.value == s)
                      for fs in groups.values() for s in _SEV_ORDER[:-1]]
    top = max(problem_counts + [1])
    head = "".join(f'<th scope="col"><span class="pill sev-{s}">{_SEV_SINGULAR[s]}</span></th>' for s in _SEV_ORDER)
    rows, panels = [], []
    for area, fs in groups.items():
        name, desc = AREAS[area]
        counts = Counter(f.severity.value for f in fs)
        problems = [f for f in fs if f.severity != Severity.INFO]
        worst = max((f.risk for f in problems), default=0)
        worst_cell = (f'<td class="hm-risk"><span class="pill sev-{risk_level(worst)}">{worst}</span></td>'
                      if worst else '<td class="hm-risk muted">–</td>')
        cells = "".join(_heat_cell(counts.get(s, 0), s, top if s != "INFO" else max(counts.get("INFO", 0), 1))
                        for s in _SEV_ORDER)
        rows.append(f'<tr data-area="{area}"><th scope="row"><a class="area-link" href="#area-{area}" '
                    f'data-area="{area}">{_e(name)}</a></th>{cells}'
                    f'<td class="hm-tot">{len(fs)}</td>{worst_cell}</tr>')
        panels.append(_area_panel(area, name, desc, fs, index))
    return f"""
<section aria-labelledby="heat-title">
  <h2 id="heat-title">Heatmap delle aree</h2>
  <p class="lead">Quanti finding ci sono in ogni macro-area per livello di gravità: più il colore è intenso,
  più sono numerosi. Clicca un'area per aprire la sua heatmap interna, controllo per controllo, con tutti i finding.</p>
  <div class="rscroll"><table class="heat">
    <thead><tr><th scope="col">Area</th>{head}<th scope="col">Totale</th><th scope="col">Rischio max</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
  <div class="areas">{"".join(panels)}</div>
</section>"""


def _area_panel(area: str, name: str, desc: str, fs: list[Finding], index: dict[int, int]) -> str:
    by_control: dict[str, list[Finding]] = {}
    for f in fs:
        by_control.setdefault(control_of(f), []).append(f)
    top = max([sum(1 for f in cf if f.severity.value == s)
               for cf in by_control.values() for s in _SEV_ORDER[:-1]] + [1])
    order = sorted(by_control.items(),
                   key=lambda kv: (min(_SEV_ORDER.index(f.severity.value) for f in kv[1]), kv[0].lower()))
    rows = []
    for control, cf in order:
        counts = Counter(f.severity.value for f in cf)
        cells = "".join(_heat_cell(counts.get(s, 0), s, top if s != "INFO" else max(counts.get("INFO", 0), 1))
                        for s in _SEV_ORDER)
        rows.append(f'<tr><th scope="row">{_e(control)}</th>{cells}<td class="hm-tot">{len(cf)}</td></tr>')
    tiles = []
    for f in _sorted_findings(fs):
        sev = f.severity.value
        tiles.append(
            f'<a class="tile sev-{sev}" href="#f-{index[id(f)]}" title="{_e(f.title)}">'
            f'<span class="tile-h"><span class="pill sev-{sev}">{_SEV_SINGULAR[sev]}</span>'
            f'<span class="tile-r">rischio {f.risk}</span></span>'
            f'<span class="tile-t">{_e(f.title)}</span>'
            f'<span class="tile-c">{_e(control_of(f))}</span></a>')
    problems = sum(1 for f in fs if f.severity != Severity.INFO)
    head = "".join(f'<th scope="col">{_SEV_SINGULAR[s]}</th>' for s in _SEV_ORDER)
    return f"""
<details class="area-panel" id="area-{area}">
  <summary><strong>{_e(name)}</strong> <span class="g-count">{len(fs)}</span>
    <span class="muted">{_plural(problems, "problema", "problemi")}, {_plural(len(fs) - problems, "informativo", "informativi")}</span></summary>
  <div class="area-body">
    <p class="muted">{_e(desc)}</p>
    <div class="rscroll"><table class="heat inner">
      <thead><tr><th scope="col">Controllo</th>{head}<th scope="col">Totale</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table></div>
    <h4>Tutti i finding dell'area</h4>
    <div class="tiles">{"".join(tiles)}</div>
  </div>
</details>"""




_COVERAGE_LABEL = {"covered": ("Rilevata", "LOW"), "partial": ("Parziale", "MEDIUM"),
                   "none": ("Non rilevata", "CRITICAL"), "unknown": ("Non nel layer", "INFO"),
                   "other-platform": ("Layer di altra piattaforma", "INFO")}


def _attack(a: Assessment) -> str:
    """Tecniche ATT&CK rese possibili dai problemi e, con un layer, la loro copertura di rilevamento."""
    data = a.metadata.get("attack")
    if not isinstance(data, dict) or not data.get("techniques"):
        return ""
    layer = data.get("layer")
    rows = []
    for r in data["techniques"]:
        cov = ""
        if layer:
            label, sev = _COVERAGE_LABEL.get(r.get("coverage"), ("?", "INFO"))
            note = f' title="{_e(r["coverage_note"])}"' if r.get("coverage_note") else ""
            cov = f'<td><span class="pill sev-{sev}"{note}>{label}</span></td>'
        titles = "; ".join(r.get("findings", [])[:4]) + (" …" if len(r.get("findings", [])) > 4 else "")
        rows.append(
            f'<tr><td><code>{_e(r["id"])}</code></td><td>{_e(r["name"])}<br><span class="muted">{_e(r["tactic"])}</span></td>'
            f'<td class="num">{r["count"]}</td><td><span class="pill sev-{_e(r["worst"])}">{_SEV_SINGULAR.get(r["worst"], "")}</span></td>'
            f'{cov}<td class="muted">{_e(titles)}</td></tr>')
    missing = sum(1 for r in data["techniques"] if r.get("coverage") == "none")
    other = any(r.get("coverage") == "other-platform" for r in data["techniques"])
    if layer and other:
        plats = ", ".join(data.get("layer_platforms") or [])
        intro = (f"Il layer <strong>{_e(layer)}</strong> descrive i rilevamenti per {_e(plats)}: non dice nulla "
                 "su questo sistema, quindi la copertura non è indicata. Usa un layer costruito per i log di "
                 "questa piattaforma.")
        cov_head = '<th scope="col">Rilevamento</th>'
    elif layer:
        intro = (f"Copertura di rilevamento dal layer <strong>{_e(layer)}</strong>. "
                 + (f"<strong>{_plural(missing, 'tecnica', 'tecniche')} senza alcun rilevamento</strong>: "
                    "un attacco che sfrutta quei problemi passerebbe inosservato, quindi vanno risolti per primi. "
                    if missing else "")
                 + "La copertura non cambia il punteggio di rischio.")
        cov_head = '<th scope="col">Rilevamento</th>'
    else:
        intro = ("Con <code>--attack-layer</code> e un layer di ATT&amp;CK Navigator (per esempio quello di "
                 "detection-engineering-lab) qui compare anche se ogni tecnica è rilevata.")
        cov_head = ""
    return f"""
<section aria-labelledby="attack-title">
  <h2 id="attack-title">Tecniche d'attacco (MITRE ATT&amp;CK)</h2>
  <p class="lead">Le tecniche che i problemi trovati rendono possibili o più facili (ATT&amp;CK v{_e(data.get("version", ""))};
  il collegamento è un giudizio di WatchDog, non una mappa ufficiale di MITRE). {intro}</p>
  <div class="rscroll"><table class="rtop">
    <thead><tr><th scope="col">ID</th><th scope="col">Tecnica</th><th scope="col">Problemi</th><th scope="col">Più grave</th>{cov_head}<th scope="col">Finding</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table></div>
</section>"""


def _compliance(findings: list[Finding]) -> str:
    """Controlli di CIS, ISO 27001 e NIST toccati dai problemi trovati."""
    tables = []
    for fw, name in FRAMEWORKS.items():
        rows = coverage(findings, fw)
        if not rows:
            continue
        body = "".join(
            f'<tr><td><code>{_e(r["id"])}</code></td><td>{_e(r["title"])}</td>'
            f'<td class="num">{r["count"]}</td>'
            f'<td><span class="pill sev-{r["worst"]}">{_SEV_SINGULAR[r["worst"]]}</span></td></tr>'
            for r in rows)
        tables.append(f"""
  <details class="area-panel"{" open" if not tables else ""}>
    <summary><strong>{_e(name)}</strong> <span class="g-count">{len(rows)}</span>
      <span class="muted">{_plural(len(rows), "controllo", "controlli")} con almeno un problema</span></summary>
    <div class="area-body"><div class="rscroll"><table class="rtop">
      <thead><tr><th scope="col">Controllo</th><th scope="col">Titolo</th><th scope="col">Problemi</th><th scope="col">Più grave</th></tr></thead>
      <tbody>{body}</tbody></table></div></div>
  </details>""")
    if not tables:
        return ""
    return f"""
<section aria-labelledby="comp-title">
  <h2 id="comp-title">Riferimenti normativi</h2>
  <p class="lead">I controlli di CIS Controls v8, ISO/IEC 27001:2022 (Annex A) e NIST SP 800-53 Rev. 5 a cui si
  riferiscono i problemi trovati. È un aiuto per l'audit: un problema indica una possibile carenza rispetto
  al controllo, ma l'assenza di problemi non dimostra la conformità (molti requisiti sono organizzativi).</p>
  <div class="areas">{"".join(tables)}</div>
</section>"""


def _secs(value) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "?"
    return f"{v:.1f} s" if v < 60 else f"{int(v) // 60} min {int(v) % 60:02d} s"


def _coverage(a: Assessment) -> str:
    names = [t for t in a.tools_used if t != "all"]
    durations = a.metadata.get("durations") if isinstance(a.metadata.get("durations"), dict) else {}
    if names:
        items = []
        for n in names:
            label, desc = _CHECK_INFO.get(n, (n, "Controllo personalizzato."))
            t = durations.get(n) if isinstance(durations.get(n), dict) else {}
            parts = [f"installazione {_secs(t['install'])}" if t.get("install") else "",
                     f"esecuzione {_secs(t['run'])}" if t.get("run") is not None else ""]
            timing = " · ".join(p for p in parts if p)
            items.append(f"<li><strong>{_e(label)}</strong><span>{_e(desc)}</span>"
                         + (f'<span class="t">{_e(timing)}</span>' if timing else "") + "</li>")
        checks = f'<ul class="checks">{"".join(items)}</ul>'
    else:
        checks = '<p class="muted">Elenco dei controlli non disponibile.</p>'

    errors = ""
    if a.errors:
        errors = (
            '<div class="notice warn"><strong>Controlli non completati o non eseguiti</strong>'
            '<p>Per questi controlli il risultato manca o è parziale: l\'assenza di segnalazioni '
            'non significa che vada tutto bene.</p><ul>'
            + "".join(f"<li>{_e(e)}</li>" for e in a.errors)
            + "</ul></div>"
        )
    skipped = ""
    if a.not_applicable():
        skipped = (
            '<div class="notice"><strong>Non applicabili a questo sistema</strong>'
            '<p>Richiesti ma senza senso qui (piattaforma o distribuzione diversa, o tool non '
            'disponibile): non sono stati eseguiti e non contano nel risultato.</p><ul>'
            + "".join(
                f"<li><strong>{_e(_CHECK_INFO.get(n, (n, ''))[0])}</strong>: {_e(r)}</li>"
                for n, r in sorted(a.not_applicable().items()))
            + "</ul></div>"
        )
    cleanup = ""
    if a.cleanup_status and a.cleanup_status != "NOT_RUN":
        cleanup = (f'<p class="muted">Pulizia dei tool installati temporaneamente: '
                   f'<strong>{_e(a.cleanup_status)}</strong>.</p>')
    return f"""
<section aria-labelledby="cov-title">
  <h2 id="cov-title">Cosa è stato controllato</h2>
  {checks}
  {errors}
  {skipped}
  {cleanup}
</section>"""


def _finding_card(i: int, f: Finding, is_new: bool = False) -> str:
    sev = f.severity.value
    conf = f.confidence.value
    evidence = f'<pre class="evidence">{_e(f.evidence)}</pre>' if f.evidence else ""
    low_conf = ' <span class="pill verify">da verificare</span>' if conf == "LOW" else ""
    new_pill = ' <span class="pill new">nuovo</span>' if is_new else ""
    command = ""
    if f.command:
        command = f"""
    <div class="cmd"><h4>Comando suggerito</h4>
      <pre class="evidence cmd-text">{_e(f.command)}</pre>
      <button type="button" class="copy" hidden>Copia comando</button>
      <p class="muted">Suggerimento generato dal tool: non è stato eseguito. Leggilo e verificalo prima di lanciarlo
      (meglio prima su un sistema non critico). Per SSH e firewall assicurati di non perdere l'accesso alla macchina.</p>
    </div>"""
    ref_text = short_refs(f)
    techs = techniques_for(f)
    if techs:
        ref_text = (ref_text + " · " if ref_text else "") + "ATT&CK " + ", ".join(techs)
    refs = f'\n    <p class="f-meta refs">Riferimenti: {_e(ref_text)}</p>' if ref_text else ""
    search = " ".join([f.title, f.category, f.source, f.description, ref_text]).lower()
    return f"""
<details class="finding sev-{sev}" id="f-{i}" data-sev="{sev}" data-cat="{_e(f.category)}" data-search="{_e(search)}">
  <summary>
    <span class="pill sev-{sev}">{_SEV_SINGULAR[sev]}</span>
    <span class="f-title">{_e(f.title)}</span>{new_pill}{low_conf}
    <span class="f-cat">{_e(f.category)}</span>
  </summary>
  <div class="f-body">
    <h4>Cosa significa</h4>
    <p>{_e(f.description)}</p>
    {f'<h4>Evidenza</h4>{evidence}' if evidence else ''}
    <div class="reco"><h4>Cosa fare</h4><p>{_e(f.recommendation)}</p></div>{command}
    <p class="f-meta">Rischio {f.risk} ({_RISK_LEVEL_IT[f.risk_level]}) = impatto {f.impact} × probabilità {f.probability}
    · Origine <code>{_e(f.source)}</code> · Confidenza {_CONF_LABEL.get(conf, _e(conf))}:
    {_e(_CONF_TEXT.get(conf, ''))}</p>{refs}
  </div>
</details>"""


def _findings(findings: list[Finding], new_keys: set | None = None) -> str:
    if not findings:
        return """
<section aria-labelledby="find-title">
  <h2 id="find-title">Findings</h2>
  <p class="empty">Nessun finding da mostrare.</p>
</section>"""
    parts = []
    i = 0
    for sev in _SEV_ORDER:
        group = [f for f in findings if f.severity.value == sev]
        if not group:
            continue
        cards = []
        for f in group:
            i += 1
            cards.append(_finding_card(
                i, f, bool(new_keys) and finding_key(f.source, f.title) in new_keys))
        parts.append(
            f'<div class="group" data-group="{sev}"><h3 class="sev-{sev}">'
            f'{_SEV_LABEL[sev]} <span class="g-count">{len(group)}</span></h3>'
            f'{"".join(cards)}</div>'
        )
    cat_options = "".join(f'<option value="{_e(c)}">{_e(c)}</option>'
                          for c in sorted({f.category for f in findings}))
    return f"""
<section aria-labelledby="find-title">
  <h2 id="find-title">Findings</h2>
  <p class="lead">Ordinati per gravità. Apri un finding per vedere spiegazione, evidenza e azione consigliata.</p>
  <div class="tools" id="tools" hidden>
    <input type="search" id="q" placeholder="Cerca per titolo, area o origine…" aria-label="Cerca tra i finding">
    <select id="cat" aria-label="Filtra per area"><option value="">Tutte le aree</option>{cat_options}</select>
    <button type="button" id="expand">Espandi tutto</button>
    <button type="button" id="collapse">Comprimi tutto</button>
    <button type="button" id="reset">Mostra tutto</button>
    <span id="shown" class="muted" aria-live="polite"></span>
  </div>
  {''.join(parts)}
  <p class="empty" id="none" hidden>Nessun finding corrisponde ai filtri.</p>
</section>"""


def _guide() -> str:
    sev = "".join(
        f'<li><span class="pill sev-{s}">{_SEV_SINGULAR[s]}</span> {_e(_SEV_MEANING[s])}</li>'
        for s in _SEV_ORDER
    )
    conf = "".join(
        f"<li><strong>{_CONF_LABEL[c].capitalize()}</strong>: {_e(_CONF_TEXT[c])}</li>"
        for c in ("HIGH", "MEDIUM", "LOW")
    )
    return f"""
<section aria-labelledby="guide-title">
  <h2 id="guide-title">Come leggere il report</h2>
  <div class="guide">
    <div><h4>Gravità</h4><ul>{sev}</ul></div>
    <div><h4>Rischio</h4><p class="muted">Rischio = impatto × probabilità. L'impatto va da 1 (basso) a 4 (critico) ed è la
    gravità; la probabilità va da 1 a 3 ed è la confidenza del rilevamento. Fasce: 12 critico, 8–11 alto,
    4–7 medio, 1–3 basso.</p></div>
    <div><h4>Confidenza</h4><ul>{conf}</ul>
    <p class="muted">Un finding informativo o a bassa confidenza può dire che un controllo non è
    stato possibile (per esempio per mancanza di permessi): non va letto come "tutto a posto".</p></div>
  </div>
</section>"""


def _render(a: Assessment, previous: dict | None = None) -> str:
    counts = a.counts_by_severity()
    findings = _sorted_findings(a.findings)
    duration = _duration(a)
    meta_items = [
        ("Target", f"<code>{_e(a.target)}</code>"),
        ("Modalità", f"<code>{_e(a.mode)}</code>"),
        ("Data", _e(_date(a))),
    ]
    if a.system_label():
        meta_items.insert(1, ("Sistema", _e(a.system_label())))
    if duration:
        meta_items.append(("Durata", _e(duration)))
    meta_items.append(("Finding", str(len(a.findings))))
    meta = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in meta_items)

    index = {id(f): n for n, f in enumerate(findings, 1)}
    cmp = compare(a, previous)
    new_keys = cmp.new_keys() if cmp else None
    body = "".join([
        _hero(a, counts),
        _comparison(cmp),
        _distribution(a, counts),
        _heatmap(findings, index),
        _risk_matrix(a),
        _priorities(findings),
        _categories(findings),
        _compliance(findings),
        _attack(a),
        _coverage(a),
        _findings(findings, new_keys),
        _guide(),
    ])
    nav = "".join(
        f'<a href="#{hid}">{label}</a>'
        for hid, label in _NAV if f'id="{hid}"' in body
    )
    return (_TEMPLATE
            .replace("%%TITLE%%", _e(a.target))
            .replace("%%NAV%%", nav)
            .replace("%%META%%", meta)
            .replace("%%BODY%%", body)
            .replace("%%TOOLS%%", _e(", ".join(a.tools_used) or "n/d"))
            .replace("%%CSS%%", _CSS)
            .replace("%%JS%%", _JS))


_NAV = [("sum-title", "Riepilogo"), ("cmp-title", "Confronto"), ("dist-title", "Distribuzione"),
        ("heat-title", "Heatmap"), ("risk-title", "Rischio"), ("prio-title", "Priorità"), ("cat-title", "Aree"), ("comp-title", "Norme"), ("attack-title", "ATT&CK"), ("cov-title", "Controlli"),
        ("find-title", "Finding"), ("guide-title", "Guida")]

_TEMPLATE = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Security Assessment Report — %%TITLE%%</title>
<style>%%CSS%%</style>
</head>
<body>
<header class="top">
  <div class="wrap">
    <p class="brand">WatchDog · Risk Assessor per Linux e macOS</p>
    <h1>Security Assessment Report</h1>
    <dl class="meta">%%META%%</dl>
  </div>
</header>
<nav class="toc" aria-label="Sezioni del report"><div class="wrap">%%NAV%%</div></nav>
<main class="wrap">
%%BODY%%
</main>
<footer class="wrap">
  <p><strong>Documento riservato.</strong> Contiene dettagli sensibili sul sistema analizzato: condividilo solo con chi deve intervenire.</p>
  <p class="muted">Generato da WatchDog · controlli eseguiti: %%TOOLS%%</p>
</footer>
<script>%%JS%%</script>
</body>
</html>
"""


_CSS = """
:root {
  --bg: #f5f6f8; --surface: #fff; --text: #1d2330; --muted: #5d6677; --border: #e2e5ea;
  --accent: #2f5fd0; --code: #eef0f4; --pre-bg: #1f2430; --pre-text: #e8ebf2;
  --c-CRITICAL: #b3261e; --c-HIGH: #c2570c; --c-MEDIUM: #a37400; --c-LOW: #1c6fb5; --c-INFO: #5d6677;
  --b-CRITICAL: #fdeceb; --b-HIGH: #fff1e5; --b-MEDIUM: #fff7de; --b-LOW: #e8f2fb; --b-INFO: #eef0f4;
  --shadow: 0 1px 3px rgba(20,30,50,.08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151c; --surface: #1b2029; --text: #e7eaf0; --muted: #98a2b3; --border: #2b3240;
    --accent: #7ea2ff; --code: #262d3a; --pre-bg: #0d1016; --pre-text: #dfe3ec;
    --c-CRITICAL: #ff8a80; --c-HIGH: #ffa45c; --c-MEDIUM: #f2c84b; --c-LOW: #6db6ff; --c-INFO: #98a2b3;
    --b-CRITICAL: #3a1d1b; --b-HIGH: #3a2616; --b-MEDIUM: #382f12; --b-LOW: #17293a; --b-INFO: #232a36;
    --shadow: none;
  }
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body { margin: 0; background: var(--bg); color: var(--text); line-height: 1.55;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
.wrap { max-width: 1000px; margin: 0 auto; padding: 0 1.25rem; }
code { background: var(--code); padding: 1px 6px; border-radius: 4px; font-size: .9em;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
h1 { margin: .15rem 0 1rem; font-size: clamp(1.6rem, 4vw, 2.2rem); }
h2 { margin: 0 0 .5rem; font-size: 1.3rem; }
h4 { margin: 1rem 0 .25rem; font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
section { margin: 2.25rem 0; }
.lead, .muted { color: var(--muted); }
.lead { margin: 0 0 1rem; }
.muted { font-size: .92rem; }
.top { background: linear-gradient(135deg, #1b2a4a, #2f5fd0); color: #fff; padding: 2rem 0 1.5rem; }
.brand { margin: 0; font-size: .85rem; letter-spacing: .12em; text-transform: uppercase; opacity: .85; }
.meta { display: flex; flex-wrap: wrap; gap: .75rem 2rem; margin: 0; }
.meta div { min-width: 7rem; }
.meta dt { font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; opacity: .75; }
.meta dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.top code { background: rgba(255,255,255,.18); color: #fff; }

.toc { position: sticky; top: 0; z-index: 10; background: var(--surface); border-bottom: 1px solid var(--border); }
.toc .wrap { display: flex; gap: .25rem; overflow-x: auto; }
.toc a { padding: .6rem .8rem; color: var(--muted); text-decoration: none; font-size: .88rem; white-space: nowrap; border-bottom: 2px solid transparent; }
.toc a:hover, .toc a.on { color: var(--accent); border-bottom-color: var(--accent); }
h2, .area-panel, .finding { scroll-margin-top: 3.5rem; }
.hero { display: flex; gap: 1.75rem; align-items: center; background: var(--surface);
  border: 1px solid var(--border); border-left: 6px solid var(--lvl, var(--c-LOW));
  border-radius: 12px; padding: 1.5rem; margin-top: 1.25rem; box-shadow: var(--shadow); position: relative; }
.lvl-CRITICAL { --lvl: var(--c-CRITICAL); } .lvl-HIGH { --lvl: var(--c-HIGH); }
.lvl-MEDIUM { --lvl: var(--c-MEDIUM); } .lvl-LOW { --lvl: var(--c-LOW); }
.gauge { position: relative; width: 150px; height: 150px; flex: none; }
.g-track { stroke: var(--border); } .g-val { stroke: var(--lvl); }
.g-text { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.g-score { font-size: 2.6rem; font-weight: 800; line-height: 1; color: var(--lvl); }
.g-max { font-size: .8rem; color: var(--muted); }
.hero-level { margin: .25rem 0; font-size: 1.1rem; }
.lvl-badge { display: inline-block; padding: .1rem .7rem; border-radius: 999px; font-weight: 800;
  letter-spacing: .04em; background: var(--lvl); color: var(--surface); }
.hero-text { margin: .4rem 0; font-size: 1.05rem; }
.hero-note { margin: .6rem 0 0; font-size: .85rem; color: var(--muted); }

.bar { display: flex; height: 16px; border-radius: 999px; overflow: hidden; background: var(--border); gap: 2px; }
.seg { min-width: 6px; }
.seg.sev-CRITICAL, .pill.sev-CRITICAL, .card.sev-CRITICAL::before { background: var(--c-CRITICAL); }
.seg.sev-HIGH, .pill.sev-HIGH, .card.sev-HIGH::before { background: var(--c-HIGH); }
.seg.sev-MEDIUM, .pill.sev-MEDIUM, .card.sev-MEDIUM::before { background: var(--c-MEDIUM); }
.seg.sev-LOW, .pill.sev-LOW, .card.sev-LOW::before { background: var(--c-LOW); }
.seg.sev-INFO, .pill.sev-INFO, .card.sev-INFO::before { background: var(--c-INFO); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: .75rem; margin-top: 1rem; }
.card { position: relative; text-align: left; font: inherit; color: inherit; cursor: pointer;
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: .8rem .9rem .8rem 1.1rem; box-shadow: var(--shadow); overflow: hidden; }
.card::before { content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 5px; }
.card[disabled] { opacity: .55; cursor: default; }
.card[aria-pressed="true"] { outline: 2px solid var(--accent); }
.card-n { display: block; font-size: 1.8rem; font-weight: 800; line-height: 1.1; }
.card-l { display: block; font-weight: 700; }
.card-m { display: block; font-size: .8rem; color: var(--muted); margin-top: .2rem; }

.pill { display: inline-block; padding: .08rem .55rem; border-radius: 999px; color: #fff;
  font-size: .72rem; font-weight: 700; letter-spacing: .03em; vertical-align: middle; white-space: nowrap; }
.rmatrix, .rtop { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: .92rem; }
.rscroll { overflow-x: auto; max-width: 100%; }
.rmatrix th, .rmatrix td, .rtop th, .rtop td { border: 1px solid var(--border, #d9dde5); padding: 8px 10px; text-align: left; }
.rmatrix td.rm { text-align: center; min-width: 90px; }
.rmatrix td.rm strong { display: block; font-size: 1.3rem; }
.rmatrix td.rm span { font-size: .75rem; opacity: .8; }
.rmatrix td.rm.zero { opacity: .35; }
.rmatrix td.sev-CRITICAL { background: var(--b-CRITICAL); } .rmatrix td.sev-HIGH { background: var(--b-HIGH); }
.rmatrix td.sev-MEDIUM { background: var(--b-MEDIUM); } .rmatrix td.sev-LOW { background: var(--b-LOW); }
.rlevels { list-style: none; display: flex; gap: 14px; flex-wrap: wrap; padding: 0; margin: 4px 0 12px; }
.rtop-h { margin: 14px 0 4px; font-size: 1rem; }
.pill.sev-MEDIUM { color: #1d2330; } .pill.verify { background: var(--b-MEDIUM); color: var(--c-MEDIUM); border: 1px solid var(--c-MEDIUM); }
@media (prefers-color-scheme: dark) { .pill { color: #10131a; } }

.cmp-score { font-size: 1.05rem; margin: 0 0 .8rem; }
.delta { font-weight: 700; padding: .05rem .5rem; border-radius: 999px; background: var(--code); }
.delta.up { color: var(--c-CRITICAL); } .delta.down { color: #1a7f37; } .delta.eq { color: var(--muted); }
@media (prefers-color-scheme: dark) { .delta.down { color: #5fd47f; } }
.cmp { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
.cmp-col { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: .6rem .9rem; }
.cmp-col h4 { margin-top: .3rem; } .cmp-col ul { list-style: none; margin: 0; padding: 0; display: grid; gap: .4rem; }
.struck { text-decoration: line-through; color: var(--muted); }
.pill.new { background: var(--accent); color: #fff; }
.cmd .evidence { margin-bottom: .4rem; } .copy { padding: .3rem .7rem; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font: inherit; font-size: .85rem; cursor: pointer; }
.cats li[data-cat].clickable { cursor: pointer; } .cats li[data-cat].clickable:hover .cat-name { color: var(--accent); text-decoration: underline; }
.tools select { padding: .5rem .6rem; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--text); font: inherit; }
.prio { margin: 0; padding-left: 1.4rem; display: grid; gap: .8rem; }
.prio li { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: .7rem .9rem; box-shadow: var(--shadow); }
.cats { list-style: none; margin: 0; padding: 0; display: grid; gap: .5rem; }
.cats li { display: grid; grid-template-columns: minmax(7rem, 12rem) 1fr 2.5rem; gap: .75rem; align-items: center; }
.cat-bar { height: 10px; background: var(--border); border-radius: 999px; overflow: hidden; }
.cat-bar span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
.cat-n { text-align: right; font-weight: 700; }
.checks { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: .6rem; }
.checks li { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: .6rem .8rem; }
.checks strong { display: block; } .checks span { color: var(--muted); font-size: .88rem; display: block; }
.checks span.t { font-size: .78rem; margin-top: .2rem; font-variant-numeric: tabular-nums; }
.notice { border: 1px solid var(--border); border-radius: 10px; padding: .8rem 1rem; margin-top: 1rem; }
.notice.warn { background: var(--b-MEDIUM); border-color: var(--c-MEDIUM); }
.notice p { margin: .3rem 0; } .notice ul { margin: .3rem 0 0; padding-left: 1.2rem; }

.tools { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; margin-bottom: 1rem; }
.tools[hidden], [hidden] { display: none !important; }
.tools input { flex: 1 1 14rem; padding: .5rem .75rem; border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); color: var(--text); font: inherit; }
.tools button { padding: .45rem .8rem; border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); color: var(--text); font: inherit; cursor: pointer; }
.tools button:hover, .card:not([disabled]):hover { border-color: var(--accent); }
.group h3 { margin: 1.5rem 0 .6rem; font-size: 1rem; color: var(--c-INFO); display: flex; gap: .5rem; align-items: center; }
.group h3.sev-CRITICAL { color: var(--c-CRITICAL); } .group h3.sev-HIGH { color: var(--c-HIGH); }
.group h3.sev-MEDIUM { color: var(--c-MEDIUM); } .group h3.sev-LOW { color: var(--c-LOW); }
.g-count { background: var(--code); color: var(--text); border-radius: 999px; padding: 0 .55rem; font-size: .8rem; }
.finding { background: var(--surface); border: 1px solid var(--border); border-left: 5px solid var(--c-INFO);
  border-radius: 10px; margin: .6rem 0; box-shadow: var(--shadow); }
.finding.sev-CRITICAL { border-left-color: var(--c-CRITICAL); } .finding.sev-HIGH { border-left-color: var(--c-HIGH); }
.finding.sev-MEDIUM { border-left-color: var(--c-MEDIUM); } .finding.sev-LOW { border-left-color: var(--c-LOW); }
.finding summary { cursor: pointer; padding: .75rem 1rem; display: flex; flex-wrap: wrap; gap: .5rem .75rem; align-items: center; list-style: none; }
.finding summary::-webkit-details-marker { display: none; }
.finding summary::before { content: "▸"; color: var(--muted); transition: transform .15s; }
.finding[open] summary::before { transform: rotate(90deg); }
.f-title { font-weight: 600; flex: 1 1 18rem; overflow-wrap: anywhere; }
.f-cat { color: var(--muted); font-size: .82rem; }
.f-body { padding: 0 1rem 1rem 2.1rem; }
.f-body p { margin: .2rem 0; overflow-wrap: anywhere; }
.evidence { background: var(--pre-bg); color: var(--pre-text); padding: .75rem; border-radius: 8px;
  overflow-x: auto; font-size: .82rem; margin: .3rem 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.reco { background: var(--b-LOW); border-left: 4px solid var(--c-LOW); border-radius: 6px; padding: .1rem .9rem .5rem; margin-top: .8rem; }
.num { text-align: center; }
.f-meta.refs { margin-top: .3rem !important; }
.f-meta { margin-top: .8rem !important; color: var(--muted); font-size: .85rem; }
.empty { padding: 1.5rem; text-align: center; color: var(--muted); background: var(--surface); border: 1px dashed var(--border); border-radius: 10px; }
.guide { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; }
.guide ul { margin: 0; padding-left: 1.1rem; display: grid; gap: .35rem; list-style: none; padding: 0; }
footer { padding: 1rem 1.25rem 3rem; font-size: .9rem; border-top: 1px solid var(--border); margin-top: 2rem; }
footer p { margin: .3rem 0; }

.heat { border-collapse: separate; border-spacing: 3px; width: 100%; font-size: .92rem; }
.heat th { text-align: left; font-weight: 600; padding: 6px 8px; white-space: nowrap; }
.heat thead th { font-size: .8rem; color: var(--muted); text-align: center; }
.heat thead th:first-child { text-align: left; }
.heat td { text-align: center; padding: 10px 6px; border-radius: 6px; min-width: 56px; font-weight: 700; }
.heat td.hm { background: var(--b-INFO); }
.heat td.hm.sev-CRITICAL { background: var(--b-CRITICAL); background: color-mix(in srgb, var(--c-CRITICAL) var(--hm), var(--surface)); }
.heat td.hm.sev-HIGH { background: var(--b-HIGH); background: color-mix(in srgb, var(--c-HIGH) var(--hm), var(--surface)); }
.heat td.hm.sev-MEDIUM { background: var(--b-MEDIUM); background: color-mix(in srgb, var(--c-MEDIUM) var(--hm), var(--surface)); }
.heat td.hm.sev-LOW { background: var(--b-LOW); background: color-mix(in srgb, var(--c-LOW) var(--hm), var(--surface)); }
.heat td.hm.sev-INFO { background: color-mix(in srgb, var(--c-INFO) calc(var(--hm) * .5), var(--surface)); }
.heat td.hm.hot { color: #fff; }
@media (prefers-color-scheme: dark) { .heat td.hm.hot { color: #10131a; } }
.heat td.hm.zero { background: var(--surface); color: var(--border); font-weight: 400; border: 1px dashed var(--border); }
.heat td.hm-tot { background: var(--code); }
.heat td.hm-risk { background: transparent; }
.heat tbody tr[data-area] { cursor: pointer; }
.heat tbody tr[data-area]:hover th a, .heat tbody tr.on th a { color: var(--accent); text-decoration: underline; }
.heat tbody tr.on td, .heat tbody tr.on th { outline: 2px solid var(--accent); outline-offset: -2px; }
.area-link { color: var(--text); text-decoration: none; }
.areas { display: grid; gap: .6rem; margin-top: 1rem; }
.area-panel { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); }
.area-panel > summary { cursor: pointer; padding: .7rem 1rem; display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; }
.area-panel[open] > summary { border-bottom: 1px solid var(--border); }
.area-body { padding: .2rem 1rem 1rem; }
.heat.inner th[scope="row"] { font-weight: 500; }
.tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: .5rem; }
.tile { display: flex; flex-direction: column; gap: .3rem; padding: .55rem .7rem; border-radius: 8px; text-decoration: none;
  color: var(--text); background: var(--b-INFO); border-left: 5px solid var(--c-INFO); }
.tile:hover { outline: 2px solid var(--accent); }
.tile.sev-CRITICAL { background: var(--b-CRITICAL); border-left-color: var(--c-CRITICAL); }
.tile.sev-HIGH { background: var(--b-HIGH); border-left-color: var(--c-HIGH); }
.tile.sev-MEDIUM { background: var(--b-MEDIUM); border-left-color: var(--c-MEDIUM); }
.tile.sev-LOW { background: var(--b-LOW); border-left-color: var(--c-LOW); }
.tile-h { display: flex; justify-content: space-between; align-items: center; gap: .4rem; }
.tile-r { font-size: .75rem; color: var(--muted); }
.tile-t { font-weight: 600; font-size: .88rem; overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
.tile-c { font-size: .75rem; color: var(--muted); }

@media (max-width: 640px) {
  .hero { flex-direction: column; text-align: center; }
  .cats li { grid-template-columns: 1fr 2.5rem; } .cat-bar { grid-column: 1 / -1; grid-row: 2; }
  .f-body { padding-left: 1rem; }
}
@media print {
  body { background: #fff; color: #000; } .top { background: #fff; color: #000; border-bottom: 2px solid #000; }
  .top code { background: #eee; color: #000; } .tools, .toc, .copy { display: none !important; }
  .hero, .finding, .card, .checks li, .prio li, .tile { box-shadow: none; break-inside: avoid; }
  .finding .f-body { display: block; }
}
"""

_JS = """
(function () {
  var tools = document.getElementById('tools');
  if (!tools) return;
  tools.hidden = false;
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var groups = Array.prototype.slice.call(document.querySelectorAll('.group'));
  var chips = Array.prototype.slice.call(document.querySelectorAll('.card[data-filter]'));
  var q = document.getElementById('q'), shown = document.getElementById('shown'), none = document.getElementById('none');
  var sev = null, cat = '';
  var catSel = document.getElementById('cat');
  function apply() {
    var term = q.value.trim().toLowerCase(), n = 0;
    cards.forEach(function (c) {
      var ok = (!sev || c.dataset.sev === sev) && (!cat || c.dataset.cat === cat) && (!term || c.dataset.search.indexOf(term) !== -1);
      c.hidden = !ok; if (ok) n++;
    });
    groups.forEach(function (g) {
      g.hidden = !g.querySelector('.finding:not([hidden])');
    });
    chips.forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.filter === sev)); });
    shown.textContent = n + ' di ' + cards.length + ' finding';
    none.hidden = n !== 0;
  }
  chips.forEach(function (b) {
    b.addEventListener('click', function () {
      if (b.disabled) return;
      sev = (sev === b.dataset.filter) ? null : b.dataset.filter;
      apply();
      var t = document.getElementById('find-title'); if (t) t.scrollIntoView();
    });
  });
  if (catSel) catSel.addEventListener('change', function () { cat = catSel.value; apply(); });
  Array.prototype.forEach.call(document.querySelectorAll('.cats li[data-cat]'), function (li) {
    li.classList.add('clickable'); li.title = 'Mostra solo questa area';
    li.addEventListener('click', function () {
      cat = li.dataset.cat; if (catSel) catSel.value = cat; apply();
      var t = document.getElementById('find-title'); if (t) t.scrollIntoView();
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('.cmd'), function (box) {
    var b = box.querySelector('.copy'), pre = box.querySelector('.cmd-text');
    if (!b || !pre) return;
    b.hidden = false;
    b.addEventListener('click', function () {
      var text = pre.textContent;
      function done() { b.textContent = 'Copiato ✓'; setTimeout(function () { b.textContent = 'Copia comando'; }, 1800); }
      function fallback() {
        var r = document.createRange(); r.selectNodeContents(pre);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        try { document.execCommand('copy'); done(); } catch (e) { b.textContent = 'Selezionato: premi Ctrl+C'; }
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else { fallback(); }
    });
  });
  var links = Array.prototype.slice.call(document.querySelectorAll('.toc a'));
  if ('IntersectionObserver' in window && links.length) {
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (e.isIntersecting) links.forEach(function (l) { l.classList.toggle('on', l.getAttribute('href') === '#' + e.target.id); });
      });
    }, { rootMargin: '-10% 0px -80% 0px' });
    links.forEach(function (l) { var h = document.querySelector(l.getAttribute('href')); if (h) io.observe(h); });
  }

  function openTarget(sel, scroll) {
    var t = document.querySelector(sel);
    if (!t) return null;
    if (t.tagName === 'DETAILS') t.open = true;
    if (t.hidden) { sev = null; cat = ''; if (catSel) catSel.value = ''; q.value = ''; apply(); }
    if (scroll) t.scrollIntoView({ block: 'start' });
    return t;
  }
  var heatRows = Array.prototype.slice.call(document.querySelectorAll('.heat tr[data-area]'));
  heatRows.forEach(function (tr) {
    tr.addEventListener('click', function (ev) {
      ev.preventDefault();
      var panel = document.getElementById('area-' + tr.dataset.area);
      if (!panel) return;
      var wasOn = tr.classList.contains('on') && panel.open;
      heatRows.forEach(function (r) { r.classList.remove('on'); });
      document.querySelectorAll('.area-panel').forEach(function (p) { p.open = false; });
      if (!wasOn) { tr.classList.add('on'); panel.open = true; panel.scrollIntoView({ block: 'start' }); }
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('a.tile[href^="#f-"]'), function (a) {
    a.addEventListener('click', function (ev) {
      ev.preventDefault();
      if (openTarget(a.getAttribute('href'), true)) history.replaceState(null, '', a.getAttribute('href'));
    });
  });
  q.addEventListener('input', apply);
  document.getElementById('expand').addEventListener('click', function () {
    cards.forEach(function (c) { if (!c.hidden) c.open = true; });
  });
  document.getElementById('collapse').addEventListener('click', function () {
    cards.forEach(function (c) { c.open = false; });
  });
  document.getElementById('reset').addEventListener('click', function () {
    sev = null; cat = ''; if (catSel) catSel.value = ''; q.value = ''; apply();
  });
  if (location.hash) {
    var t = document.querySelector(location.hash.replace(/[^#\\w-]/g, ''));
    if (t && t.tagName === 'DETAILS') t.open = true;
  }
  apply();
})();
"""

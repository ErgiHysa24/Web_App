import threading
import time
from datetime import timedelta

from sqlalchemy import select

from watchdog_web import engine as eng
from watchdog_web import services as svc
from watchdog_web.db import session_scope
from watchdog_web.models import Finding, Scan, Target, now
from watchdog_web.worker import Worker, claim_next, reap_stale

from conftest import TARGET, FakeSSH

FAST = {"preset": "custom", "tools": ["kernel", "ssh_config"]}


def _worker(app) -> Worker:
    return Worker(app.state.db, app.state.settings, app.state.box, name="test-worker")


def _run_all(app, timeout=120):
    w = _worker(app)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        w.run_once()
        with session_scope(app.state.db) as s:
            if not s.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))).all():
                return
        time.sleep(0.2)
    raise AssertionError("le scansioni non sono finite in tempo")


def _scan(db, scan_id) -> Scan:
    with session_scope(db) as s:
        scan = s.get(Scan, scan_id)
        _ = scan.target.name, len(scan.findings)
        return scan


def _start(browser, target_id, **extra) -> int:
    r = browser("anna").post("/scans/new", {"targets": str(target_id), **FAST, **extra}, page="/scans/new")
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def test_scan_runs_and_results_are_stored(app, browser, db, target_id):
    scan_id = _start(browser, target_id)
    b = browser("anna")
    page = b.get(f"/scans/{scan_id}")
    assert "In coda" in page.text and "data-scan-live" in page.text
    assert b.get(f"/scans/{scan_id}/status.json").json()["position"] == 1
    _run_all(app)
    scan = _scan(db, scan_id)
    assert scan.status == "done", scan.error
    assert scan.progress == 100 and scan.risk_score is not None and scan.findings
    assert scan.tools == ["ssh_config", "kernel"]
    # la password SSH è arrivata all'esecutore decifrata, la chiave del server è stata registrata
    assert FakeSSH.seen[-1]["password"] == "segretissima-ssh" and FakeSSH.seen[-1]["accept_new_host_key"] is True
    with session_scope(db) as s:
        assert s.get(Target, target_id).host_key == FakeSSH.host_key
    page = b.get(f"/scans/{scan_id}?severity=ALL")
    assert page.status_code == 200 and "Problemi per area e gravità" in page.text
    assert b.get("/").status_code == 200 and b.get(f"/targets/{target_id}").status_code == 200
    # report completo: servito in sandbox, scaricabile in tre formati
    r = b.get(f"/scans/{scan_id}/report")
    assert r.status_code == 200 and r.headers["content-security-policy"].startswith("sandbox")
    assert "allow-same-origin" not in r.headers["content-security-policy"]
    assert b.get(f"/scans/{scan_id}/report?format=json").json()["target"]
    assert b.get(f"/scans/{scan_id}/report?format=md").status_code == 200
    assert b.get(f"/scans/{scan_id}/report?format=exe").status_code == 400


def test_second_scan_uses_pinned_host_key_and_can_be_compared(app, browser, db, target_id):
    first = _start(browser, target_id)
    _run_all(app)
    second = _start(browser, target_id)
    _run_all(app)
    assert FakeSSH.seen[-1]["known_host_key"] == FakeSSH.host_key
    assert FakeSSH.seen[-1]["accept_new_host_key"] is False
    r = browser("anna").get(f"/compare?a={second}&b={first}")
    assert r.status_code == 200 and "Ancora presenti" in r.text


def test_connection_failure_is_a_failed_scan_not_a_clean_one(app, browser, db, target_id):
    FakeSSH.fail_with = "AuthenticationException: Authentication failed."
    scan_id = _start(browser, target_id)
    _run_all(app)
    scan = _scan(db, scan_id)
    assert scan.status == "failed" and "Connessione SSH non riuscita" in scan.error
    assert scan.risk_score is None and not scan.findings
    page = browser("anna").get(f"/scans/{scan_id}").text
    assert "nessun risultato" in page and "Risultati per area" not in page
    assert "segretissima-ssh" not in page


def test_queue_one_running_scan_per_target(app, browser, db, target_id):
    anna = browser("anna")
    other = anna.post("/targets/new", {**TARGET, "name": "Secondo", "host": "192.0.2.11"})
    other_id = int(other.headers["location"].rsplit("/", 1)[1])
    with session_scope(db) as s:
        ids = [svc.enqueue_scan(s, s.get(Target, t), None, "native").id for t in (target_id, target_id, other_id)]
    with session_scope(db) as s:
        assert claim_next(s, "w1") == ids[0]
    with session_scope(db) as s:
        assert claim_next(s, "w2") == ids[2]          # il secondo sullo stesso obiettivo aspetta
    with session_scope(db) as s:
        assert claim_next(s, "w3") is None
    with session_scope(db) as s:
        s.get(Scan, ids[0]).status = "done"
    with session_scope(db) as s:
        assert claim_next(s, "w1") == ids[1]


def test_queue_limit_per_target(browser, target_id):
    anna = browser("anna")
    for _ in range(svc.MAX_QUEUED_PER_TARGET):
        assert anna.post("/scans/new", {"targets": str(target_id), "preset": "native"}).status_code == 303
    r = anna.post("/scans/new", {"targets": str(target_id), "preset": "native"})
    assert r.status_code == 400 and "in coda" in r.text
    assert anna.post("/scans/new", {"targets": str(target_id), "preset": "custom", "tools": "inventato"}).status_code == 400
    assert anna.post("/scans/new", {"preset": "native"}).status_code == 400


def test_cancel_queued_scan(app, browser, db, target_id):
    scan_id = _start(browser, target_id)
    assert browser("vito").post(f"/scans/{scan_id}/cancel").status_code == 403
    assert browser("anna").post(f"/scans/{scan_id}/cancel").status_code == 303
    assert _scan(db, scan_id).status == "cancelled"
    with session_scope(db) as s:
        assert claim_next(s, "w") is None


def test_cancel_running_scan_stops_at_next_step(app, db, target_id):
    with session_scope(db) as s:
        scan_id = svc.enqueue_scan(s, s.get(Target, target_id), None, "custom", ["kernel"]).id
    with session_scope(db) as s:
        assert claim_next(s, "w") == scan_id
        svc.request_cancel(s, s.get(Scan, scan_id))
    eng.run_scan(scan_id, db, app.state.settings, app.state.box)
    scan = _scan(db, scan_id)
    assert scan.status == "cancelled" and not scan.findings


def test_stale_running_scan_is_closed(app, db, target_id):
    with session_scope(db) as s:
        scan_id = svc.enqueue_scan(s, s.get(Target, target_id), None, "native").id
    with session_scope(db) as s:
        claim_next(s, "worker-morto")
        assert reap_stale(s, app.state.settings) == 0
        s.get(Scan, scan_id).heartbeat_at = now() - timedelta(minutes=30)
    with session_scope(db) as s:
        assert reap_stale(s, app.state.settings) == 1
    scan = _scan(db, scan_id)
    assert scan.status == "failed" and "non risponde" in scan.error


def test_two_scans_run_at_the_same_time(app, browser, db, target_id, monkeypatch):
    anna = browser("anna")
    other = anna.post("/targets/new", {**TARGET, "name": "Secondo", "host": "192.0.2.11"})
    other_id = int(other.headers["location"].rsplit("/", 1)[1])
    together, running, lock = [], [0], threading.Lock()

    def slow_scan(scan_id, factory, settings, box):
        with lock:
            running[0] += 1
            together.append(running[0])
        time.sleep(0.5)
        with lock:
            running[0] -= 1
        with session_scope(factory) as s:
            s.get(Scan, scan_id).status = "done"

    monkeypatch.setattr("watchdog_web.worker.run_scan", slow_scan)
    with session_scope(db) as s:
        for t in (target_id, other_id):
            svc.enqueue_scan(s, s.get(Target, t), None, "native")
    _run_all(app, timeout=20)
    assert max(together) == 2


def test_text_from_the_scanned_system_is_escaped(app, browser, db, target_id):
    with session_scope(db) as s:
        scan = Scan(target_id=target_id, status="done", risk_level="HIGH", risk_score=70, counts={"HIGH": 1},
                    areas={"access": {"count": 1, "worst": "HIGH"}}, summary={"errors": ["<img src=x onerror=1>"]},
                    incomplete=1, finished_at=now(), started_at=now(), system_label="<b>Ubuntu</b>")
        scan.findings.append(Finding(position=1, title="<script>alert(1)</script>", severity="HIGH", area="access",
                                     source="users-collector:x", evidence="</pre><script>alert(2)</script>"))
        s.add(scan)
        s.flush()
        scan_id = scan.id
    b = browser("anna")
    for url in (f"/scans/{scan_id}", "/", "/scans", f"/targets/{target_id}"):
        html = b.get(url).text
        assert "<script>alert" not in html and "<img src=x" not in html and "<b>Ubuntu" not in html, url
    html = b.get(f"/scans/{scan_id}").text
    assert "&lt;script&gt;alert(1)" in html and "non sono stati completati" in html


def test_report_path_outside_reports_dir_is_not_served(app, browser, db, target_id, tmp_path):
    secret = tmp_path / "altrove"
    secret.mkdir()
    (secret / "assessment.html").write_text("segreto")
    with session_scope(db) as s:
        scan = Scan(target_id=target_id, status="done", risk_level="LOW", risk_score=1, report_dir=str(secret),
                    finished_at=now())
        s.add(scan)
        s.flush()
        scan_id = scan.id
    assert browser("anna").get(f"/scans/{scan_id}/report").status_code == 400

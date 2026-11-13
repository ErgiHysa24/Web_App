"""Più utenti: ognuno vede solo le sue macchine, condivisione, tag, registrazione, grafici."""
import dataclasses
import re

from sqlalchemy import select

from watchdog_web import services as svc
from watchdog_web.db import session_scope
from watchdog_web.models import AuditLog, Finding, Scan, Target, User, now
from watchdog_web.security import totp_code, totp_step

from conftest import TARGET, csrf_of
from test_scans import _run_all

FAST = {"preset": "custom", "tools": ["kernel"]}


def _new_target(b, **changes) -> int:
    r = b.post("/targets/new", {**TARGET, **changes})
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])


def _done_scan(db, target_id, **fields) -> int:
    with session_scope(db) as s:
        scan = Scan(target_id=target_id, status="done", risk_level="HIGH", risk_score=fields.pop("score", 60),
                    counts={"HIGH": 1, "LOW": 2}, areas={"network": {"count": 1, "worst": "HIGH"}},
                    finished_at=now(), started_at=now(), system_label="Debian 12", tools=["nmap", "kernel"], **fields)
        s.add(scan)
        s.flush()
        return scan.id


# ---------------------------------------------------------------- isolamento

def test_users_see_only_their_machines(app, browser, db, target_id):
    anna, bruno, admin = browser("anna"), browser("bruno"), browser("admin")
    scan_id = _done_scan(db, target_id)
    secret = "Server di prova"
    for url in ("/", "/targets", "/scans", "/insights", "/map"):
        assert secret not in bruno.get(url).text, url
        assert secret in anna.get(url).text, url
        assert secret in admin.get(url).text, url
    for url in (f"/targets/{target_id}", f"/targets/{target_id}/edit", f"/scans/{scan_id}",
                f"/scans/{scan_id}/report", f"/compare?a={scan_id}&b={scan_id}"):
        r = bruno.get(url)
        assert r.status_code in (400, 403) and secret not in r.text, url
    assert bruno.get(f"/scans/{scan_id}/status.json").status_code == 404
    assert bruno.get("/status.json").json()["last_finished"] == 0
    for url, data in ((f"/targets/{target_id}/edit", TARGET), (f"/targets/{target_id}/delete", {}),
                      (f"/targets/{target_id}/share", {"username": "bruno"}), (f"/scans/{scan_id}/cancel", {}),
                      (f"/scans/{scan_id}/delete", {})):
        assert bruno.post(url, data).status_code in (400, 403), url
    r = bruno.post("/scans/new", {"targets": str(target_id), "preset": "native"}, page="/scans/new")
    assert r.status_code == 400
    with session_scope(db) as s:
        assert s.get(Target, target_id) is not None and s.get(Target, target_id).name == secret


def test_same_name_for_different_owners(browser):
    anna, bruno = browser("anna"), browser("bruno")
    _new_target(anna)
    assert anna.post("/targets/new", TARGET).status_code == 400            # stesso proprietario: no
    _new_target(bruno)                                                     # altro proprietario: sì


def test_api_isolation(app, browser, db, target_id):
    from test_api import _h, _token
    scan_id = _done_scan(db, target_id)
    c, h = app.state.client, _h(_token(browser, "bruno"))
    assert c.get("/api/v1/targets", headers=h).json()["targets"] == []
    assert c.get(f"/api/v1/targets/{target_id}", headers=h).status_code == 404
    assert c.get("/api/v1/scans", headers=h).json()["scans"] == []
    for url in (f"/api/v1/scans/{scan_id}", f"/api/v1/scans/{scan_id}/findings", f"/api/v1/scans/{scan_id}/report"):
        assert c.get(url, headers=h).status_code == 404, url
    assert c.post(f"/api/v1/scans/{scan_id}/cancel", headers=h).status_code == 404
    assert c.post("/api/v1/scans", json={"target_id": target_id}, headers=h).status_code == 404
    assert c.post("/api/v1/scans", json={"target": "server di prova"}, headers=h).status_code == 404


# ---------------------------------------------------------------- condivisione

def test_sharing_read_only_then_with_scans(app, browser, db, target_id):
    anna, bruno = browser("anna"), browser("bruno")
    assert anna.post(f"/targets/{target_id}/share", {"username": "nessuno"}).status_code == 303
    assert anna.post(f"/targets/{target_id}/share", {"username": "bruno"}).status_code == 303
    page = bruno.get(f"/targets/{target_id}")
    assert page.status_code == 200 and "sola lettura" in page.text
    assert bruno.get(f"/targets/{target_id}/edit").status_code == 403
    r = bruno.post("/scans/new", {"targets": str(target_id), **FAST}, page="/scans/new")
    assert r.status_code == 400
    assert "Server di prova" not in bruno.get("/scans/new").text
    anna.post(f"/targets/{target_id}/share", {"username": "bruno", "can_scan": "1"})
    r = bruno.post("/scans/new", {"targets": str(target_id), **FAST}, page="/scans/new")
    assert r.status_code == 303
    _run_all(app)
    assert bruno.get(f"/targets/{target_id}/edit").status_code == 403    # gestire resta del proprietario
    with session_scope(db) as s:
        share_id = s.get(Target, target_id).shares[0].id
    anna.post(f"/targets/{target_id}/unshare/{share_id}")
    assert bruno.get(f"/targets/{target_id}").status_code == 400
    with session_scope(db) as s:
        actions = [a.action for a in s.scalars(select(AuditLog)).all()]
    assert "target.share" in actions and "target.unshare" in actions


def test_viewer_with_share_cannot_scan(browser, target_id):
    anna, vito = browser("anna"), browser("vito")
    anna.post(f"/targets/{target_id}/share", {"username": "vito", "can_scan": "1"})
    assert vito.get(f"/targets/{target_id}").status_code == 200
    assert vito.post("/scans/new", {"targets": str(target_id), **FAST}, page="/").status_code == 403


def test_share_api_with_scan_permission(app, browser, db, target_id):
    from test_api import _h, _token
    browser("anna").post(f"/targets/{target_id}/share", {"username": "bruno"})
    c, h = app.state.client, _h(_token(browser, "bruno"))
    assert [t["id"] for t in c.get("/api/v1/targets", headers=h).json()["targets"]] == [target_id]
    r = c.post("/api/v1/scans", json={"target_id": target_id}, headers=h)
    assert r.status_code == 403


# ---------------------------------------------------------------- tag

def test_tags(app, browser, db):
    anna = browser("anna")
    a = _new_target(anna, name="Web aula 3", tags="Aula 3, linux")
    b = _new_target(anna, name="Router", host="192.0.2.1", tags="rete")
    with session_scope(db) as s:
        assert s.get(Target, a).tags == ["aula-3", "linux"]
    assert anna.post("/targets/new", {**TARGET, "name": "X", "tags": "<script>"}).status_code == 400
    assert anna.post("/targets/new", {**TARGET, "name": "Y", "tags": ",".join(f"t{i}" for i in range(9))}).status_code == 400
    page = anna.get("/?tag=linux").text
    assert "Web aula 3" in page and "Router" not in page
    assert "Router" in anna.get("/targets?tag=rete").text and "Web aula 3" not in anna.get("/targets?tag=rete").text
    form = anna.get("/scans/new?tag=linux").text
    assert re.search(rf'value="{a}"[^>]*checked', form) and not re.search(rf'value="{b}"[^>]*checked', form)
    assert svc.parse_tags(["A b", "a-b"]) == ["a-b"]


def test_mine_filter_for_admin(app, browser, db, target_id):
    admin = browser("admin")
    _new_target(admin, name="Macchina admin", host="192.0.2.77")
    page = admin.get("/?mine=1").text
    assert "Macchina admin" in page and "Server di prova" not in page


# ---------------------------------------------------------------- registrazione

def _register(app, browser, db, username="nuovo", password="Una-Frase-Lunga-2026"):
    b = browser()
    page = b.get("/register")
    assert page.status_code == 200
    r = b.c.post("/register", data={"csrf": csrf_of(page.text), "username": username, "full_name": "Nuovo Utente",
                                     "password": password, "repeat": password})
    assert r.status_code == 303 and r.headers["location"] == "/register/2fa", r.text
    page = b.get("/register/2fa")
    assert "data:image/svg+xml" in page.text
    with session_scope(db) as s:
        u = s.scalar(select(User).where(User.username == username))
        assert u.approval == "unconfirmed"
        secret = app.state.box.decrypt(u.totp_secret_enc)
    return b, page, secret


def test_registration_needs_2fa_and_approval(app, browser, db):
    b, page, secret = _register(app, browser, db)
    # senza codice valido la registrazione non è completa e non si entra
    assert b.c.post("/register/2fa", data={"csrf": csrf_of(page.text), "code": "000000"}).status_code == 400
    assert browser().login("nuovo", "Una-Frase-Lunga-2026").status_code == 401
    code = totp_code(secret, totp_step())
    r = b.c.post("/register/2fa", data={"csrf": csrf_of(page.text), "code": code})
    assert r.status_code == 200 and "Richiesta inviata" in r.text
    r = browser().login("nuovo", "Una-Frase-Lunga-2026")
    assert r.status_code == 403 and "in attesa" in r.text
    assert browser().login("nuovo", "sbagliata-sbagliata").status_code == 401   # senza password non lo si sa
    admin = browser("admin")
    assert "nuovo" in admin.get("/users").text and "richiesta di registrazione" in admin.get("/").text
    with session_scope(db) as s:
        uid = s.scalar(select(User).where(User.username == "nuovo")).id
        s.scalar(select(User).where(User.username == "nuovo")).totp_last_step = 0
    assert admin.post(f"/users/{uid}/approve", {"role": "admin"}, page="/users").status_code == 303
    with session_scope(db) as s:
        u = s.get(User, uid)
        assert u.approval == "approved" and u.role == "analyst"            # mai admin direttamente
    other = browser()
    assert other.login("nuovo", "Una-Frase-Lunga-2026").headers["location"] == "/login/2fa"
    page = other.get("/login/2fa")
    step = totp_step() + 1
    r = other.c.post("/login/2fa", data={"csrf": csrf_of(page.text), "code": totp_code(secret, step)})
    assert r.status_code == 303 and other.get("/").status_code == 200
    assert other.get("/targets/new").status_code == 200
    r = other.post("/account/2fa/disable", {"password": "Una-Frase-Lunga-2026", "code": "123456"})
    with session_scope(db) as s:
        assert s.get(User, uid).totp_enabled                               # non si disattiva
        actions = [a.action for a in s.scalars(select(AuditLog)).all()]
    assert "register.request" in actions and "register.approve" in actions


def test_registration_rejected(app, browser, db):
    b, page, secret = _register(app, browser, db, "scartato")
    b.c.post("/register/2fa", data={"csrf": csrf_of(page.text), "code": totp_code(secret, totp_step())})
    with session_scope(db) as s:
        uid = s.scalar(select(User).where(User.username == "scartato")).id
    assert browser("admin").post(f"/users/{uid}/reject", page="/users").status_code == 303
    with session_scope(db) as s:
        assert s.get(User, uid) is None


def test_registration_rules(app, browser, db):
    b = browser()
    page = b.get("/register")
    base = {"csrf": csrf_of(page.text), "full_name": "", "password": "Una-Frase-Lunga-2026",
            "repeat": "Una-Frase-Lunga-2026"}
    assert b.c.post("/register", data={**base, "username": "anna"}).status_code == 400          # già usato
    assert b.c.post("/register", data={**base, "username": "A B"}).status_code == 400
    assert b.c.post("/register", data={**base, "username": "corto", "password": "breve"}).status_code == 400
    assert b.c.post("/register", data={**base, "username": "diverso", "repeat": "altro"}).status_code == 400
    for i in range(5):
        c = browser()
        p = c.get("/register")
        c.c.post("/register", data={**base, "csrf": csrf_of(p.text), "username": f"utente{i}"})
    c = browser()
    p = c.get("/register")
    r = c.c.post("/register", data={**base, "csrf": csrf_of(p.text), "username": "utente9"})
    assert r.status_code == 429


def test_registration_can_be_turned_off(app, browser):
    app.state.settings = dataclasses.replace(app.state.settings, registration="off")
    assert browser().get("/register").status_code == 404
    assert "Registrati" not in browser().get("/login").text


def test_unfinished_registration_is_cleaned_up(app, browser, db):
    from datetime import timedelta
    _register(app, browser, db, "lasciato")
    with session_scope(db) as s:
        s.scalar(select(User).where(User.username == "lasciato")).created_at = now() - timedelta(hours=1)
    _register(app, browser, db, "lasciato")                                # il nome torna libero


# ---------------------------------------------------------------- grafici e mappa

def _nmap_scan(db, target_id, score=70):
    scan_id = _done_scan(db, target_id, score=score, options={"external_scan": True})
    with session_scope(db) as s:
        scan = s.get(Scan, scan_id)
        scan.findings += [
            Finding(position=1, title="Porte aperte su x: 3", severity="INFO", area="network", source="nmap:open-ports",
                    evidence="22/tcp ssh\n23/tcp telnet\n8080/tcp <b>http-proxy</b>"),
            Finding(position=2, title="Servizio rischioso esposto: Telnet", severity="HIGH", area="network",
                    source="nmap:port-23", evidence="23/tcp open telnet"),
            Finding(position=3, title="Porte aperte su x: 1", severity="INFO", area="network",
                    source="nmap-external:open-ports", evidence="22/tcp ssh"),
        ]
    return scan_id


def test_open_ports_are_read_from_nmap_results(app, db, target_id):
    scan_id = _nmap_scan(db, target_id)
    with session_scope(db) as s:
        info = svc.open_ports(s, s.get(Scan, scan_id))
    ports = {p["port"]: p for p in info["ports"]}
    assert set(ports) == {22, 23, 8080} and info["ran_internal"] and info["ran_external"]
    assert ports[22]["external"] and ports[22]["internal"] and not ports[23]["external"]
    assert ports[23]["severity"] == "HIGH" and ports[8080]["severity"] is None


def test_charts_pages(app, browser, db, target_id):
    anna = browser("anna")
    with session_scope(db) as s:
        s.get(Target, target_id).tags = ["aula-3"]
    other = _new_target(anna, name="Seconda", host="192.0.2.30", tags="aula-3, linux")
    with session_scope(db) as s:                       # il form non lo permette: difesa in profondità
        s.get(Target, other).name = "<script>alert(1)</script>"
    _done_scan(db, target_id, score=40)
    _nmap_scan(db, target_id, score=70)
    _done_scan(db, other, score=20)
    for url in ("/", "/insights", "/map", f"/targets/{target_id}", "/insights?tag=aula-3", "/map?tag=linux"):
        r = anna.get(url)
        assert r.status_code == 200, url
        assert "<script>alert(1)" not in r.text, url
    page = anna.get("/insights").text
    assert page.count('<svg class="chart') >= 4 and "Confronto tra tag" in page
    assert "Andamento nel tempo" in page
    page = anna.get("/map").text
    assert "netmap" in page and "telnet" in page and "&lt;b&gt;http-proxy" in page
    assert "<b>http-proxy" not in page
    page = anna.get(f"/targets/{target_id}").text
    assert "Andamento del rischio" in page and "Porte aperte" in page and "dall'esterno" in page
    assert 'class="chart spark' in anna.get("/").text


def test_scan_page_has_area_chart(app, browser, db, target_id):
    scan_id = _nmap_scan(db, target_id)
    page = browser("anna").get(f"/scans/{scan_id}").text
    assert "Problemi per area e gravità" in page and 'href="/scans/%d?area=network&amp;severity=HIGH' % scan_id in page

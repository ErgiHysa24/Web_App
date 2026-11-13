"""Difese aggiunte: verifica in due passaggi, reti consentite, sessioni, intestazioni."""
import dataclasses
import time

import pytest
from sqlalchemy import select

from watchdog_web import engine as eng
from watchdog_web import netpolicy
from watchdog_web import services as svc
from watchdog_web.config import parse_networks
from watchdog_web.db import session_scope
from watchdog_web.models import AuditLog, Scan, Target, User
from watchdog_web.security import totp_code, totp_step
from watchdog_web.worker import claim_next

from conftest import PASSWORD, TARGET, csrf_of


def _policy(app, **changes):
    app.state.settings = dataclasses.replace(app.state.settings, **changes)


def _secret(app, db, username):
    with session_scope(db) as s:
        u = s.scalar(select(User).where(User.username == username))
        return app.state.box.decrypt(u.totp_secret_enc)


def _enable_2fa(app, db, b, username):
    page = b.get("/account/2fa")
    assert page.status_code == 200 and "data:image/svg+xml" in page.text
    secret = _secret(app, db, username)
    r = b.c.post("/account/2fa/enable", data={"csrf": csrf_of(page.text), "code": totp_code(secret, totp_step())})
    assert r.status_code == 303, r.text
    return secret


# ---------------------------------------------------------------- verifica in due passaggi

def test_admin_must_set_up_2fa_before_anything_else(app, browser, db):
    _policy(app, require_2fa="admin")
    admin = browser("admin")
    for url in ("/", "/users", "/targets", "/account"):
        r = admin.get(url)
        assert r.status_code == 303 and r.headers["location"] == "/account/2fa", url
    anna = browser("anna")                                  # analista: non obbligatoria
    assert anna.get("/").status_code == 200
    _enable_2fa(app, db, admin, "admin")
    assert admin.get("/users").status_code == 200


def test_login_with_2fa(app, browser, db):
    b = browser("anna")
    secret = _enable_2fa(app, db, b, "anna")
    other = browser()
    assert other.login("anna").headers["location"] == "/login/2fa"
    assert other.get("/").status_code == 303                       # la password da sola non basta
    page = other.get("/login/2fa")
    r = other.c.post("/login/2fa", data={"csrf": csrf_of(page.text), "code": "000000"})
    assert r.status_code == 401
    code = totp_code(secret, totp_step())
    with session_scope(db) as s:                                   # il codice dell'attivazione era già usato
        s.scalar(select(User).where(User.username == "anna")).totp_last_step = totp_step() - 2
    r = other.c.post("/login/2fa", data={"csrf": csrf_of(page.text), "code": code})
    assert r.status_code == 303 and other.get("/").status_code == 200
    # lo stesso codice non vale una seconda volta
    third = browser()
    third.login("anna")
    page = third.get("/login/2fa")
    assert third.c.post("/login/2fa", data={"csrf": csrf_of(page.text), "code": code}).status_code == 401


def test_enabling_2fa_closes_other_sessions(app, browser, db):
    a, b = browser("anna"), browser("anna")
    _enable_2fa(app, db, a, "anna")
    assert a.get("/").status_code == 200 and b.get("/").status_code == 303


def test_wrong_2fa_codes_lock_the_user(app, browser, db):
    b = browser("anna")
    _enable_2fa(app, db, b, "anna")
    attacker = browser()
    attacker.login("anna")
    page = attacker.get("/login/2fa")
    statuses = [attacker.c.post("/login/2fa", data={"csrf": csrf_of(page.text), "code": "123456"}).status_code
                for _ in range(5)]
    assert statuses[-1] == 429
    with session_scope(db) as s:
        assert s.scalar(select(User).where(User.username == "anna")).locked_until is not None


def test_admin_resets_2fa_and_cli_too(app, browser, db, monkeypatch):
    anna = browser("anna")
    _enable_2fa(app, db, anna, "anna")
    with session_scope(db) as s:
        uid = s.scalar(select(User).where(User.username == "anna")).id
    assert browser("admin").post(f"/users/{uid}/reset-2fa", page="/users").status_code == 303
    assert anna.get("/").status_code == 303                       # sessione chiusa
    fresh = browser()
    assert fresh.login("anna").headers["location"] == "/"          # niente codice: azzerata


def test_disable_2fa_needs_password_and_code(app, browser, db):
    b = browser("anna")
    secret = _enable_2fa(app, db, b, "anna")
    with session_scope(db) as s:
        s.scalar(select(User).where(User.username == "anna")).totp_last_step = 0
    b.post("/account/2fa/disable", {"password": "sbagliata", "code": totp_code(secret, totp_step())})
    with session_scope(db) as s:
        assert s.scalar(select(User).where(User.username == "anna")).totp_enabled
    b.post("/account/2fa/disable", {"password": PASSWORD, "code": totp_code(secret, totp_step())})
    with session_scope(db) as s:
        assert not s.scalar(select(User).where(User.username == "anna")).totp_enabled


def test_2fa_secret_is_encrypted(app, browser, db):
    b = browser("anna")
    secret = _enable_2fa(app, db, b, "anna")
    with session_scope(db) as s:
        stored = s.scalar(select(User).where(User.username == "anna")).totp_secret_enc
    assert stored and secret not in stored


# ---------------------------------------------------------------- accesso

def test_unknown_and_existing_users_look_the_same_when_locked(browser):
    texts = []
    for name in ("anna", "nessuno"):
        b = browser()
        for _ in range(5):
            r = b.login(name, "sbagliata-sbagliata")
        texts.append((r.status_code, r.text.count("Troppi tentativi sbagliati per questo utente")))
    assert texts[0] == texts[1] == (429, 1)


def test_idle_session_expires(app, browser):
    b = browser("anna")
    assert b.get("/").status_code == 200
    _policy(app, idle_minutes=0)
    time.sleep(1.1)
    assert b.get("/").status_code == 303


def test_status_polling_does_not_keep_session_alive(app, browser, monkeypatch):
    b = browser("anna")
    start = time.time()
    monkeypatch.setattr(time, "time", lambda: start + 20 * 60)
    assert b.get("/status.json").status_code == 200
    monkeypatch.setattr(time, "time", lambda: start + 40 * 60)     # 40 minuti dall'ultima pagina vera
    assert b.get("/").status_code == 303


def test_cross_origin_post_is_refused(browser):
    b = browser("anna")
    token = csrf_of(b.get("/account").text)
    r = b.c.post("/account/tokens/new", data={"csrf": token, "name": "x"},
                 headers={"Origin": "https://sito-cattivo.example"})
    assert r.status_code == 400
    r = b.c.post("/account/tokens/new", data={"csrf": token, "name": "x"}, headers={"Origin": "http://testserver"})
    assert r.status_code == 303


def test_large_request_body_is_refused(browser):
    b = browser("anna")
    r = b.c.post("/targets/new", content=b"x" * (300 * 1024), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413


def test_headers_and_secure_cookie_with_https(app, browser):
    r = browser().get("/login")
    assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert "strict-transport-security" not in r.headers
    assert app.state.client.get("/healthz").json() == {"status": "ok"}


def test_https_settings(settings, monkeypatch):
    from fastapi.testclient import TestClient
    from watchdog_web.app import create_app
    app = create_app(dataclasses.replace(settings, https_only=True))
    with TestClient(app, base_url="https://testserver") as c:
        r = c.get("/login")
        hsts = r.headers["strict-transport-security"]
        assert hsts.startswith("max-age=") and "includesubdomains" in hsts.lower()
        assert "browsing-topics=()" in r.headers["permissions-policy"]
        cookie = r.headers["set-cookie"].lower()
        assert cookie.startswith("__host-watchdog=") and "secure" in cookie and "path=/" in cookie


# ---------------------------------------------------------------- reti consentite

NETS = parse_networks("192.168.0.0/16,10.0.0.0/8")


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost", "0.0.0.0", "169.254.169.254", "fe80::1",
                                  "224.0.0.1", "8.8.8.8", "2001:4860:4860::8888", "db", "WEB", "::ffff:127.0.0.1"])
def test_hosts_that_are_never_allowed(host):
    with pytest.raises(netpolicy.HostNotAllowed):
        netpolicy.check_host(host, NETS, ("db", "web"), resolve=True)


def test_allowed_hosts():
    assert netpolicy.check_host("192.168.1.20", NETS, (), resolve=True) == ["192.168.1.20"]
    assert netpolicy.check_host("server.lab", NETS, (), resolve=False) == []       # controllato alla scansione
    with pytest.raises(netpolicy.HostNotAllowed, match="non si risolve"):
        netpolicy.check_host("non-esiste.invalid", NETS, (), resolve=True)
    with pytest.raises(Exception):
        parse_networks("non-una-rete")
    assert len(parse_networks("*")) == 2


def test_name_resolving_outside_allowed_networks_fails_at_scan_time(app, browser, db, monkeypatch):
    r = browser("anna").post("/targets/new", {**TARGET, "host": "server.lab"})
    assert r.status_code == 303                                     # il nome non si controlla al salvataggio
    tid = int(r.headers["location"].rsplit("/", 1)[1])
    monkeypatch.setattr(netpolicy, "_resolve", lambda name: [netpolicy._ip("8.8.8.8")] if name == "server.lab" else [])
    with session_scope(db) as s:
        scan_id = svc.enqueue_scan(s, s.get(Target, tid), None, "native").id
    with session_scope(db) as s:
        claim_next(s, "w")
    eng.run_scan(scan_id, db, app.state.settings, app.state.box)
    with session_scope(db) as s:
        scan = s.get(Scan, scan_id)
        assert scan.status == "failed" and "Obiettivo non consentito" in scan.error and "8.8.8.8" in scan.error


def test_scan_connects_to_the_checked_address(app, browser, db, monkeypatch):
    from conftest import FakeSSH
    r = browser("anna").post("/targets/new", {**TARGET, "host": "server.lab"})
    tid = int(r.headers["location"].rsplit("/", 1)[1])
    monkeypatch.setattr(netpolicy, "_resolve", lambda name: [netpolicy._ip("10.1.2.3")] if name == "server.lab" else [])
    with session_scope(db) as s:
        scan_id = svc.enqueue_scan(s, s.get(Target, tid), None, "custom", ["kernel"]).id
    with session_scope(db) as s:
        claim_next(s, "w")
    eng.run_scan(scan_id, db, app.state.settings, app.state.box)
    assert FakeSSH.seen[-1]["host"] == "10.1.2.3"


def test_audit_records_2fa_events(app, browser, db):
    _enable_2fa(app, db, browser("anna"), "anna")
    with session_scope(db) as s:
        assert "2fa.enable" in [a.action for a in s.scalars(select(AuditLog)).all()]


def test_existing_database_gets_the_new_columns(app):
    """Chi aveva già installato la prima versione: all'avvio le colonne nuove vengono aggiunte."""
    from sqlalchemy import inspect, text
    from watchdog_web.db import ADDED_COLUMNS, init_schema
    engine = app.state.engine
    with engine.begin() as conn:
        for table, column, _ in ADDED_COLUMNS:
            conn.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
    init_schema(engine)
    init_schema(engine)                                            # una seconda volta non fa nulla
    insp = inspect(engine)
    for table, column, _ in ADDED_COLUMNS:
        assert column in {c["name"] for c in insp.get_columns(table)}
    with session_scope(app.state.db) as s:
        assert s.scalar(select(User).where(User.username == "anna")).totp_enabled is False

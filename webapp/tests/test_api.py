import re

from sqlalchemy import select

from watchdog_web.db import session_scope
from watchdog_web.models import ApiToken, Scan

from test_scans import _run_all


def _token(browser, username: str, scope: str = "scan", days: str = "90") -> str:
    b = browser(username)
    assert b.post("/account/tokens/new", {"name": "test", "scope": scope, "days": days}).status_code == 303
    page = b.get("/account").text
    token = re.search(r'class="token">(wd_[^<]+)<', page).group(1)
    assert token not in b.get("/account").text          # mostrato una volta sola
    return token


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_api_needs_a_valid_token(app, browser, db):
    c = app.state.client
    assert c.get("/api/v1/targets").status_code == 401
    assert c.get("/api/v1/targets", headers=_h("wd_inventato")).status_code == 401
    token = _token(browser, "anna")
    me = c.get("/api/v1/me", headers=_h(token)).json()
    assert me["username"] == "anna" and me["read_only"] is False and me["expires_at"]
    with session_scope(db) as s:
        row = s.scalar(select(ApiToken))
        assert token not in (row.token_hash, row.prefix) and len(row.token_hash) == 64
        row.revoked = True
    assert c.get("/api/v1/me", headers=_h(token)).status_code == 401


def test_api_session_cookie_is_not_enough(browser):
    assert browser("anna").get("/api/v1/targets").status_code == 401


def test_api_full_flow(app, browser, db):
    c, h = app.state.client, _h(_token(browser, "anna"))
    body = {"name": "Da API", "host": "192.0.2.20", "ssh_user": "root", "secret": "password-ssh"}
    r = c.post("/api/v1/targets", json=body, headers=h)
    assert r.status_code == 201 and "secret" not in r.json() and "password-ssh" not in r.text
    assert c.post("/api/v1/targets", json=body, headers=h).status_code == 400            # nome già usato
    assert c.post("/api/v1/targets", json={**body, "name": "x", "host": "a b"}, headers=h).status_code == 400
    assert c.post("/api/v1/scans", json={"target": "non esiste"}, headers=h).status_code == 404
    r = c.post("/api/v1/scans", json={"target": "da api", "preset": "custom", "tools": ["kernel"]}, headers=h)
    assert r.status_code == 202 and r.json()["status"] == "queued"
    scan_id = r.json()["id"]
    assert c.get(f"/api/v1/scans/{scan_id}/findings", headers=h).status_code == 409        # non ancora finita
    _run_all(app)
    r = c.get(f"/api/v1/scans/{scan_id}", headers=h).json()
    assert r["status"] == "done" and "incomplete_checks" in r and r["risk_score"] is not None
    r = c.get(f"/api/v1/scans/{scan_id}/findings", headers=h).json()
    assert r["findings"] and {"title", "severity", "area", "references"} <= set(r["findings"][0])
    assert c.get(f"/api/v1/scans/{scan_id}/report?format=json", headers=h).json()["findings"] is not None
    assert c.get("/api/v1/scans?status=done", headers=h).json()["scans"][0]["id"] == scan_id
    assert c.get("/api/v1/targets", headers=h).json()["targets"][0]["last_scan"]["id"] == scan_id
    assert c.post(f"/api/v1/scans/{scan_id}/cancel", headers=h).status_code == 409
    assert c.get("/api/v1/openapi.json").status_code == 401             # lo schema solo col token
    assert c.get("/api/v1/openapi.json", headers=h).json()["paths"]


def test_api_viewer_token_cannot_start_scans(app, browser, db, target_id):
    c, h = app.state.client, _h(_token(browser, "vito"))
    assert c.get("/api/v1/targets", headers=h).status_code == 200
    assert c.post("/api/v1/scans", json={"target_id": target_id}, headers=h).status_code == 403
    with session_scope(db) as s:
        assert s.scalars(select(Scan)).all() == []


def test_read_only_token(app, browser, db, target_id):
    c, h = app.state.client, _h(_token(browser, "anna", scope="read"))
    assert c.get("/api/v1/me", headers=h).json()["read_only"] is True
    assert c.get("/api/v1/targets", headers=h).status_code == 200
    r = c.post("/api/v1/scans", json={"target_id": target_id}, headers=h)
    assert r.status_code == 403 and "sola lettura" in r.json()["error"]


def test_token_without_scope_is_read_only(app, browser):
    b = browser("anna")
    b.post("/account/tokens/new", {"name": "senza scelta"})
    token = re.search(r'class="token">(wd_[^<]+)<', b.get("/account").text).group(1)
    assert app.state.client.get("/api/v1/me", headers=_h(token)).json()["read_only"] is True


def test_expired_token_is_refused(app, browser, db):
    from datetime import timedelta
    from watchdog_web.models import now
    c, token = app.state.client, _token(browser, "anna")
    assert c.get("/api/v1/me", headers=_h(token)).status_code == 200
    with session_scope(db) as s:
        s.scalar(select(ApiToken)).expires_at = now() - timedelta(minutes=1)
    assert c.get("/api/v1/me", headers=_h(token)).status_code == 401
    assert "Scaduto" in browser("anna").get("/account").text


def test_api_cannot_create_targets_outside_allowed_networks(app, browser):
    c, h = app.state.client, _h(_token(browser, "anna"))
    for host in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "localhost", "db"):
        body = {"name": f"x-{host}", "host": host, "ssh_user": "root", "secret": "password-ssh"}
        r = c.post("/api/v1/targets", json=body, headers=h)
        assert r.status_code == 400, (host, r.text)

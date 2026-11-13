from sqlalchemy import select

from watchdog_web.db import session_scope
from watchdog_web.models import AuditLog, User

from conftest import PASSWORD, csrf_of


def test_pages_require_login(browser):
    b = browser()
    for url in ("/", "/targets", "/scans", "/users", "/audit", "/account", "/scans/1/report"):
        r = b.get(url)
        assert r.status_code == 303 and r.headers["location"] == "/login", url
    assert b.get("/status.json").status_code == 303


def test_login_and_logout(browser):
    b = browser()
    assert b.login("anna", "sbagliata-sbagliata").status_code == 401
    assert b.login("nessuno").status_code == 401
    assert b.login("anna").status_code == 303
    assert b.get("/").status_code == 200
    assert b.post("/logout").status_code == 303
    assert b.get("/").status_code == 303


def test_login_does_not_reveal_which_users_exist(browser):
    a = browser().login("anna", "sbagliata-sbagliata").text
    b = browser().login("inesistente", "sbagliata-sbagliata").text
    assert "Nome utente o password non corretti." in a and "Nome utente o password non corretti." in b


def test_lockout_after_repeated_failures(browser, db):
    b = browser()
    statuses = [b.login("anna", "sbagliata-sbagliata").status_code for _ in range(5)]
    assert statuses == [401, 401, 401, 401, 429]                 # al quinto errore scatta il blocco
    r = b.login("anna")                       # password giusta, ma l'utente è bloccato
    assert r.status_code == 429 and "Troppi tentativi sbagliati" in r.text
    with session_scope(db) as s:
        actions = [a.action for a in s.scalars(select(AuditLog)).all()]
    assert "login.lockout" in actions and "login.locked" in actions


def test_post_without_csrf_token_is_rejected(browser):
    b = browser("anna")
    r = b.c.post("/targets/new", data={"name": "x", "host": "h", "ssh_user": "u", "secret_password": "p"})
    assert r.status_code == 400
    r = b.c.post("/logout", data={"csrf": "inventato"})
    assert r.status_code == 400 and b.get("/").status_code == 200


def test_roles(browser, target_id):
    viewer, analyst, admin = browser("vito"), browser("anna"), browser("admin")
    assert viewer.get("/targets").status_code == 200
    assert viewer.get("/targets/new").status_code == 403
    assert viewer.post("/scans/new", {"targets": str(target_id), "preset": "native"}).status_code == 403
    assert analyst.get("/targets/new").status_code == 200
    assert analyst.get("/users").status_code == 403
    assert viewer.post(f"/targets/{target_id}/delete").status_code == 403    # il proprietario può
    assert admin.get("/users").status_code == 200 and admin.get("/audit").status_code == 200


def test_admin_creates_user_and_password_reset_closes_sessions(browser):
    admin = browser("admin")
    r = admin.post("/users/new", {"username": "luca", "full_name": "Luca", "role": "analyst", "password": "corta"})
    assert r.status_code == 400
    r = admin.post("/users/new", {"username": "luca", "full_name": "Luca", "role": "analyst",
                                  "password": "Nuova-Frase-Segreta-77"})
    assert r.status_code == 303
    luca = browser()
    assert luca.login("luca", "Nuova-Frase-Segreta-77").status_code == 303
    # password scelta dall'amministratore: prima di tutto va cambiata
    r = luca.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/account/password-change"
    assert luca.get("/targets").headers["location"] == "/account/password-change"
    r = luca.post("/account/password", {"current": "Nuova-Frase-Segreta-77", "new": "Nuova-Frase-Segreta-77",
                                        "repeat": "Nuova-Frase-Segreta-77"}, page="/account/password-change")
    assert r.status_code == 400 and "diversa" in r.text
    r = luca.post("/account/password", {"current": "Nuova-Frase-Segreta-77", "new": "Scelta-Personale-2026",
                                        "repeat": "Scelta-Personale-2026"}, page="/account/password-change")
    assert r.status_code == 303
    assert luca.get("/").status_code == 200
    uid = [u for u in _users(admin) if u[1] == "luca"][0][0]
    admin.post(f"/users/{uid}/edit", {"role": "analyst", "active": "1", "password": "Altra-Frase-Lunga-88"})
    assert luca.get("/").status_code == 303                   # la vecchia sessione non vale più
    again = browser()
    assert again.login("luca", "Altra-Frase-Lunga-88").status_code == 303
    assert again.get("/").headers["location"] == "/account/password-change"   # reimpostata dall'admin
    admin.post(f"/users/{uid}/edit", {"role": "analyst"})     # senza "active": disattivato
    assert browser().login("luca", "Altra-Frase-Lunga-88").status_code == 401


def _users(admin):
    with session_scope(admin.c.app.state.db) as s:
        return [(u.id, u.username) for u in s.scalars(select(User)).all()]


def test_last_admin_cannot_be_demoted(browser):
    admin = browser("admin")
    uid = [u for u in _users(admin) if u[1] == "admin"][0][0]
    admin.post(f"/users/{uid}/edit", {"role": "viewer", "active": "1"})
    assert admin.get("/users").status_code == 200


def test_change_own_password(browser):
    b, other = browser("anna"), browser("anna")
    r = b.post("/account/password", {"current": "errata", "new": "Nuova-Frase-Segreta-77", "repeat": "Nuova-Frase-Segreta-77"})
    assert r.status_code == 400
    r = b.post("/account/password", {"current": PASSWORD, "new": "Nuova-Frase-Segreta-77", "repeat": "Nuova-Frase-Segreta-77"})
    assert r.status_code == 303
    assert b.get("/").status_code == 200 and other.get("/").status_code == 303


def test_security_headers(browser):
    r = browser().get("/login")
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=lax" in r.headers["set-cookie"].lower()
    assert csrf_of(r.text)

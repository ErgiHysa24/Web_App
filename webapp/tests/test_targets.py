import io

import paramiko
from sqlalchemy import select

from watchdog_web.db import session_scope
from watchdog_web.models import Target

from conftest import TARGET


def _target(db, target_id) -> Target:
    with session_scope(db) as s:
        return s.get(Target, target_id)


def test_credentials_are_encrypted_and_never_shown(app, browser, db, target_id):
    t = _target(db, target_id)
    assert t.secret_enc and "segretissima-ssh" not in t.secret_enc
    assert app.state.box.decrypt(t.secret_enc) == "segretissima-ssh"
    b = browser("anna")
    for url in (f"/targets/{target_id}", f"/targets/{target_id}/edit", "/targets"):
        assert "segretissima-ssh" not in b.get(url).text


def test_edit_keeps_secret_and_new_host_forgets_host_key(app, browser, db, target_id):
    with session_scope(db) as s:
        s.get(Target, target_id).host_key = "ssh-ed25519 AAAA"
    b = browser("anna")
    data = {**TARGET, "secret_password": "", "notes": "aula 3"}
    assert b.post(f"/targets/{target_id}/edit", data).status_code == 303
    t = _target(db, target_id)
    assert app.state.box.decrypt(t.secret_enc) == "segretissima-ssh" and t.host_key and t.notes == "aula 3"
    assert b.post(f"/targets/{target_id}/edit", {**data, "host": "192.0.2.99"}).status_code == 303
    assert _target(db, target_id).host_key == ""


def test_invalid_targets_are_rejected(browser, target_id):
    b = browser("anna")
    bad = [{"host": "10.0.0.1; rm -rf /"}, {"host": "-oProxyCommand=x"}, {"port": "70000"}, {"ssh_user": "a b"},
           {"name": TARGET["name"]}, {"secret_password": ""}, {"name": ""}]
    for change in bad:
        r = b.post("/targets/new", {**TARGET, "name": "Altro", **change})
        assert r.status_code == 400, change


def test_private_key_validation(browser, db):
    b = browser("anna")
    key = paramiko.RSAKey.generate(2048)
    plain, locked = io.StringIO(), io.StringIO()
    key.write_private_key(plain)
    key.write_private_key(locked, password="passphrase")
    base = {**TARGET, "auth_method": "key", "secret_password": ""}
    assert b.post("/targets/new", {**base, "secret_key": "non è una chiave"}).status_code == 400
    r = b.post("/targets/new", {**base, "secret_key": locked.getvalue()})
    assert r.status_code == 400 and "passphrase" in r.text
    assert b.post("/targets/new", {**base, "secret_key": plain.getvalue()}).status_code == 303
    with session_scope(db) as s:
        t = s.scalar(select(Target))
        assert t.auth_method == "key" and "PRIVATE KEY" not in t.secret_enc


def test_archive_and_delete(browser, db, target_id):
    anna, admin = browser("anna"), browser("admin")
    assert anna.post(f"/targets/{target_id}/archive", {"archived": "1"}).status_code == 303
    assert _target(db, target_id).archived
    r = anna.post("/scans/new", {"targets": str(target_id), "preset": "native"})
    assert r.status_code == 400 and "archiviato" in r.text
    assert admin.post(f"/targets/{target_id}/delete").status_code == 303
    assert _target(db, target_id) is None

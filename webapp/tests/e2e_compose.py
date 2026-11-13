"""Prova completa contro l'applicazione avviata con docker compose (usata dalla CI).

Fa quello che farebbe una persona e poi uno strumento esterno: accesso dal browser in
HTTPS con attivazione della verifica in due passaggi, creazione di un token, obiettivo e
scansione via API, attesa del risultato, report.

    python e2e_compose.py https://127.0.0.1:8443 admin PASSWORD host-ssh porta utente password
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import re
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

base, admin, admin_password, ssh_host, ssh_port, ssh_user, ssh_password = sys.argv[1:8]
# Il certificato è firmato dalla CA locale del proxy: qui non serve verificarlo.
tls = ssl.create_default_context()
tls.check_hostname = False
tls.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), urllib.request.HTTPSHandler(context=tls))
api_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls))


def totp(secret: str) -> str:
    secret = secret.replace(" ", "")
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time() // 30)), hashlib.sha1).digest()
    o = mac[-1] & 15
    return str((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)


def page(path: str, data: dict | None = None) -> str:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    with web.open(base + path, body, timeout=30) as r:
        return r.read().decode()


def csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def api(token: str, method: str, path: str, body: dict | None = None, raw: bool = False):
    req = urllib.request.Request(base + "/api/v1" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with api_opener.open(req, timeout=60) as r:
        data = r.read()
        return data if raw else json.loads(data)


html = page("/login", {"username": admin, "password": admin_password, "csrf": csrf(page("/login"))})
assert "Attiva la verifica in due passaggi" in html, "l'amministratore deve attivare la 2FA prima di tutto"
secret = re.search(r'class="token">([A-Z2-7 ]+)<', html).group(1)
html = page("/account/2fa/enable", {"code": totp(secret), "csrf": csrf(html)})
assert "Quadro generale" in html, "attivazione della 2FA non riuscita"
print("accesso con attivazione della verifica in due passaggi: ok")
html = page("/account/tokens/new", {"name": "ci", "scope": "scan", "days": "30", "csrf": csrf(page("/account"))})
token = re.search(r'class="token">(wd_[^<]+)<', html).group(1)
print("accesso e token: ok")

target = api(token, "POST", "/targets", {"name": "Target di prova", "host": ssh_host, "port": int(ssh_port),
                                         "ssh_user": ssh_user, "secret": ssh_password})
# Due scansioni insieme sullo stesso obiettivo: la seconda deve aspettare la prima.
first = api(token, "POST", "/scans", {"target_id": target["id"], "preset": "native"})
second = api(token, "POST", "/scans", {"target_id": target["id"], "preset": "custom",
                                       "tools": ["linux", "users", "ssh_config", "nmap"]})
seen_together = False
deadline = time.time() + 900
while time.time() < deadline:
    a, b = (api(token, "GET", f"/scans/{x['id']}") for x in (first, second))
    seen_together |= a["status"] == "running" and b["status"] == "running"
    print(f"  #{a['id']} {a['status']} {a['progress']}% {a['current_step']} | #{b['id']} {b['status']} {b['progress']}%")
    if a["status"] not in ("queued", "running") and b["status"] not in ("queued", "running"):
        break
    time.sleep(5)
assert a["status"] == "done", a
assert b["status"] == "done", b
assert not seen_together, "due scansioni in corso sullo stesso obiettivo"
assert a["risk_score"] is not None and a["system"], a
print(f"scansione nativa: rischio {a['risk_score']}/100 su {a['system']}, {a['incomplete_checks']} controlli non completati")

findings = api(token, "GET", f"/scans/{first['id']}/findings")["findings"]
assert len(findings) > 5, len(findings)
assert any(f["references"] for f in findings)
report = json.loads(api(token, "GET", f"/scans/{first['id']}/report?format=json", raw=True))
assert report["metadata"]["host"]["family"] == "debian", report["metadata"]["host"]
tools = api(token, "GET", f"/scans/{second['id']}?log=true")
assert "nmap" in tools["tools"] and "nmap" in tools["log"].lower(), tools["log"]
assert json.loads(api(token, "GET", f"/scans/{second['id']}/report?format=json", raw=True))["cleanup_status"] == "SUCCESS"
assert api(token, "GET", f"/targets/{target['id']}")["host_key_known"] is True

html = page(f"/scans/{first['id']}?severity=ALL")
# (la password del target di prova coincide col nome utente "monitor", che nei risultati compare:
# che le credenziali non vengano mai mostrate lo verificano i test con una password univoca)
assert "Problemi per area e gravità" in html or "Risultati per area" in html
assert "<html" in page(f"/scans/{first['id']}/report").lower()
assert "Cosa è cambiato" in page(f"/compare?a={first['id']}&b={second['id']}")
assert "Target di prova" in page("/")
print(f"tutto ok: {len(findings)} risultati, report e confronto disponibili")

# Registrazione con 2FA e approvazione, poi isolamento: il nuovo utente non vede le macchine dell'admin.
jar2 = http.cookiejar.CookieJar()
other = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar2), urllib.request.HTTPSHandler(context=tls))


def page2(path: str, data: dict | None = None) -> str:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    with other.open(base + path, body, timeout=30) as r:
        return r.read().decode()


html = page2("/register", {"username": "studente1", "full_name": "Studente Uno", "password": "Frase-Lunga-Studente-1",
                            "repeat": "Frase-Lunga-Studente-1", "csrf": csrf(page2("/register"))})
reg_secret = re.search(r'class="token">([A-Z2-7 ]+)<', html).group(1)
html = page2("/register/2fa", {"code": totp(reg_secret), "csrf": csrf(html)})
assert "Richiesta inviata" in html, "registrazione non completata"
users = page("/users")
uid = re.search(r'action="/users/(\d+)/approve"', users).group(1)
page(f"/users/{uid}/approve", {"role": "analyst", "csrf": csrf(users)})
time.sleep(31)                              # il codice della registrazione non si può riusare: aspetto il prossimo
html = page2("/login", {"username": "studente1", "password": "Frase-Lunga-Studente-1", "csrf": csrf(page2("/login"))})
html = page2("/login/2fa", {"code": totp(reg_secret), "csrf": csrf(html)})
assert "Quadro generale" in html, "accesso del nuovo utente non riuscito"
assert "Target di prova" not in html and "Target di prova" not in page2("/targets"), "vede le macchine di altri"
print("registrazione, approvazione e isolamento tra utenti: ok")

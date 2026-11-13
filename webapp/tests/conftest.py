"""Ambiente dei test: database vuoto a ogni test (SQLite su file, o PostgreSQL se
WATCHDOG_TEST_DATABASE_URL è impostata) e un finto collegamento SSH che esegue i comandi
sulla macchina dei test."""
from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

from risk_assessor.executor import LocalExecutor
from watchdog_web import engine as eng
from watchdog_web.app import create_app
from watchdog_web.config import Settings, parse_networks
from watchdog_web.db import Base, session_scope
from watchdog_web.models import User
from watchdog_web.security import hash_password

PASSWORD = "Prova-Sicura-2026"


class FakeSSH(LocalExecutor):
    """Stessa interfaccia di SSHExecutor, ma i comandi girano in locale."""
    host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake"
    fail_with: str | None = None
    seen: list[dict] = []

    def __init__(self, **kwargs) -> None:
        super().__init__()
        FakeSSH.seen.append(kwargs)
        self.server_host_key = None

    def connect(self) -> None:
        from risk_assessor.executor import SSHConnectionError
        if FakeSSH.fail_with:
            raise SSHConnectionError(FakeSSH.fail_with)
        self.server_host_key = FakeSSH.host_key


@pytest.fixture()
def settings(tmp_path) -> Settings:
    url = os.environ.get("WATCHDOG_TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}"
    # 2FA non obbligatoria nei test generici: i test dedicati la attivano.
    return Settings(database_url=url, secret_key="t" * 48, reports_dir=tmp_path / "reports",
                    worker_concurrency=2, https_only=False, session_hours=8, scan_timeout_minutes=90,
                    require_2fa="none", allowed_networks=parse_networks("192.0.2.0/24,10.0.0.0/8"))


@pytest.fixture()
def app(settings, monkeypatch):
    application = create_app(settings)
    Base.metadata.drop_all(application.state.engine)
    FakeSSH.fail_with, FakeSSH.seen = None, []
    monkeypatch.setattr(eng, "SSHExecutor", FakeSSH)
    with TestClient(application) as client:
        application.state.client = client
        with session_scope(application.state.db) as s:
            for name, role in (("admin", "admin"), ("anna", "analyst"), ("bruno", "analyst"), ("vito", "viewer")):
                s.add(User(username=name, role=role, password_hash=hash_password(PASSWORD)))
        yield application
    Base.metadata.drop_all(application.state.engine)
    application.state.engine.dispose()


@pytest.fixture()
def db(app):
    return app.state.db


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


class Browser:
    """Un utente col suo browser: tiene i cookie e aggiunge il token CSRF ai moduli."""

    def __init__(self, app) -> None:
        self.c = TestClient(app, follow_redirects=False)

    def login(self, username: str, password: str = PASSWORD):
        page = self.c.get("/login")
        return self.c.post("/login", data={"username": username, "password": password, "csrf": csrf_of(page.text)})

    def get(self, url: str, **kw):
        return self.c.get(url, **kw)

    def post(self, url: str, data: dict | None = None, page: str = "/account"):
        token = csrf_of(self.c.get(page).text)
        return self.c.post(url, data={**(data or {}), "csrf": token})


@pytest.fixture()
def browser(app):
    def make(username: str | None = None) -> Browser:
        b = Browser(app)
        if username:
            assert b.login(username).status_code == 303
        return b
    return make


TARGET = {"name": "Server di prova", "host": "192.0.2.10", "port": "22", "ssh_user": "studente",
          "auth_method": "password", "secret_password": "segretissima-ssh", "sudo_password": "", "notes": ""}


@pytest.fixture()
def target_id(browser) -> int:
    r = browser("anna").post("/targets/new", TARGET)
    assert r.status_code == 303, r.text
    return int(r.headers["location"].rsplit("/", 1)[1])

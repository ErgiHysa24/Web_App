"""Più host in una volta: inventario YAML, esecuzione in parallelo, riepilogo complessivo.

Formato dell'inventario (vedi docs/inventory.example.yaml):

    defaults:              # valori comuni (facoltativo)
      user: monitor
      port: 22
      key: ~/.ssh/id_ed25519
    hosts:
      - host: 192.168.1.10
        name: web-01       # facoltativo, per i report
      - host: db.example.lan
        user: admin
        password_env: DB_SSH_PASSWORD
        tools: [linux, lynis]

Le password non stanno mai nel file: si indicano solo i NOMI delle variabili d'ambiente
(`password_env`, `sudo_password_env`). Ogni host usa una propria connessione SSH; un host
irraggiungibile non ferma gli altri.
"""
from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import yaml

from risk_assessor.models import Assessment

MAX_PARALLEL = 16
_ALLOWED_KEYS = {"host", "name", "user", "port", "key", "password_env", "sudo_password_env",
                 "accept_new_host_key", "tools", "external_scan"}
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]+$")


class InventoryError(ValueError):
    """Inventario non valido: il messaggio dice cosa correggere."""


@dataclass
class FleetHost:
    host: str
    user: str
    name: str = ""
    port: int = 22
    key: str | None = None
    password_env: str | None = None
    sudo_password_env: str | None = None
    accept_new_host_key: bool = False
    tools: list[str] | None = None
    external_scan: bool = False

    @property
    def label(self) -> str:
        return self.name or self.host


@dataclass
class HostResult:
    host: FleetHost
    assessment: Assessment | None = None
    error: str = ""
    reports: list[Path] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.assessment is not None


def _as_tools(value, where: str) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list):
        items = [str(v) for v in value]
    else:
        raise InventoryError(f"{where}: 'tools' deve essere una lista o una stringa separata da virgole")
    tools = [t.strip().lower() for t in items if t.strip()]
    return tools or None


def load_inventory(path: str | Path) -> list[FleetHost]:
    """Legge e valida l'inventario. Solleva InventoryError con un messaggio chiaro."""
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise InventoryError(f"inventario non leggibile: {e}") from e
    except yaml.YAMLError as e:
        raise InventoryError(f"inventario non valido (YAML): {e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), list) or not data["hosts"]:
        raise InventoryError("l'inventario deve contenere una lista 'hosts' non vuota")
    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise InventoryError("'defaults' deve essere un elenco di chiavi e valori")
    if {"password", "sudo_password"} & set(defaults):
        raise InventoryError("defaults: le password non vanno nell'inventario: usare password_env")
    unknown = set(defaults) - _ALLOWED_KEYS
    if unknown:
        raise InventoryError(f"defaults: chiavi sconosciute: {', '.join(sorted(unknown))}")

    hosts: list[FleetHost] = []
    seen: set[tuple[str, int]] = set()
    for i, raw in enumerate(data["hosts"], 1):
        where = f"hosts[{i}]"
        if isinstance(raw, str):
            raw = {"host": raw}
        if not isinstance(raw, dict):
            raise InventoryError(f"{where}: atteso un host (stringa o elenco di chiavi)")
        if {"password", "sudo_password"} & set(raw):
            raise InventoryError(f"{where}: le password non vanno nell'inventario: usare "
                                 "password_env / sudo_password_env con il nome di una variabile d'ambiente")
        unknown = set(raw) - _ALLOWED_KEYS
        if unknown:
            raise InventoryError(f"{where}: chiavi sconosciute: {', '.join(sorted(unknown))}")
        entry = {**{k: v for k, v in defaults.items() if k not in ("host", "name")}, **raw}
        host = str(entry.get("host") or "").strip()
        if not host or not _HOST.match(host) or host.startswith("-"):
            raise InventoryError(f"{where}: 'host' mancante o non valido")
        user = str(entry.get("user") or "").strip()
        if not user or user.startswith("-") or any(c.isspace() for c in user):
            raise InventoryError(f"{where} ({host}): 'user' mancante o non valido")
        try:
            port = int(entry.get("port", 22))
        except (TypeError, ValueError):
            raise InventoryError(f"{where} ({host}): 'port' deve essere un numero") from None
        if not 1 <= port <= 65535:
            raise InventoryError(f"{where} ({host}): 'port' fuori intervallo")
        for env_key in ("password_env", "sudo_password_env"):
            name = entry.get(env_key)
            if name is not None and not _ENV_NAME.match(str(name)):
                raise InventoryError(f"{where} ({host}): '{env_key}' deve essere il NOME di una "
                                     "variabile d'ambiente (le password non vanno nel file)")
        if (host, port) in seen:
            raise InventoryError(f"{where}: host duplicato {host}:{port}")
        seen.add((host, port))
        key = entry.get("key")
        hosts.append(FleetHost(
            host=host, user=user, name=str(entry.get("name") or "").strip(), port=port,
            key=os.path.expanduser(str(key)) if key else None,
            password_env=entry.get("password_env"), sudo_password_env=entry.get("sudo_password_env"),
            accept_new_host_key=bool(entry.get("accept_new_host_key", False)),
            tools=_as_tools(entry.get("tools"), where), external_scan=bool(entry.get("external_scan", False)),
        ))
    return hosts


def run_fleet(hosts: list[FleetHost], run_one: Callable[[FleetHost], HostResult],
              parallel: int = 4, on_done: Callable[[HostResult, int, int], None] | None = None
              ) -> list[HostResult]:
    """Esegue `run_one` su ogni host, al massimo `parallel` alla volta. Ordine dell'inventario."""
    parallel = max(1, min(MAX_PARALLEL, int(parallel), len(hosts)))
    results: dict[int, HostResult] = {}

    def wrapped(h: FleetHost) -> HostResult:
        start = time.monotonic()
        try:
            r = run_one(h)
        except Exception as e:   # un host non deve mai fermare gli altri
            r = HostResult(h, error=f"{type(e).__name__}: {e}")
        r.seconds = time.monotonic() - start
        return r

    with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="watchdog-host") as pool:
        futures = {pool.submit(wrapped, h): i for i, h in enumerate(hosts)}
        try:
            for done, fut in enumerate(as_completed(futures), 1):
                r = fut.result()
                results[futures[fut]] = r
                if on_done is not None:
                    on_done(r, done, len(hosts))
        except KeyboardInterrupt:
            # Gli host in attesa non partono; quelli in corso finiscono (con la pulizia dei tool).
            pool.shutdown(wait=True, cancel_futures=True)
            raise
    return [results[i] for i in range(len(hosts))]

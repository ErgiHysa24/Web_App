"""Impostazioni, lette dalle variabili d'ambiente (vedi .env.example).

Nessun segreto ha un valore predefinito utilizzabile: senza WATCHDOG_SECRET_KEY
l'applicazione non parte, così non può finire in laboratorio con una chiave nota.
"""
from __future__ import annotations

import os
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

# Reti private (RFC 1918 e IPv6 locali): di default si analizzano solo macchine della rete locale.
DEFAULT_ALLOWED_NETWORKS = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
# Nomi dei servizi dell'applicazione stessa: non sono mai obiettivi validi.
DEFAULT_DENIED_HOSTS = "db,web,worker,proxy"


class ConfigError(RuntimeError):
    """Configurazione mancante o non valida: il messaggio dice cosa impostare."""


def _int(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} deve essere un numero intero") from None
    return max(low, min(high, value))


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "si", "sì")


def _choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
    raw = os.environ.get(name, "").strip().lower() or default
    if raw not in allowed:
        raise ConfigError(f"{name} deve essere uno tra: {', '.join(allowed)}")
    return raw


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str                 # firma dei cookie di sessione e cifratura delle credenziali
    reports_dir: Path               # report HTML/JSON/MD di ogni scansione
    worker_concurrency: int         # scansioni contemporanee per worker
    https_only: bool                # cookie "Secure": solo se la app è servita in HTTPS
    session_hours: int
    scan_timeout_minutes: int       # oltre questo tempo una scansione è considerata bloccata
    idle_minutes: int = 30          # sessione chiusa dopo questo tempo senza attività
    require_2fa: str = "all"        # chi deve usare la verifica in due passaggi: admin | all | none
    registration: str = "approval"  # approval = ci si registra e un amministratore approva; off = solo admin
    allowed_networks: tuple = field(default_factory=lambda: parse_networks(DEFAULT_ALLOWED_NETWORKS))
    denied_hosts: tuple = tuple(DEFAULT_DENIED_HOSTS.split(","))

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


def parse_networks(raw: str) -> tuple:
    """"10.0.0.0/8, 192.168.1.0/24" -> reti. "*" = qualsiasi indirizzo (sconsigliato)."""
    nets = []
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part == "*":
            return (ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0"))
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ConfigError(f"WATCHDOG_ALLOWED_NETWORKS: «{part}» non è una rete valida "
                              "(esempio: 192.168.1.0/24)") from None
    if not nets:
        raise ConfigError("WATCHDOG_ALLOWED_NETWORKS è vuota: indica almeno una rete")
    return tuple(nets)


def load_settings() -> Settings:
    secret = os.environ.get("WATCHDOG_SECRET_KEY", "").strip()
    if len(secret) < 32:
        raise ConfigError(
            "WATCHDOG_SECRET_KEY mancante o troppo corta (minimo 32 caratteri). "
            "Generala con: python -c \"import secrets; print(secrets.token_urlsafe(48))\"")
    url = os.environ.get("WATCHDOG_DATABASE_URL", "").strip()
    if not url:
        raise ConfigError("WATCHDOG_DATABASE_URL mancante, per esempio "
                          "postgresql+psycopg://watchdog:PASSWORD@db:5432/watchdog")
    return Settings(
        database_url=url,
        secret_key=secret,
        reports_dir=Path(os.environ.get("WATCHDOG_REPORTS_DIR", "/data/reports")),
        worker_concurrency=_int("WATCHDOG_WORKER_CONCURRENCY", 2, 1, 8),
        https_only=_bool("WATCHDOG_HTTPS_ONLY", False),
        session_hours=_int("WATCHDOG_SESSION_HOURS", 8, 1, 72),
        scan_timeout_minutes=_int("WATCHDOG_SCAN_TIMEOUT_MINUTES", 90, 10, 600),
        idle_minutes=_int("WATCHDOG_IDLE_MINUTES", 30, 5, 480),
        require_2fa=_choice("WATCHDOG_REQUIRE_2FA", "all", ("admin", "all", "none")),
        registration=_choice("WATCHDOG_REGISTRATION", "approval", ("approval", "off")),
        allowed_networks=parse_networks(os.environ.get("WATCHDOG_ALLOWED_NETWORKS", "") or DEFAULT_ALLOWED_NETWORKS),
        denied_hosts=tuple(h.strip().lower() for h in
                           (os.environ.get("WATCHDOG_DENIED_HOSTS") or DEFAULT_DENIED_HOSTS).split(",") if h.strip()),
    )

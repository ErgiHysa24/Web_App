"""Prepara il file .env di WatchDog Web. Funziona su Linux, macOS, Raspberry Pi e Windows.

    python3 setup_env.py        (su Windows: python setup_env.py)

- Se .env non c'è, lo crea con chiavi casuali e con i nomi e gli indirizzi di questo
  computer per il certificato HTTPS.
- Se .env c'è già, non cambia nessun valore: aggiunge solo le impostazioni che mancano
  (per esempio dopo un aggiornamento).
"""
from __future__ import annotations

import os
import re
import secrets
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENV = HERE / ".env"
EXAMPLE = HERE / ".env.example"


def lan_ip() -> str | None:
    """Indirizzo di questo computer nella rete locale (non invia nulla in rete)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") else ip
    except OSError:
        return None
    finally:
        s.close()


def server_names(ip: str | None) -> str:
    names = ["localhost", "127.0.0.1"]
    if ip:
        names.append(ip)
    host = socket.gethostname().split(".")[0].lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", host or ""):
        names += [host, f"{host}.local"]
    return ", ".join(dict.fromkeys(names))


def wanted(ip: str | None) -> dict[str, str]:
    return {
        "WATCHDOG_SECRET_KEY": secrets.token_hex(32),
        "POSTGRES_PASSWORD": secrets.token_hex(24),
        "WATCHDOG_SERVER_NAMES": server_names(ip),
        "WATCHDOG_DEFAULT_SNI": ip or "localhost",
    }


def parse(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def main() -> int:
    ip = lan_ip()
    values = wanted(ip)
    template = EXAMPLE.read_text(encoding="utf-8")
    if not ENV.exists():
        text = template
        for key, value in values.items():
            text = re.sub(rf"(?m)^{key}=.*$", lambda _m, k=key, v=value: f"{k}={v}", text)
        old_umask = os.umask(0o077) if hasattr(os, "umask") else None
        try:
            ENV.write_text(text, encoding="utf-8")
        finally:
            if old_umask is not None:
                os.umask(old_umask)
        print("Creato .env con chiavi casuali.")
    else:
        text = ENV.read_text(encoding="utf-8")
        current = parse(text)
        added = []
        defaults = parse(template)
        for key, default in defaults.items():
            if key in current and current[key]:
                continue
            value = values.get(key, default)
            if key in current:
                text = re.sub(rf"(?m)^{key}=.*$", lambda _m, k=key, v=value: f"{k}={v}", text)
            else:
                text = text.rstrip("\n") + f"\n{key}={value}\n"
            added.append(key)
        if added:
            ENV.write_text(text, encoding="utf-8")
            print("Aggiunte a .env le impostazioni mancanti: " + ", ".join(added))
        else:
            print(".env è già completo: nessuna modifica.")
    if hasattr(os, "chmod"):
        try:
            os.chmod(ENV, 0o600)
        except OSError:
            pass
    final = parse(ENV.read_text(encoding="utf-8"))
    port = final.get("WATCHDOG_HTTPS_PORT", "8443")
    print()
    print("Indirizzi per il certificato HTTPS: " + final.get("WATCHDOG_SERVER_NAMES", ""))
    print("Ora:  docker compose up -d --build")
    print("Poi:  docker compose exec web watchdog-web create-admin")
    where = final.get("WATCHDOG_DEFAULT_SNI") or "localhost"
    print(f"Apri: https://localhost:{port}   (da questo computer)")
    if where != "localhost":
        print(f"      https://{where}:{port}   (dagli altri computer della rete)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

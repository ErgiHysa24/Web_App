"""Comandi di amministrazione: watchdog-web <comando>.

  init-db                     crea le tabelle
  create-admin [utente]       crea (o ripristina) un amministratore; chiede la password
  reset-password <utente>     nuova password e sblocco dell'utente
  reset-2fa <utente>          azzera la verifica in due passaggi (telefono perso)
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from watchdog_web.config import ConfigError, load_settings
from watchdog_web.db import init_schema, make_engine, make_session_factory, session_scope
from watchdog_web.models import AuditLog, User
from watchdog_web.security import hash_password, password_problem


def _ask_password(username: str) -> str:
    env = os.environ.get("WATCHDOG_ADMIN_PASSWORD")
    if env:
        problem = password_problem(env, username)
        if problem:
            raise SystemExit(f"WATCHDOG_ADMIN_PASSWORD: {problem}")
        return env
    for _ in range(3):
        first = getpass.getpass("Password: ")
        problem = password_problem(first, username)
        if problem:
            print(problem, file=sys.stderr)
            continue
        if getpass.getpass("Ripeti la password: ") != first:
            print("Le due password non coincidono.", file=sys.stderr)
            continue
        return first
    raise SystemExit("Password non impostata.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchdog-web", description="Amministrazione di WatchDog Web")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="crea le tabelle")
    p = sub.add_parser("create-admin", help="crea o ripristina un amministratore")
    p.add_argument("username", nargs="?", default="admin")
    p = sub.add_parser("reset-password", help="nuova password per un utente")
    p.add_argument("username")
    p = sub.add_parser("reset-2fa", help="azzera la verifica in due passaggi di un utente")
    p.add_argument("username")
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as e:
        print(f"Configurazione: {e}", file=sys.stderr)
        return 2
    engine = make_engine(settings.database_url)
    init_schema(engine)
    if args.command == "init-db":
        print("Tabelle pronte.")
        return 0
    username = args.username.strip().lower()
    factory = make_session_factory(engine)
    with session_scope(factory) as s:
        user = s.scalar(select(User).where(User.username == username))
        if args.command in ("reset-password", "reset-2fa") and user is None:
            print(f"L'utente «{username}» non esiste.", file=sys.stderr)
            return 1
        if args.command == "reset-2fa":
            user.totp_enabled, user.totp_secret_enc, user.totp_last_step = False, "", 0
            user.session_version += 1
            s.add(AuditLog(username="(riga di comando)", action="2fa.reset", detail=username))
            print(f"Verifica in due passaggi di «{username}» azzerata: al prossimo accesso la configurerà di nuovo.")
            return 0
        password = _ask_password(username)
        if user is None:
            s.add(User(username=username, full_name="Amministratore", role="admin",
                       password_hash=hash_password(password)))
            print(f"Amministratore «{username}» creato.")
        else:
            user.password_hash = hash_password(password)
            user.failed_logins, user.locked_until = 0, None
            user.must_change_password = False
            user.session_version += 1
            if args.command == "create-admin":
                user.role, user.active = "admin", True
            print(f"Password di «{username}» aggiornata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Connessione al database (SQLAlchemy 2)."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(url: str):
    if url.startswith("sqlite"):
        # Solo per i test: un database in memoria condiviso tra i thread.
        kwargs = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url in ("sqlite://", "sqlite+pysqlite://"):
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=10)


def make_session_factory(engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Una transazione: commit alla fine, rollback se qualcosa va storto."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


# Colonne aggiunte dopo la prima versione: le tabelle già esistenti le ricevono all'avvio.
# (tabella, colonna, definizione SQL valida sia per PostgreSQL sia per SQLite)
ADDED_COLUMNS = [
    ("users", "must_change_password", "BOOLEAN NOT NULL DEFAULT false"),
    ("users", "totp_secret_enc", "TEXT NOT NULL DEFAULT ''"),
    ("users", "totp_enabled", "BOOLEAN NOT NULL DEFAULT false"),
    ("users", "totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "approval", "VARCHAR(16) NOT NULL DEFAULT 'approved'"),
    ("users", "self_registered", "BOOLEAN NOT NULL DEFAULT false"),
    ("api_tokens", "expires_at", "TIMESTAMP WITH TIME ZONE"),
    ("api_tokens", "read_only", "BOOLEAN NOT NULL DEFAULT false"),
    ("targets", "tags", {"postgresql": "JSONB NOT NULL DEFAULT '[]'::jsonb", "sqlite": "JSON NOT NULL DEFAULT '[]'"}),
]
# Vincoli della prima versione che non valgono più (solo PostgreSQL, dove esistono già).
DROPPED_CONSTRAINTS = [("targets", "targets_name_key")]


def init_schema(engine) -> None:
    """Crea le tabelle che mancano e aggiunge le colonne nuove a quelle esistenti. Web e
    worker partono insieme: su PostgreSQL un lock consultivo fa sì che lo faccia uno alla volta."""
    from sqlalchemy import inspect, text

    import watchdog_web.models  # noqa: F401  (registra le tabelle)
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(727274)"))
        Base.metadata.create_all(conn)
        insp = inspect(conn)
        for table, column, ddl in ADDED_COLUMNS:
            if column not in {c["name"] for c in insp.get_columns(table)}:
                if isinstance(ddl, dict):
                    ddl = ddl[engine.dialect.name]
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_targets_created_by ON targets (created_by)"))
        if engine.dialect.name == "postgresql":
            for table, constraint in DROPPED_CONSTRAINTS:
                conn.execute(text(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint}"))

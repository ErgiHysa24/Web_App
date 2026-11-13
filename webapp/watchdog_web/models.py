"""Tabelle del database.

- users        chi accede, con ruolo (admin, analyst, viewer)
- api_tokens   token personali per l'API (si salva solo l'hash)
- targets      le macchine da analizzare; password e chiavi SSH sono cifrate
- scans        ogni scansione: è anche la coda dei lavori (stato queued -> running -> ...)
- findings     i risultati di ogni scansione, una riga per problema
- audit_log    chi ha fatto cosa e quando
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, false, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from watchdog_web.db import Base

ROLES = ("admin", "analyst", "viewer")
ROLE_LABEL = {"admin": "Amministratore", "analyst": "Analista", "viewer": "Solo lettura"}
SCAN_STATES = ("queued", "running", "done", "failed", "cancelled")
ACTIVE_STATES = ("queued", "running")

JsonType = JSON().with_variant(JSONB(), "postgresql")


def now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Cambia a ogni cambio password o disattivazione: invalida le sessioni aperte.
    session_version: Mapped[int] = mapped_column(Integer, default=1)
    # L'amministratore ha impostato la password: al primo accesso l'utente deve cambiarla.
    # approved = può accedere; pending = registrato, aspetta un amministratore;
    # unconfirmed = registrazione iniziata ma senza verifica in due passaggi confermata.
    approval: Mapped[str] = mapped_column(String(16), default="approved", server_default="approved")
    self_registered: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Verifica in due passaggi: segreto cifrato come le credenziali, ultimo codice usato (anti-riuso).
    totp_secret_enc: Mapped[str] = mapped_column(Text, default="", server_default="")
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    totp_last_step: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tokens: Mapped[list["ApiToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    def can(self, action: str) -> bool:
        """Permessi per ruolo: view < scan (analyst) < admin."""
        if not self.active:
            return False
        level = {"viewer": 1, "analyst": 2, "admin": 3}.get(self.role, 0)
        return level >= {"view": 1, "scan": 2, "admin": 3}[action]


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    prefix: Mapped[str] = mapped_column(String(16), index=True)      # per riconoscerlo nell'elenco
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 del token
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    read_only: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    user: Mapped[User] = relationship(back_populates="tokens")

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        exp = self.expires_at if self.expires_at.tzinfo else self.expires_at.replace(tzinfo=timezone.utc)
        return exp <= now()

    @property
    def usable(self) -> bool:
        return not self.revoked and not self.expired and self.user.active


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Il nome è unico per proprietario (controllato dall'applicazione), non per tutti.
    name: Mapped[str] = mapped_column(String(80))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_user: Mapped[str] = mapped_column(String(64))
    auth_method: Mapped[str] = mapped_column(String(16), default="password")   # password | key
    # Cifrati con la chiave dell'applicazione (Fernet): mai in chiaro nel database.
    secret_enc: Mapped[str] = mapped_column(Text, default="")          # password SSH o chiave privata
    sudo_password_enc: Mapped[str] = mapped_column(Text, default="")
    # Chiave pubblica del server vista alla prima connessione: le successive devono coincidere.
    host_key: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    # Proprietario: chi l'ha creato. Lo vedono solo lui, chi ha una condivisione e gli amministratori.
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
                                                   index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list] = mapped_column(JsonType, default=list)

    scans: Mapped[list["Scan"]] = relationship(back_populates="target")
    owner: Mapped["User | None"] = relationship(foreign_keys=[created_by])
    shares: Mapped[list["TargetShare"]] = relationship(back_populates="target", cascade="all, delete-orphan")

    @property
    def address(self) -> str:
        return f"{self.ssh_user}@{self.host}:{self.port}"


class TargetShare(Base):
    """Un obiettivo condiviso con un altro utente: in sola lettura o anche per avviare scansioni."""
    __tablename__ = "target_shares"
    __table_args__ = (Index("uq_target_shares", "target_id", "user_id", unique=True),)

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    can_scan: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    target: Mapped[Target] = relationship(back_populates="shares")
    user: Mapped["User"] = relationship()


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    preset: Mapped[str] = mapped_column(String(32), default="native")
    tools: Mapped[list] = mapped_column(JsonType, default=list)
    options: Mapped[dict] = mapped_column(JsonType, default=dict)       # no_install, keep_tools, ...
    # avanzamento
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_step: Mapped[str] = mapped_column(String(200), default="")
    log: Mapped[str] = mapped_column(Text, default="")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    worker: Mapped[str] = mapped_column(String(80), default="")
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # tempi
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # risultato
    error: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    system_label: Mapped[str] = mapped_column(String(200), default="")
    counts: Mapped[dict] = mapped_column(JsonType, default=dict)        # per severità
    areas: Mapped[dict] = mapped_column(JsonType, default=dict)         # heatmap: area -> {count, worst}
    incomplete: Mapped[int] = mapped_column(Integer, default=0)         # controlli non completati
    summary: Mapped[dict] = mapped_column(JsonType, default=dict)       # confronto, durate, non applicabili
    report_dir: Mapped[str] = mapped_column(String(500), default="")

    target: Mapped[Target] = relationship(back_populates="scans")
    requester: Mapped[User | None] = relationship()
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target_created", "target_id", "created_at"),
        # Garanzia nel database, anche con più worker: una sola scansione in corso per obiettivo.
        Index("uq_scans_one_running", "target_id", unique=True,
              postgresql_where=text("status = 'running'"), sqlite_where=text("status = 'running'")),
    )

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATES

    @property
    def duration_seconds(self) -> int | None:
        if not self.started_at:
            return None
        end = self.finished_at or now()
        start = self.started_at if self.started_at.tzinfo else self.started_at.replace(tzinfo=timezone.utc)
        end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
        return max(0, int((end - start).total_seconds()))


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)       # ordine nel report (per i link)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    risk: Mapped[int] = mapped_column(Integer, default=0)
    area: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    command: Mapped[str] = mapped_column(Text, default="")
    refs: Mapped[dict] = mapped_column(JsonType, default=dict)      # cis, iso27001, nist, attack

    scan: Mapped[Scan] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")      # resta anche se l'utente viene eliminato
    action: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")

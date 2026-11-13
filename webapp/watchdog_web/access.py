"""Chi vede e chi usa quali obiettivi.

- Amministratore: tutto.
- Gli altri: gli obiettivi che hanno creato e quelli condivisi con loro. Una condivisione
  è in sola lettura o permette anche di avviare scansioni.
- Analista: crea obiettivi propri e li analizza. Solo lettura: vede soltanto ciò che gli
  è stato condiviso.

Le scansioni, i risultati e i report seguono il loro obiettivo. Un obiettivo che l'utente
non può vedere risulta "inesistente": niente messaggi che ne rivelino l'esistenza.
"""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from watchdog_web.models import Scan, Target, TargetShare, User


def visible_filter(user: User):
    """Condizione SQL sugli obiettivi visibili (None = nessun filtro, amministratore)."""
    if user.can("admin"):
        return None
    shared = select(TargetShare.target_id).where(TargetShare.user_id == user.id)
    return or_(Target.created_by == user.id, Target.id.in_(shared))


def targets_query(user: User):
    q = select(Target)
    cond = visible_filter(user)
    return q if cond is None else q.where(cond)


def scans_query(user: User):
    q = select(Scan).join(Target, Scan.target_id == Target.id)
    cond = visible_filter(user)
    return q if cond is None else q.where(cond)


def _share(s: Session, user: User, target: Target) -> TargetShare | None:
    return s.scalar(select(TargetShare).where(TargetShare.target_id == target.id, TargetShare.user_id == user.id))


def can_view(s: Session, user: User, target: Target | None) -> bool:
    if target is None:
        return False
    if user.can("admin") or target.created_by == user.id:
        return True
    return _share(s, user, target) is not None


def can_scan(s: Session, user: User, target: Target | None) -> bool:
    if target is None or not user.can("scan"):
        return False
    if user.can("admin") or target.created_by == user.id:
        return True
    share = _share(s, user, target)
    return share is not None and share.can_scan


def can_manage(user: User, target: Target | None) -> bool:
    """Modificare, condividere, archiviare, eliminare: proprietario o amministratore."""
    if target is None:
        return False
    return user.can("admin") or (user.can("scan") and target.created_by == user.id)

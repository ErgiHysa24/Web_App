"""API REST /api/v1 per gli altri strumenti del laboratorio.

Autenticazione: intestazione `Authorization: Bearer wd_…` con un token creato dal proprio
profilo. Il token ha gli stessi permessi dell'utente che lo ha creato. Le credenziali
degli obiettivi si possono impostare ma non vengono mai restituite.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from watchdog_web import access
from watchdog_web import engine as eng
from watchdog_web import services as svc
from watchdog_web.models import ApiToken, Finding, Scan, Target, User, now
from watchdog_web.security import TOKEN_PREFIX, hash_token
from watchdog_web.views import client_ip, get_db, report_response

router = APIRouter(prefix="/api/v1", tags=["api"])


def api_user(request: Request, s: Session = Depends(get_db)) -> User:
    from watchdog_web.app import NotAuthenticated
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    value = value.strip()
    if scheme.lower() != "bearer" or not value.startswith(TOKEN_PREFIX):
        raise NotAuthenticated()
    token = s.scalar(select(ApiToken).where(ApiToken.token_hash == hash_token(value)))
    if token is None or not token.usable or token.user.approval != "approved":
        raise NotAuthenticated()
    request.state.api_token = token
    # Aggiorno "ultimo uso" al massimo una volta al minuto, per non scrivere a ogni chiamata.
    last = token.last_used_at
    if last is not None and last.tzinfo is None:
        from datetime import timezone
        last = last.replace(tzinfo=timezone.utc)
    if last is None or (now() - last).total_seconds() > 60:
        token.last_used_at = now()
        s.commit()
    return token.user


def api_require(action: str):
    def dep(request: Request, user: User = Depends(api_user)) -> User:
        from watchdog_web.app import Forbidden
        if not user.can(action):
            raise Forbidden("Il tuo ruolo non consente questa operazione.")
        if action != "view" and request.state.api_token.read_only:
            raise Forbidden("Questo token è di sola lettura.")
        return user
    return dep


def _not_found(what: str) -> JSONResponse:
    return JSONResponse({"error": f"{what} non trovato."}, 404)


def _scan_for(s: Session, user: User, scan_id: int, lock: bool = False) -> Scan | None:
    """La scansione, solo se il suo obiettivo è visibile all'utente."""
    q = select(Scan).where(Scan.id == scan_id)
    scan = s.scalar(q.with_for_update() if lock else q)
    return scan if scan is not None and access.can_view(s, user, scan.target) else None


class TargetIn(BaseModel):
    name: str = Field(max_length=80)
    host: str = Field(max_length=255)
    port: int = 22
    ssh_user: str = Field(max_length=64)
    auth_method: Literal["password", "key"] = "password"
    secret: str = Field(description="Password SSH oppure chiave privata (senza passphrase)", max_length=20000)
    sudo_password: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=8)


class ScanIn(BaseModel):
    target_id: int | None = None
    target: str | None = Field(default=None, description="Nome dell'obiettivo, in alternativa a target_id")
    preset: Literal["native", "full", "custom"] = "native"
    tools: list[str] = Field(default_factory=list, description="Solo con preset=custom")
    no_install: bool = False
    keep_tools: bool = False
    external_scan: bool = False
    allow_epel: bool = False


@router.get("/me", summary="Chi sono (verifica del token)")
def me(request: Request, user: User = Depends(api_user)):
    from watchdog_web.services import iso
    token = request.state.api_token
    return {"username": user.username, "role": user.role, "read_only": token.read_only or not user.can("scan"),
            "expires_at": iso(token.expires_at)}


@router.get("/openapi.json", include_in_schema=False)
def openapi(request: Request, user: User = Depends(api_user)):
    """Schema dell'API: solo per chi ha un token valido."""
    return request.app.openapi()


@router.get("/checks", summary="Controlli e tool disponibili")
def checks(user: User = Depends(api_require("view"))):
    return {"native": eng.NATIVE_CHECKS, "external": eng.EXTERNAL_TOOLS, "optional": eng.OPTIONAL_TOOLS,
            "presets": {k: v[1] for k, v in eng.PRESETS.items()}}


@router.get("/targets", summary="Elenco degli obiettivi visibili (propri, condivisi; tutti per l'amministratore)")
def targets(tag: str | None = None, user: User = Depends(api_require("view")), s: Session = Depends(get_db)):
    rows = s.scalars(access.targets_query(user).where(Target.archived.is_(False))
                     .order_by(func.lower(Target.name))).all()
    if tag:
        rows = [t for t in rows if tag.strip().lower() in (t.tags or [])]
    latest = svc.latest_done(s, [t.id for t in rows])
    out = []
    for t in rows:
        d = svc.target_to_dict(t)
        d["last_scan"] = svc.scan_to_dict(latest[t.id]) if t.id in latest else None
        out.append(d)
    return {"targets": out}


@router.post("/targets", status_code=201, summary="Crea un obiettivo")
def target_create(body: TargetIn, request: Request, user: User = Depends(api_require("scan")),
                  s: Session = Depends(get_db)):
    target = Target()
    try:
        svc.apply_target_fields(s, request.app.state.box, target, {**body.model_dump(), "_owner_id": user.id}, new=True,
                                settings=request.app.state.settings)
    except svc.Invalid as e:
        return JSONResponse({"error": str(e)}, 400)
    target.created_by = user.id
    s.add(target)
    s.flush()
    svc.audit(s, user, "target.create", f"{target.name} ({target.address}) via API", client_ip(request))
    s.commit()
    return svc.target_to_dict(target)


@router.get("/targets/{target_id}", summary="Un obiettivo")
def target_get(target_id: int, user: User = Depends(api_require("view")), s: Session = Depends(get_db)):
    t = s.get(Target, target_id)
    return svc.target_to_dict(t) if access.can_view(s, user, t) else _not_found("Obiettivo")


@router.post("/scans", status_code=202, summary="Avvia una scansione (va in coda)")
def scan_create(body: ScanIn, request: Request, user: User = Depends(api_require("scan")),
                s: Session = Depends(get_db)):
    target = None
    if body.target_id is not None:
        target = s.get(Target, body.target_id)
    elif body.target:
        # Per nome: prima i propri, poi gli altri visibili (condivisi o, per l'amministratore, tutti).
        candidates = s.scalars(access.targets_query(user)
                               .where(func.lower(Target.name) == body.target.strip().lower())).all()
        candidates.sort(key=lambda t: t.created_by != user.id)
        if len(candidates) > 1 and candidates[0].created_by != user.id:
            return JSONResponse({"error": "Più obiettivi visibili hanno questo nome: usa target_id."}, 409)
        target = candidates[0] if candidates else None
    if not access.can_view(s, user, target):
        return _not_found("Obiettivo")
    if not access.can_scan(s, user, target):
        return JSONResponse({"error": "Puoi vedere questo obiettivo ma non avviare scansioni."}, 403)
    try:
        scan = svc.enqueue_scan(s, target, user, body.preset, body.tools, body.model_dump())
    except svc.Invalid as e:
        return JSONResponse({"error": str(e)}, 409 if "in coda" in str(e) else 400)
    svc.audit(s, user, "scan.start", f"#{scan.id} {target.name} ({body.preset}) via API", client_ip(request))
    s.commit()
    return svc.scan_to_dict(scan)


@router.get("/scans", summary="Elenco delle scansioni (le più recenti prima)")
def scans(target_id: int | None = None, status: str | None = None, limit: int = 50,
          user: User = Depends(api_require("view")), s: Session = Depends(get_db)):
    q = access.scans_query(user)
    if target_id is not None:
        q = q.where(Scan.target_id == target_id)
    if status:
        q = q.where(Scan.status == status)
    rows = s.scalars(q.order_by(Scan.id.desc()).limit(max(1, min(200, limit)))).all()
    return {"scans": [svc.scan_to_dict(x) for x in rows]}


@router.get("/scans/{scan_id}", summary="Stato e riepilogo di una scansione")
def scan_get(scan_id: int, log: bool = False, user: User = Depends(api_require("view")),
             s: Session = Depends(get_db)):
    scan = _scan_for(s, user, scan_id)
    return svc.scan_to_dict(scan, log=log) if scan else _not_found("Scansione")


@router.post("/scans/{scan_id}/cancel", summary="Annulla una scansione in coda o in corso")
def scan_cancel(scan_id: int, request: Request, user: User = Depends(api_require("scan")),
                s: Session = Depends(get_db)):
    scan = _scan_for(s, user, scan_id, lock=True)
    if scan is None:
        return _not_found("Scansione")
    if not access.can_scan(s, user, scan.target):
        return JSONResponse({"error": "Puoi vedere questa scansione ma non annullarla."}, 403)
    if not svc.request_cancel(s, scan):
        return JSONResponse({"error": "La scansione è già finita."}, 409)
    svc.audit(s, user, "scan.cancel", f"#{scan.id} via API", client_ip(request))
    s.commit()
    return svc.scan_to_dict(scan)


@router.get("/scans/{scan_id}/findings", summary="Risultati di una scansione completata")
def scan_findings(scan_id: int, severity: str | None = None, area: str | None = None,
                  user: User = Depends(api_require("view")), s: Session = Depends(get_db)):
    scan = _scan_for(s, user, scan_id)
    if scan is None:
        return _not_found("Scansione")
    if scan.status != "done":
        return JSONResponse({"error": f"La scansione non è completata (stato: {scan.status})."}, 409)
    q = select(Finding).where(Finding.scan_id == scan.id)
    if severity:
        q = q.where(Finding.severity == severity.upper())
    if area:
        q = q.where(Finding.area == area)
    rows = s.scalars(q.order_by(Finding.position)).all()
    return {"scan": svc.scan_to_dict(scan), "findings": [svc.finding_to_dict(f) for f in rows]}


@router.get("/scans/{scan_id}/report", summary="Report completo (format = json, md, html)")
def scan_report(scan_id: int, request: Request, format: str = "json",
                user: User = Depends(api_require("view")), s: Session = Depends(get_db)):
    scan = _scan_for(s, user, scan_id)
    if scan is None:
        return _not_found("Scansione")
    return report_response(request, scan, format, True)

"""Pagine dell'applicazione (HTML generato dal server)."""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from watchdog_web import __version__, access
from watchdog_web import engine as eng
from watchdog_web import services as svc
from watchdog_web.models import (ACTIVE_STATES, ROLE_LABEL, ROLES, ApiToken, AuditLog, Finding, Scan, Target,
                                 TargetShare, User, now)
from watchdog_web.security import (DUMMY_HASH, hash_password, hash_token, new_api_token, new_csrf_token,
                                   new_totp_secret, password_problem, totp_match, totp_qr_data_uri, totp_uri,
                                   verify_password)

router = APIRouter(include_in_schema=False)

LOCK_AFTER = 5                      # tentativi sbagliati prima del blocco dell'utente
LOCK_MINUTES = 15
IP_WINDOW_SECONDS = 15 * 60
IP_MAX_FAILURES = 20                # tentativi sbagliati dallo stesso indirizzo nella finestra
PAGE_SIZE = 50
PENDING_2FA_SECONDS = 300           # tempo per inserire il codice dopo la password
TOKEN_DAYS = (30, 90, 365)
# Pagine raggiungibili da chi deve ancora cambiare la password o attivare la verifica in due passaggi.
PASSWORD_PAGES = ("/account/password-change", "/account/password", "/logout")
TWO_FA_PAGES = ("/account/2fa", "/account/2fa/enable", "/logout")
# Il report completo contiene testo che arriva dai sistemi analizzati: sandbox senza
# "allow-same-origin", quindi non può leggere cookie né chiamare l'applicazione.
REPORT_CSP = ("sandbox allow-scripts allow-popups; default-src 'none'; style-src 'unsafe-inline'; "
              "script-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'")
REPORT_FILES = {"html": ("assessment.html", "text/html; charset=utf-8"),
                "json": ("assessment.json", "application/json"),
                "md": ("assessment.md", "text/markdown; charset=utf-8")}


# --------------------------------------------------------------------------- dipendenze

def get_db(request: Request):
    s = request.app.state.db()
    try:
        yield s
    finally:
        s.rollback()        # ogni modifica è confermata esplicitamente con commit()
        s.close()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def needs_2fa(user: User, settings) -> bool:
    """La politica richiede la verifica in due passaggi per questo utente?
    Chi si è registrato da solo l'ha attivata alla registrazione e la tiene sempre."""
    return (settings.require_2fa == "all" or user.self_registered
            or (settings.require_2fa == "admin" and user.role == "admin"))


def get_user(request: Request, s: Session = Depends(get_db)) -> User:
    from watchdog_web.app import NotAuthenticated, RedirectTo
    settings = request.app.state.settings
    uid = request.session.get("uid")
    if not uid:
        raise NotAuthenticated()
    user = s.get(User, uid)
    if (user is None or not user.active or user.approval != "approved"
            or user.session_version != request.session.get("sv")):
        request.session.clear()
        raise NotAuthenticated()
    # Inattività: il controllo automatico dello stato (status.json) non conta come attività.
    now_ts = int(time.time())
    if now_ts - int(request.session.get("seen", 0)) > settings.idle_minutes * 60:
        request.session.clear()
        flash(request, "Sessione chiusa dopo un periodo di inattività: accedi di nuovo.", "warn")
        raise NotAuthenticated()
    path = request.url.path
    if not path.endswith("status.json"):
        request.session["seen"] = now_ts
    if user.must_change_password and path not in PASSWORD_PAGES:
        raise RedirectTo("/account/password-change")
    if needs_2fa(user, settings) and not user.totp_enabled and path not in TWO_FA_PAGES + PASSWORD_PAGES:
        raise RedirectTo("/account/2fa")
    return user


def require(action: str):
    def dep(user: User = Depends(get_user)) -> User:
        from watchdog_web.app import Forbidden
        if not user.can(action):
            raise Forbidden()
        return user
    return dep


async def checked_form(request: Request) -> FormData:
    """Legge il modulo e verifica il token CSRF legato alla sessione."""
    from watchdog_web.app import BadRequest
    import hmac
    from urllib.parse import urlsplit
    # Difesa in più oltre al token: se il browser dichiara da dove arriva la richiesta,
    # deve arrivare da questa stessa applicazione.
    origin = request.headers.get("origin")
    if origin is not None and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
        raise BadRequest("Richiesta arrivata da un'altra pagina: per sicurezza non è stata eseguita.")
    form = await request.form()
    expected = request.session.get("csrf") or ""
    got = str(form.get("csrf", ""))
    if not expected or not hmac.compare_digest(expected, got):
        raise BadRequest("La pagina è scaduta: torna indietro, ricaricala e riprova.")
    return form


def flash(request: Request, text: str, kind: str = "ok") -> None:
    request.session["flash"] = [kind, text]


def render(request: Request, name: str, user: User | None, status_code: int = 200, **ctx):
    if not request.session.get("csrf"):
        request.session["csrf"] = new_csrf_token()
    ctx.update(user=user, csrf=request.session["csrf"], flash=request.session.pop("flash", None),
               version=__version__, path=request.url.path,
               registration_open=request.app.state.settings.registration == "approval")
    return request.app.state.templates.TemplateResponse(request, name, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def _get_or_404(s: Session, model, ident: int):
    from watchdog_web.app import BadRequest
    obj = s.get(model, ident)
    if obj is None:
        raise BadRequest("Questo elemento non esiste più.")
    return obj


# --------------------------------------------------------------------------- filtri dei template

_TZ = None


def _tz():
    global _TZ
    if _TZ is None:
        try:
            _TZ = ZoneInfo(os.environ.get("WATCHDOG_TIMEZONE", "Europe/Rome"))
        except Exception:
            _TZ = timezone.utc
    return _TZ


def fmt_dt(value: datetime | None, short: bool = False) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    local = value.astimezone(_tz())
    return local.strftime("%d/%m %H:%M" if short else "%d/%m/%Y %H:%M")


def fmt_duration(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds} s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m} min {s:02d} s"
    h, m = divmod(m, 60)
    return f"{h} h {m:02d} min"


def register_filters(templates) -> None:
    env = templates.env
    env.filters["dt"] = fmt_dt
    env.filters["duration"] = fmt_duration
    from watchdog_web import charts
    env.globals["sparkline"] = charts.sparkline
    env.globals.update(SEVERITIES=svc.SEVERITIES, SEVERITY_LABEL=svc.SEVERITY_LABEL,
                       STATUS_LABEL=svc.STATUS_LABEL, ROLE_LABEL=ROLE_LABEL, AREA_SHORT=svc.AREA_SHORT, AREA_HEAD=svc.AREA_HEAD,
                       HEATMAP_AREAS=svc.HEATMAP_AREAS, PRESETS=eng.PRESETS, OPTION_LABELS=svc.OPTION_LABELS)


# --------------------------------------------------------------------------- accesso

@router.get("/login")
def login_page(request: Request, s: Session = Depends(get_db)):
    if request.session.get("uid"):
        return redirect("/")
    first_run = s.scalar(select(func.count()).select_from(User).where(User.approval == "approved")) == 0
    for key in ("pending_uid", "pending_sv", "pending_at"):
        request.session.pop(key, None)
    return render(request, "login.html", None, first_run=first_run, error=None, username="")


def _ip_blocked(request: Request) -> bool:
    attempts = request.app.state.login_attempts
    cutoff = time.monotonic() - IP_WINDOW_SECONDS
    recent = [t for t in attempts.get(client_ip(request), []) if t > cutoff]
    attempts[client_ip(request)] = recent
    return len(recent) >= IP_MAX_FAILURES


def _recent(bucket: dict, key: str, window: int = IP_WINDOW_SECONDS) -> list[float]:
    cutoff = time.monotonic() - window
    recent = [x for x in bucket.get(key, []) if x > cutoff]
    bucket[key] = recent
    return recent


LOCKED_MESSAGE = f"Troppi tentativi sbagliati per questo utente: riprova tra {LOCK_MINUTES} minuti."


def _register_failure(request: Request, s: Session, user: User | None, username: str, what: str) -> bool:
    """Conta un tentativo sbagliato. True se ora l'utente è bloccato.

    Anche i nomi che non esistono vengono "bloccati" allo stesso modo, così il messaggio
    non rivela quali utenti esistono."""
    ip = client_ip(request)
    request.app.state.login_attempts.setdefault(ip, []).append(time.monotonic())
    if user is None:
        attempts = request.app.state.unknown_attempts.setdefault(username, [])
        attempts.append(time.monotonic())
        svc.audit(s, None, "login.failed", "utente inesistente", ip, username=username)
        return len(_recent(request.app.state.unknown_attempts, username, LOCK_MINUTES * 60)) >= LOCK_AFTER
    user.failed_logins += 1
    if user.failed_logins >= LOCK_AFTER:
        user.locked_until = now() + timedelta(minutes=LOCK_MINUTES)
        user.failed_logins = 0
        svc.audit(s, user, "login.lockout", f"{what}: bloccato per {LOCK_MINUTES} minuti", ip)
        return True
    svc.audit(s, user, "login.failed", what, ip)
    return False


def _is_locked(request: Request, user: User | None, username: str) -> bool:
    if user is None:
        return len(_recent(request.app.state.unknown_attempts, username, LOCK_MINUTES * 60)) >= LOCK_AFTER
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until is not None and locked_until > now()


def _start_session(request: Request, s: Session, user: User) -> RedirectResponse:
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now()
    svc.audit(s, user, "login.ok", "con verifica in due passaggi" if user.totp_enabled else "", client_ip(request))
    s.commit()
    request.session.clear()                          # nuova sessione: niente riuso di quella anonima
    request.session.update(uid=user.id, sv=user.session_version, csrf=new_csrf_token(), seen=int(time.time()))
    return redirect("/")


@router.post("/login")
def login(request: Request, form: FormData = Depends(checked_form), s: Session = Depends(get_db)):
    username = str(form.get("username", "")).strip().lower()[:64]
    password = str(form.get("password", ""))[:300]
    generic = "Nome utente o password non corretti."

    def failed(message: str, status: int = 401):
        s.commit()
        return render(request, "login.html", None, status_code=status, first_run=False,
                      error=message, username=username)

    if _ip_blocked(request):
        return render(request, "login.html", None, status_code=429, first_run=False, username=username,
                      error="Troppi tentativi da questo computer. Riprova tra un quarto d'ora.")
    user = s.scalar(select(User).where(User.username == username))
    if _is_locked(request, user, username):
        verify_password(password, DUMMY_HASH)       # stesso tempo di risposta in ogni caso
        svc.audit(s, user, "login.locked", "", client_ip(request), username=username)
        return failed(LOCKED_MESSAGE, 429)
    ok = verify_password(password, user.password_hash if user else DUMMY_HASH) and user is not None and user.active
    if not ok or user.approval == "unconfirmed":
        locked = _register_failure(request, s, user, username, "password errata")
        return failed(LOCKED_MESSAGE if locked else generic, 429 if locked else 401)
    if user.approval == "pending":
        # Solo chi conosce la password scopre che la richiesta è in attesa.
        s.commit()
        return render(request, "login.html", None, status_code=403, first_run=False, username=username,
                      error="La tua registrazione è in attesa: un amministratore deve ancora approvarla.")
    if user.totp_enabled:
        # Password giusta: manca il codice. La sessione non è ancora valida per nessuna pagina.
        request.session.clear()
        request.session.update(pending_uid=user.id, pending_sv=user.session_version,
                               pending_at=int(time.time()), csrf=new_csrf_token())
        s.commit()
        return redirect("/login/2fa")
    return _start_session(request, s, user)


def _pending_user(request: Request, s: Session) -> User | None:
    uid = request.session.get("pending_uid")
    if not uid or time.time() - int(request.session.get("pending_at", 0)) > PENDING_2FA_SECONDS:
        return None
    user = s.get(User, uid)
    if user is None or not user.active or not user.totp_enabled or user.session_version != request.session.get("pending_sv"):
        return None
    return user


@router.get("/login/2fa")
def login_2fa_page(request: Request, s: Session = Depends(get_db)):
    if _pending_user(request, s) is None:
        request.session.clear()
        return redirect("/login")
    return render(request, "login_2fa.html", None, error=None)


@router.post("/login/2fa")
def login_2fa(request: Request, form: FormData = Depends(checked_form), s: Session = Depends(get_db)):
    user = _pending_user(request, s)
    if user is None:
        request.session.clear()
        flash(request, "Tempo scaduto: inserisci di nuovo nome utente e password.", "warn")
        return redirect("/login")
    if _ip_blocked(request) or _is_locked(request, user, user.username):
        request.session.clear()
        s.commit()
        return render(request, "login.html", None, status_code=429, first_run=False, username=user.username,
                      error=LOCKED_MESSAGE)
    step = totp_match(request.app.state.box.decrypt(user.totp_secret_enc), str(form.get("code", "")),
                      user.totp_last_step)
    if step is None:
        locked = _register_failure(request, s, user, user.username, "codice di verifica errato")
        s.commit()
        if locked:
            request.session.clear()
            return render(request, "login.html", None, status_code=429, first_run=False, username=user.username,
                          error=LOCKED_MESSAGE)
        return render(request, "login_2fa.html", None, status_code=401,
                      error="Codice non valido o già usato. Aspetta quello successivo e riprova.")
    user.totp_last_step = step
    return _start_session(request, s, user)


@router.post("/logout")
def logout(request: Request, form: FormData = Depends(checked_form)):
    request.session.clear()
    return redirect("/login")


# --------------------------------------------------------------------------- accesso agli obiettivi

def _not_found():
    from watchdog_web.app import BadRequest
    return BadRequest("Questo elemento non esiste o non è tra i tuoi.")


def visible_target(s: Session, user: User, target_id: int, need: str = "view") -> Target:
    """L'obiettivo, se l'utente può vederlo (need=view), analizzarlo (scan) o gestirlo (manage).
    Altrimenti "non esiste": non si rivela che esiste un obiettivo di qualcun altro."""
    from watchdog_web.app import Forbidden
    target = s.get(Target, target_id)
    if not access.can_view(s, user, target):
        raise _not_found()
    if need == "scan" and not access.can_scan(s, user, target):
        raise Forbidden("Puoi vedere questo obiettivo ma non avviare scansioni.")
    if need == "manage" and not access.can_manage(user, target):
        raise Forbidden("Solo il proprietario o un amministratore può modificare questo obiettivo.")
    return target


def visible_scan(s: Session, user: User, scan_id: int, need: str = "view", lock: bool = False) -> Scan:
    q = select(Scan).where(Scan.id == scan_id)
    scan = s.scalar(q.with_for_update() if lock else q)
    if scan is None or not access.can_view(s, user, scan.target):
        raise _not_found()
    visible_target(s, user, scan.target_id, need)
    return scan


def _filtered_targets(s: Session, user: User, tag: str = "", mine: bool = False, archived: bool = False):
    q = access.targets_query(user).where(Target.archived.is_(archived)).order_by(func.lower(Target.name))
    if mine:
        q = q.where(Target.created_by == user.id)
    targets = s.scalars(q).all()
    tags = svc.all_tags(targets)
    if tag:
        targets = [t for t in targets if tag in (t.tags or [])]
    return targets, tags


# --------------------------------------------------------------------------- quadro generale

def _dashboard_data(s: Session, user: User, tag: str, mine: bool) -> dict:
    targets, tags = _filtered_targets(s, user, tag, mine)
    ids = [t.id for t in targets]
    latest = svc.latest_done(s, ids)
    history = svc.score_history(s, ids)
    active = s.scalars(access.scans_query(user).where(Scan.status.in_(ACTIVE_STATES)).order_by(Scan.id)).all()
    active_by_target: dict[int, Scan] = {}
    for scan in active:
        if scan.target_id not in active_by_target or scan.status == "running":
            active_by_target[scan.target_id] = scan
    rows = [{"target": t, "scan": latest.get(t.id), "active": active_by_target.get(t.id),
             "history": history.get(t.id, []), "can_scan": access.can_scan(s, user, t)} for t in targets]
    # In alto i sistemi messi peggio; quelli mai analizzati in fondo.
    rows.sort(key=lambda r: (r["scan"] is None, -(r["scan"].risk_score or 0) if r["scan"] else 0,
                             r["target"].name.lower()))
    recent = s.scalars(access.scans_query(user).where(Scan.status.notin_(ACTIVE_STATES))
                       .order_by(Scan.id.desc()).limit(8)).all()
    totals = {sev: 0 for sev in svc.SEVERITIES}
    for scan in latest.values():
        for sev, n in (scan.counts or {}).items():
            if sev in totals:
                totals[sev] += int(n)
    pending = s.scalar(select(func.count()).select_from(User).where(User.approval == "pending")) \
        if user.can("admin") else 0
    return {"rows": rows, "active": active, "recent": recent, "totals": totals, "tags": tags, "tag": tag,
            "breakdowns": svc.area_breakdowns(s, [x.id for x in latest.values()]),
            "mine": mine, "analysed": len(latest), "incomplete": sum(1 for x in latest.values() if x.incomplete),
            "pending_registrations": pending}


@router.get("/")
def dashboard(request: Request, tag: str = "", mine: int = 0, user: User = Depends(require("view")),
              s: Session = Depends(get_db)):
    return render(request, "dashboard.html", user, **_dashboard_data(s, user, tag.strip().lower(), bool(mine)))


@router.get("/status.json")
def status_json(user: User = Depends(require("view")), s: Session = Depends(get_db)):
    """Per l'aggiornamento automatico della coda nel quadro generale."""
    active = s.scalars(access.scans_query(user).where(Scan.status.in_(ACTIVE_STATES)).order_by(Scan.id)).all()
    last_done = s.scalar(access.scans_query(user).with_only_columns(func.max(Scan.id))
                         .where(Scan.status.notin_(ACTIVE_STATES)))
    return {"active": [{"id": x.id, "target": x.target.name, "status": x.status, "progress": x.progress,
                        "step": x.current_step} for x in active], "last_finished": last_done or 0}


# --------------------------------------------------------------------------- obiettivi

@router.get("/targets")
def targets_page(request: Request, archived: int = 0, tag: str = "", mine: int = 0,
                 user: User = Depends(require("view")), s: Session = Depends(get_db)):
    targets, tags = _filtered_targets(s, user, tag.strip().lower(), bool(mine), bool(archived))
    return render(request, "targets.html", user, targets=targets, latest=svc.latest_done(s, [t.id for t in targets]),
                  archived=bool(archived), tags=tags, tag=tag.strip().lower(), mine=bool(mine))


@router.get("/targets/new")
def target_new_page(request: Request, user: User = Depends(require("scan"))):
    return render(request, "target_form.html", user, target=None, values={"port": 22, "auth_method": "password"},
                  error=None)


def _save_target(request: Request, form: FormData, user: User, s: Session, target: Target, new: bool):
    data = dict(form)
    data["secret"] = data.pop("secret_key", "") if data.get("auth_method") == "key" else data.pop("secret_password", "")
    data.pop("secret_key", None), data.pop("secret_password", None)
    data["_owner_id"] = user.id
    try:
        svc.apply_target_fields(s, request.app.state.box, target, data, new=new,
                                settings=request.app.state.settings)
    except svc.Invalid as e:
        s.rollback()
        data.pop("secret", None), data.pop("sudo_password", None)
        data["tags"] = str(form.get("tags", ""))
        return render(request, "target_form.html", user, status_code=400, target=None if new else target,
                      values=data, error=str(e))
    if new:
        target.created_by = user.id
        s.add(target)
    s.flush()
    svc.audit(s, user, "target.create" if new else "target.update", f"{target.name} ({target.address})",
              client_ip(request))
    s.commit()
    flash(request, f"Obiettivo «{target.name}» salvato.")
    return redirect(f"/targets/{target.id}")


@router.post("/targets/new")
def target_new(request: Request, form: FormData = Depends(checked_form), user: User = Depends(require("scan")),
               s: Session = Depends(get_db)):
    return _save_target(request, form, user, s, Target(), True)


@router.get("/targets/{target_id}")
def target_page(request: Request, target_id: int, user: User = Depends(require("view")),
                s: Session = Depends(get_db)):
    from watchdog_web import charts
    target = visible_target(s, user, target_id)
    scans = s.scalars(select(Scan).where(Scan.target_id == target.id).order_by(Scan.id.desc()).limit(30)).all()
    done = [x for x in scans if x.status == "done"]
    history = svc.score_history(s, [target.id], limit=30).get(target.id, [])
    latest = done[0] if done else None
    return render(request, "target.html", user, target=target, scans=scans, done=done,
                  fingerprint=svc.host_key_fingerprint(target.host_key),
                  trend=charts.trend_chart(history, fmt_dt) if len(history) >= 2 else None,
                  ports=svc.open_ports(s, latest) if latest else None,
                  can_scan=access.can_scan(s, user, target), can_manage=access.can_manage(user, target))


@router.get("/targets/{target_id}/edit")
def target_edit_page(request: Request, target_id: int, user: User = Depends(require("scan")),
                     s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    values = svc.target_to_dict(target)
    values["tags"] = ", ".join(target.tags or [])
    return render(request, "target_form.html", user, target=target, values=values, error=None)


@router.post("/targets/{target_id}/edit")
def target_edit(request: Request, target_id: int, form: FormData = Depends(checked_form),
                user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    return _save_target(request, form, user, s, visible_target(s, user, target_id, "manage"), False)


@router.post("/targets/{target_id}/reset-host-key")
def target_reset_key(request: Request, target_id: int, form: FormData = Depends(checked_form),
                     user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    target.host_key = ""
    svc.audit(s, user, "target.reset-host-key", target.name, client_ip(request))
    s.commit()
    flash(request, "Chiave del server azzerata: alla prossima scansione verrà registrata quella nuova.")
    return redirect(f"/targets/{target.id}")


@router.post("/targets/{target_id}/archive")
def target_archive(request: Request, target_id: int, form: FormData = Depends(checked_form),
                   user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    target.archived = form.get("archived", "1") == "1"
    svc.audit(s, user, "target.archive" if target.archived else "target.restore", target.name, client_ip(request))
    s.commit()
    flash(request, f"«{target.name}» {'archiviato' if target.archived else 'ripristinato'}.")
    return redirect("/targets")


@router.post("/targets/{target_id}/share")
def target_share(request: Request, target_id: int, form: FormData = Depends(checked_form),
                 user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    username = str(form.get("username", "")).strip().lower()[:64]
    other = s.scalar(select(User).where(User.username == username, User.approval == "approved",
                                        User.active.is_(True)))
    if other is None:
        flash(request, f"Nessun utente attivo si chiama «{username}».", "error")
        return redirect(f"/targets/{target.id}#condivisione")
    if other.id == target.created_by:
        flash(request, "È il proprietario: vede già l'obiettivo.", "error")
        return redirect(f"/targets/{target.id}#condivisione")
    can_scan = form.get("can_scan") == "1" and other.can("scan")
    share = s.scalar(select(TargetShare).where(TargetShare.target_id == target.id, TargetShare.user_id == other.id))
    if share is None:
        share = TargetShare(target_id=target.id, user_id=other.id)
        s.add(share)
    share.can_scan = can_scan
    svc.audit(s, user, "target.share", f"{target.name} con {other.username} "
              f"({'scansioni' if can_scan else 'sola lettura'})", client_ip(request))
    s.commit()
    flash(request, f"«{target.name}» condiviso con {other.username}"
          f"{' (può avviare scansioni)' if can_scan else ' in sola lettura'}.")
    return redirect(f"/targets/{target.id}#condivisione")


@router.post("/targets/{target_id}/unshare/{share_id}")
def target_unshare(request: Request, target_id: int, share_id: int, form: FormData = Depends(checked_form),
                   user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    share = s.get(TargetShare, share_id)
    if share is not None and share.target_id == target.id:
        svc.audit(s, user, "target.unshare", f"{target.name} con {share.user.username}", client_ip(request))
        s.delete(share)
        s.commit()
        flash(request, "Condivisione rimossa.")
    return redirect(f"/targets/{target.id}#condivisione")


@router.post("/targets/{target_id}/delete")
def target_delete(request: Request, target_id: int, form: FormData = Depends(checked_form),
                  user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    target = visible_target(s, user, target_id, "manage")
    if s.scalar(select(func.count()).select_from(Scan).where(Scan.target_id == target.id,
                                                             Scan.status.in_(ACTIVE_STATES))):
        flash(request, "Ci sono scansioni in corso su questo obiettivo: annullale prima di eliminarlo.", "error")
        return redirect(f"/targets/{target.id}")
    name = target.name
    for scan in s.scalars(select(Scan).where(Scan.target_id == target.id)).all():
        _remove_report(request, scan)
        s.delete(scan)
    s.delete(target)
    svc.audit(s, user, "target.delete", name, client_ip(request))
    s.commit()
    flash(request, f"«{name}» eliminato con tutte le sue scansioni.")
    return redirect("/targets")


# --------------------------------------------------------------------------- scansioni

@router.get("/scans")
def scans_page(request: Request, status: str = "", target: int = 0, page: int = 1,
               user: User = Depends(require("view")), s: Session = Depends(get_db)):
    q = access.scans_query(user)
    if status in svc.STATUS_LABEL:
        q = q.where(Scan.status == status)
    if target:
        q = q.where(Scan.target_id == target)
    page = max(1, page)
    scans = s.scalars(q.order_by(Scan.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE + 1)).all()
    targets = s.scalars(access.targets_query(user).order_by(func.lower(Target.name))).all()
    return render(request, "scans.html", user, scans=scans[:PAGE_SIZE], more=len(scans) > PAGE_SIZE,
                  page=page, status=status, target_id=target, targets=targets)


def _scannable(s: Session, user: User) -> list[Target]:
    targets = s.scalars(access.targets_query(user).where(Target.archived.is_(False))
                        .order_by(func.lower(Target.name))).all()
    return [t for t in targets if access.can_scan(s, user, t)]


def _scan_form(request: Request, user: User, s: Session, selected: list[int], error: str | None, status: int = 200):
    targets = _scannable(s, user)
    return render(request, "scan_new.html", user, status_code=status, targets=targets, selected=selected,
                  tags=svc.all_tags(targets), native=eng.NATIVE_CHECKS, external=eng.EXTERNAL_TOOLS,
                  optional=eng.OPTIONAL_TOOLS, notes=eng.TOOL_NOTES, error=error)


@router.get("/scans/new")
def scan_new_page(request: Request, target: int = 0, tag: str = "", user: User = Depends(require("scan")),
                  s: Session = Depends(get_db)):
    selected = [target] if target else []
    if tag:
        selected += [t.id for t in _scannable(s, user) if tag.strip().lower() in (t.tags or [])]
    return _scan_form(request, user, s, selected, None)


@router.post("/scans/new")
def scan_new(request: Request, form: FormData = Depends(checked_form), user: User = Depends(require("scan")),
             s: Session = Depends(get_db)):
    ids = [int(v) for v in form.getlist("targets") if str(v).isdigit()]
    preset = str(form.get("preset", "native"))
    custom = [str(v) for v in form.getlist("tools")]
    options = {k: form.get(k) == "1" for k in svc.OPTION_LABELS}
    created: list[Scan] = []
    try:
        if not ids:
            raise svc.Invalid("Scegli almeno un obiettivo.")
        for tid in dict.fromkeys(ids):
            target = s.get(Target, tid)
            if not access.can_scan(s, user, target):
                raise svc.Invalid("Uno degli obiettivi scelti non esiste più o non puoi analizzarlo.")
            created.append(svc.enqueue_scan(s, target, user, preset, custom, options))
    except svc.Invalid as e:
        s.rollback()
        return _scan_form(request, user, s, ids, str(e), 400)
    for scan in created:
        svc.audit(s, user, "scan.start", f"#{scan.id} {scan.target.name} ({preset})", client_ip(request))
    s.commit()
    if len(created) == 1:
        return redirect(f"/scans/{created[0].id}")
    flash(request, f"{len(created)} scansioni messe in coda.")
    return redirect("/scans")


@router.get("/scans/{scan_id}")
def scan_page(request: Request, scan_id: int, severity: str = "", area: str = "", q: str = "",
              user: User = Depends(require("view")), s: Session = Depends(get_db)):
    from watchdog_web import charts
    scan = visible_scan(s, user, scan_id)
    findings: list[Finding] = []
    if scan.status == "done":
        fq = select(Finding).where(Finding.scan_id == scan.id)
        if severity in svc.SEVERITIES:
            fq = fq.where(Finding.severity == severity)
        elif not q and not area:
            fq = fq.where(Finding.severity != "INFO") if severity != "ALL" else fq
        if area in svc.AREA_SHORT:
            fq = fq.where(Finding.area == area)
        if q.strip():
            like = f"%{q.strip()[:80]}%"
            fq = fq.where(Finding.title.ilike(like) | Finding.source.ilike(like) | Finding.description.ilike(like))
        findings = s.scalars(fq.order_by(Finding.position)).all()
    previous = s.scalar(select(Scan).where(Scan.target_id == scan.target_id, Scan.status == "done",
                                           Scan.id < scan.id).order_by(Scan.id.desc()).limit(1))
    breakdown = svc.area_breakdown(s, scan) if scan.status == "done" else {}
    return render(request, "scan.html", user, scan=scan, findings=findings, severity=severity, area=area, q=q,
                  previous=previous, position=svc.queue_position(s, scan),
                  has_report=_report_file(request, scan, "html") is not None,
                  area_chart=charts.area_severity_chart(breakdown, scan.id) if breakdown else None,
                  can_scan=access.can_scan(s, user, scan.target), can_manage=access.can_manage(user, scan.target))


@router.get("/scans/{scan_id}/status.json")
def scan_status(scan_id: int, user: User = Depends(require("view")), s: Session = Depends(get_db)):
    scan = s.get(Scan, scan_id)
    if scan is None or not access.can_view(s, user, scan.target):
        return JSONResponse({"error": "non trovata"}, 404)
    return {"status": scan.status, "label": svc.STATUS_LABEL[scan.status], "progress": scan.progress,
            "step": scan.current_step, "log": scan.log[-6000:], "position": svc.queue_position(s, scan),
            "duration": fmt_duration(scan.duration_seconds), "cancel_requested": scan.cancel_requested}


@router.post("/scans/{scan_id}/cancel")
def scan_cancel(request: Request, scan_id: int, form: FormData = Depends(checked_form),
                user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    # Riga bloccata: il worker non può prenderla in carico mentre la si annulla.
    scan = visible_scan(s, user, scan_id, "scan", lock=True)
    if not svc.request_cancel(s, scan):
        s.rollback()
        flash(request, "La scansione era già finita.", "error")
        return redirect(f"/scans/{scan_id}")
    svc.audit(s, user, "scan.cancel", f"#{scan.id} {scan.target.name}", client_ip(request))
    s.commit()
    flash(request, "Annullamento richiesto: si ferma alla fine del controllo in corso e rimuove i tool installati."
          if scan.status == "running" else "Scansione annullata.")
    return redirect(f"/scans/{scan_id}")


@router.post("/scans/{scan_id}/delete")
def scan_delete(request: Request, scan_id: int, form: FormData = Depends(checked_form),
                user: User = Depends(require("scan")), s: Session = Depends(get_db)):
    scan = visible_scan(s, user, scan_id, "manage")
    if scan.active:
        flash(request, "La scansione è ancora in corso: annullala prima di eliminarla.", "error")
        return redirect(f"/scans/{scan_id}")
    target_id = scan.target_id
    _remove_report(request, scan)
    svc.audit(s, user, "scan.delete", f"#{scan.id} {scan.target.name}", client_ip(request))
    s.delete(scan)
    s.commit()
    flash(request, "Scansione eliminata.")
    return redirect(f"/targets/{target_id}")


def _report_dir(request: Request, scan: Scan) -> Path | None:
    """Cartella del report, solo se sta davvero dentro la cartella dei report."""
    if not scan.report_dir:
        return None
    base = request.app.state.settings.reports_dir.resolve()
    path = Path(scan.report_dir).resolve()
    if base not in path.parents or not path.is_dir():
        return None
    return path


def _report_file(request: Request, scan: Scan, fmt: str) -> Path | None:
    folder = _report_dir(request, scan)
    if folder is None or fmt not in REPORT_FILES:
        return None
    path = folder / REPORT_FILES[fmt][0]
    return path if path.is_file() else None


def _remove_report(request: Request, scan: Scan) -> None:
    import shutil
    folder = _report_dir(request, scan)
    if folder is not None:
        shutil.rmtree(folder, ignore_errors=True)


def report_response(request: Request, scan: Scan, fmt: str, download: bool) -> Response:
    from watchdog_web.app import BadRequest
    path = _report_file(request, scan, fmt)
    if path is None:
        raise BadRequest("Il report di questa scansione non è disponibile.")
    headers = {"Content-Security-Policy": REPORT_CSP, "X-Content-Type-Options": "nosniff"}
    name = f"watchdog-{scan.id}-{REPORT_FILES[fmt][0]}"
    if download or fmt != "html":
        return FileResponse(path, media_type=REPORT_FILES[fmt][1], filename=name, headers=headers)
    return FileResponse(path, media_type=REPORT_FILES[fmt][1], headers=headers)


@router.get("/scans/{scan_id}/report")
def scan_report(request: Request, scan_id: int, format: str = "html", download: int = 0,
                user: User = Depends(require("view")), s: Session = Depends(get_db)):
    return report_response(request, visible_scan(s, user, scan_id), format, bool(download))


@router.get("/compare")
def compare_page(request: Request, a: int = 0, b: int = 0, user: User = Depends(require("view")),
                 s: Session = Depends(get_db)):
    from watchdog_web.app import BadRequest
    old, new = visible_scan(s, user, a), visible_scan(s, user, b)
    if old.status != "done" or new.status != "done":
        raise BadRequest("Scegli due scansioni completate da confrontare.")
    if old.target_id != new.target_id:
        raise BadRequest("Si possono confrontare solo due scansioni dello stesso obiettivo.")
    if old.id > new.id:
        old, new = new, old
    return render(request, "compare.html", user, old=old, new=new, diff=svc.compare_scans(s, old, new))


# --------------------------------------------------------------------------- utenti (solo amministratori)

def _users_ctx(s: Session) -> dict:
    return {"users": s.scalars(select(User).where(User.approval == "approved").order_by(User.username)).all(),
            "pending": s.scalars(select(User).where(User.approval == "pending").order_by(User.created_at)).all(),
            "roles": ROLES}


@router.get("/users")
def users_page(request: Request, user: User = Depends(require("admin")), s: Session = Depends(get_db)):
    return render(request, "users.html", user, error=None, values={}, **_users_ctx(s))


@router.post("/users/{user_id}/approve")
def user_approve(request: Request, user_id: int, form: FormData = Depends(checked_form),
                 user: User = Depends(require("admin")), s: Session = Depends(get_db)):
    other = s.get(User, user_id)
    if other is None or other.approval != "pending":
        flash(request, "Questa richiesta non è più in attesa.", "error")
        return redirect("/users")
    role = str(form.get("role", "analyst"))
    if role not in ("analyst", "viewer"):
        role = "analyst"                    # amministratore solo dopo, con una scelta esplicita
    other.approval, other.role, other.active = "approved", role, True
    svc.audit(s, user, "register.approve", f"{other.username} ({role})", client_ip(request))
    s.commit()
    flash(request, f"«{other.username}» approvato come {ROLE_LABEL[role].lower()}: ora può accedere.")
    return redirect("/users")


@router.post("/users/{user_id}/reject")
def user_reject(request: Request, user_id: int, form: FormData = Depends(checked_form),
                user: User = Depends(require("admin")), s: Session = Depends(get_db)):
    other = s.get(User, user_id)
    if other is None or other.approval != "pending":
        flash(request, "Questa richiesta non è più in attesa.", "error")
        return redirect("/users")
    name = other.username
    s.delete(other)
    svc.audit(s, user, "register.reject", name, client_ip(request))
    s.commit()
    flash(request, f"Richiesta di «{name}» rifiutata ed eliminata.")
    return redirect("/users")


def _admins_left(s: Session, excluding: User) -> int:
    return s.scalar(select(func.count()).select_from(User).where(
        User.role == "admin", User.active.is_(True), User.id != excluding.id))


@router.post("/users/new")
def user_new(request: Request, form: FormData = Depends(checked_form), user: User = Depends(require("admin")),
             s: Session = Depends(get_db)):
    import re
    username = str(form.get("username", "")).strip().lower()
    password = str(form.get("password", ""))
    role = str(form.get("role", "viewer"))
    error = None
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}", username):
        error = "Nome utente: da 3 a 64 caratteri, solo lettere minuscole, numeri, punto, trattino."
    elif role not in ROLES:
        error = "Ruolo non valido."
    elif s.scalar(select(User).where(User.username == username)):
        error = "Esiste già un utente con questo nome."
    else:
        error = password_problem(password, username)
    if error:
        return render(request, "users.html", user, status_code=400, error=error, **_users_ctx(s),
                      values={"username": username, "full_name": form.get("full_name", ""), "role": role})
    s.add(User(username=username, full_name=str(form.get("full_name", "")).strip()[:120],
               password_hash=hash_password(password), role=role, must_change_password=True))
    svc.audit(s, user, "user.create", f"{username} ({role})", client_ip(request))
    s.commit()
    flash(request, f"Utente «{username}» creato. Comunicagli la password: al primo accesso dovrà cambiarla.")
    return redirect("/users")


@router.post("/users/{user_id}/edit")
def user_edit(request: Request, user_id: int, form: FormData = Depends(checked_form),
              user: User = Depends(require("admin")), s: Session = Depends(get_db)):
    other = _get_or_404(s, User, user_id)
    role = str(form.get("role", other.role))
    active = form.get("active") == "1"
    password = str(form.get("password", ""))
    if role not in ROLES:
        flash(request, "Ruolo non valido.", "error")
        return redirect("/users")
    if other.role == "admin" and other.active and (role != "admin" or not active) and _admins_left(s, other) == 0:
        flash(request, "Deve restare almeno un amministratore attivo.", "error")
        return redirect("/users")
    changes = []
    if password:
        problem = password_problem(password, other.username)
        if problem:
            flash(request, problem, "error")
            return redirect("/users")
        other.password_hash = hash_password(password)
        other.failed_logins, other.locked_until = 0, None
        other.must_change_password = other.id != user.id
        changes.append("password")
    if role != other.role:
        changes.append(f"ruolo {other.role} -> {role}")
        other.role = role
    if active != other.active:
        changes.append("riattivato" if active else "disattivato")
        other.active = active
        if not active:
            for token in other.tokens:
                token.revoked = True
    if changes:
        other.session_version += 1          # chiude le sessioni aperte di quell'utente
        svc.audit(s, user, "user.update", f"{other.username}: {', '.join(changes)}", client_ip(request))
        s.commit()
        if other.id == user.id:
            request.session["sv"] = other.session_version
        flash(request, f"«{other.username}» aggiornato.")
    return redirect("/users")


# --------------------------------------------------------------------------- profilo e token

def _account_ctx(request: Request, s: Session, user: User) -> dict:
    tokens = s.scalars(select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.id.desc())).all()
    return {"tokens": tokens, "new_token": None, "token_days": TOKEN_DAYS,
            "requires_2fa": needs_2fa(user, request.app.state.settings)}


@router.get("/account")
def account_page(request: Request, user: User = Depends(require("view")), s: Session = Depends(get_db)):
    ctx = _account_ctx(request, s, user)
    ctx["new_token"] = request.session.pop("new_token", None)
    return render(request, "account.html", user, error=None, **ctx)


@router.get("/account/password-change")
def password_change_page(request: Request, user: User = Depends(get_user)):
    if not user.must_change_password:
        return redirect("/account")
    return render(request, "password_change.html", user, error=None)


# --------------------------------------------------------------------------- verifica in due passaggi

@router.get("/account/2fa")
def twofa_page(request: Request, user: User = Depends(get_user), s: Session = Depends(get_db)):
    box = request.app.state.box
    if user.totp_enabled:
        return redirect("/account")
    # Segreto nuovo a ogni visita finché non è confermato: salvato cifrato, attivo solo dopo il codice.
    secret = new_totp_secret()
    user.totp_secret_enc = box.encrypt(secret)
    s.commit()
    uri = totp_uri(secret, user.username)
    return render(request, "twofa_setup.html", user, secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                  qr=totp_qr_data_uri(uri), required=needs_2fa(user, request.app.state.settings), error=None)


@router.post("/account/2fa/enable")
def twofa_enable(request: Request, form: FormData = Depends(checked_form), user: User = Depends(get_user),
                 s: Session = Depends(get_db)):
    if user.totp_enabled or not user.totp_secret_enc:
        return redirect("/account")
    secret = request.app.state.box.decrypt(user.totp_secret_enc)
    step = totp_match(secret, str(form.get("code", "")), 0)
    if step is None:
        uri = totp_uri(secret, user.username)
        return render(request, "twofa_setup.html", user, status_code=400,
                      secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), qr=totp_qr_data_uri(uri),
                      required=needs_2fa(user, request.app.state.settings),
                      error="Il codice non corrisponde. Controlla che l'ora del telefono sia giusta e riprova.")
    user.totp_enabled, user.totp_last_step = True, step
    user.session_version += 1                       # le altre sessioni devono rientrare col codice
    svc.audit(s, user, "2fa.enable", "", client_ip(request))
    s.commit()
    request.session["sv"] = user.session_version
    flash(request, "Verifica in due passaggi attivata: da ora all'accesso serve anche il codice dell'app.")
    return redirect("/")


@router.post("/account/2fa/disable")
def twofa_disable(request: Request, form: FormData = Depends(checked_form), user: User = Depends(require("view")),
                  s: Session = Depends(get_db)):
    if needs_2fa(user, request.app.state.settings):
        flash(request, "Per il tuo ruolo la verifica in due passaggi è obbligatoria.", "error")
        return redirect("/account")
    secret = request.app.state.box.decrypt(user.totp_secret_enc) if user.totp_enabled else ""
    step = totp_match(secret, str(form.get("code", "")), user.totp_last_step) if secret else None
    if not verify_password(str(form.get("password", "")), user.password_hash) or step is None:
        flash(request, "Password o codice non corretti: la verifica in due passaggi resta attiva.", "error")
        return redirect("/account")
    user.totp_enabled, user.totp_secret_enc, user.totp_last_step = False, "", 0
    user.session_version += 1
    svc.audit(s, user, "2fa.disable", "", client_ip(request))
    s.commit()
    request.session["sv"] = user.session_version
    flash(request, "Verifica in due passaggi disattivata.")
    return redirect("/account")


@router.post("/users/{user_id}/reset-2fa")
def user_reset_2fa(request: Request, user_id: int, form: FormData = Depends(checked_form),
                   user: User = Depends(require("admin")), s: Session = Depends(get_db)):
    other = _get_or_404(s, User, user_id)
    other.totp_enabled, other.totp_secret_enc, other.totp_last_step = False, "", 0
    other.session_version += 1
    svc.audit(s, user, "2fa.reset", other.username, client_ip(request))
    s.commit()
    if other.id == user.id:
        request.session["sv"] = other.session_version
    flash(request, f"Verifica in due passaggi di «{other.username}» azzerata: al prossimo accesso la configurerà di nuovo"
          if needs_2fa(other, request.app.state.settings) else
          f"Verifica in due passaggi di «{other.username}» disattivata.")
    return redirect("/users")


@router.post("/account/password")
def account_password(request: Request, form: FormData = Depends(checked_form),
                     user: User = Depends(require("view")), s: Session = Depends(get_db)):
    current, new1, new2 = (str(form.get(k, "")) for k in ("current", "new", "repeat"))
    error = None
    if not verify_password(current, user.password_hash):
        error = "La password attuale non è corretta."
    elif new1 != new2:
        error = "Le due nuove password non coincidono."
    elif new1 == current:
        error = "La nuova password deve essere diversa da quella attuale."
    else:
        error = password_problem(new1, user.username)
    if error:
        if user.must_change_password:
            return render(request, "password_change.html", user, status_code=400, error=error)
        return render(request, "account.html", user, status_code=400, error=error, **_account_ctx(request, s, user))
    user.password_hash = hash_password(new1)
    user.must_change_password = False
    user.session_version += 1
    svc.audit(s, user, "account.password", "", client_ip(request))
    s.commit()
    request.session["sv"] = user.session_version     # questa sessione resta valida, le altre no
    flash(request, "Password cambiata. Le altre sessioni aperte sono state chiuse.")
    return redirect("/account")


@router.post("/account/tokens/new")
def token_new(request: Request, form: FormData = Depends(checked_form), user: User = Depends(require("view")),
              s: Session = Depends(get_db)):
    name = str(form.get("name", "")).strip()[:80] or "Token"
    active_tokens = [x for x in s.scalars(select(ApiToken).where(ApiToken.user_id == user.id,
                                                                  ApiToken.revoked.is_(False))).all() if not x.expired]
    if len(active_tokens) >= 10:
        flash(request, "Hai già 10 token attivi: revocane uno prima di crearne un altro.", "error")
        return redirect("/account")
    try:
        days = int(str(form.get("days", "90")))
    except ValueError:
        days = 90
    if days not in TOKEN_DAYS:
        days = 90
    # Di default sola lettura: i permessi di scansione vanno chiesti esplicitamente.
    read_only = form.get("scope") != "scan" or not user.can("scan")
    token, prefix, digest = new_api_token()
    s.add(ApiToken(user_id=user.id, name=name, prefix=prefix, token_hash=digest, read_only=read_only,
                   expires_at=now() + timedelta(days=days)))
    svc.audit(s, user, "token.create", f"{name} ({'sola lettura' if read_only else 'lettura e scansioni'}, "
              f"{days} giorni)", client_ip(request))
    s.commit()
    request.session["new_token"] = token             # mostrato una volta sola, alla pagina successiva
    return redirect("/account")


@router.post("/account/tokens/{token_id}/revoke")
def token_revoke(request: Request, token_id: int, form: FormData = Depends(checked_form),
                 user: User = Depends(require("view")), s: Session = Depends(get_db)):
    token = s.get(ApiToken, token_id)
    if token is not None and (token.user_id == user.id or user.can("admin")):
        token.revoked = True
        svc.audit(s, user, "token.revoke", token.name, client_ip(request))
        s.commit()
        flash(request, "Token revocato.")
    return redirect("/account")


# --------------------------------------------------------------------------- registro delle attività

@router.get("/audit")
def audit_page(request: Request, page: int = 1, user: User = Depends(require("admin")),
               s: Session = Depends(get_db)):
    page = max(1, page)
    rows = s.scalars(select(AuditLog).order_by(AuditLog.id.desc()).offset((page - 1) * 100).limit(101)).all()
    return render(request, "audit.html", user, rows=rows[:100], more=len(rows) > 100, page=page)


__all__ = ["router", "register_filters", "report_response", "get_db", "hash_token"]

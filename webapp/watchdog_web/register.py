"""Registrazione: chiunque raggiunge l'applicazione può chiedere un account.

1. sceglie nome utente e password;
2. nello stesso passaggio attiva la verifica in due passaggi (QR + codice): senza il
   codice la richiesta non esiste ancora;
3. la richiesta resta in attesa finché un amministratore non la approva scegliendo il
   ruolo (analista o solo lettura). Prima dell'approvazione l'account non entra.

Limiti contro gli abusi: poche registrazioni per indirizzo, un numero massimo di
richieste in attesa, le registrazioni lasciate a metà si cancellano da sole.
"""
from __future__ import annotations

import re
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session
from starlette.datastructures import FormData

from watchdog_web import services as svc
from watchdog_web.models import User, now
from watchdog_web.security import (hash_password, new_csrf_token, new_totp_secret, password_problem,
                                   totp_match, totp_qr_data_uri, totp_uri)
from watchdog_web.views import _recent, checked_form, client_ip, get_db, redirect, render

router = APIRouter(include_in_schema=False)

REG_PER_IP_PER_HOUR = 5
MAX_WAITING = 30                 # richieste in attesa di approvazione, in tutto
UNCONFIRMED_MINUTES = 30         # dopo, una registrazione senza 2FA confermata si cancella
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")


def _enabled(request: Request) -> bool:
    return request.app.state.settings.registration == "approval"


def _closed(request: Request):
    return render(request, "error.html", None, status_code=404, title="Registrazione non disponibile",
                  message="Su questa installazione gli account li crea un amministratore.")


def _cleanup(s: Session) -> None:
    s.execute(delete(User).where(User.approval == "unconfirmed",
                                 User.created_at < now() - timedelta(minutes=UNCONFIRMED_MINUTES)))


def _form(request: Request, error: str | None = None, values: dict | None = None, status: int = 200):
    return render(request, "register.html", None, status_code=status, error=error, values=values or {})


@router.get("/register")
def register_page(request: Request):
    if not _enabled(request):
        return _closed(request)
    if request.session.get("uid"):
        return redirect("/")
    return _form(request)


@router.post("/register")
def register(request: Request, form: FormData = Depends(checked_form), s: Session = Depends(get_db)):
    if not _enabled(request):
        return _closed(request)
    username = str(form.get("username", "")).strip().lower()[:64]
    full_name = str(form.get("full_name", "")).strip()[:120]
    password, repeat = str(form.get("password", ""))[:300], str(form.get("repeat", ""))[:300]
    values = {"username": username, "full_name": full_name}
    ip = client_ip(request)
    attempts = request.app.state.register_attempts
    if len(_recent(attempts, ip, 3600)) >= REG_PER_IP_PER_HOUR:
        return _form(request, "Troppe registrazioni da questo computer: riprova tra un'ora.", values, 429)
    _cleanup(s)
    error = None
    if not USERNAME_RE.fullmatch(username):
        error = "Nome utente: da 3 a 64 caratteri, solo lettere minuscole, numeri, punto, trattino e trattino basso."
    elif password != repeat:
        error = "Le due password non coincidono."
    else:
        error = password_problem(password, username)
    if error is None and s.scalar(select(User).where(User.username == username)) is not None:
        error = "Questo nome utente è già usato: scegline un altro."
    if error is None and s.scalar(select(func.count()).select_from(User)
                                  .where(User.approval.in_(("pending", "unconfirmed")))) >= MAX_WAITING:
        error = "Ci sono già troppe richieste in attesa: riprova più tardi o chiedi a un amministratore."
    if error:
        s.commit()
        return _form(request, error, values, 400)
    attempts.setdefault(ip, []).append(time.monotonic())
    user = User(username=username, full_name=full_name, password_hash=hash_password(password), role="viewer",
                approval="unconfirmed", self_registered=True,
                totp_secret_enc=request.app.state.box.encrypt(new_totp_secret()))
    s.add(user)
    s.commit()
    request.session.clear()
    request.session.update(reg_uid=user.id, reg_at=int(time.time()), csrf=new_csrf_token())
    return redirect("/register/2fa")


def _registering(request: Request, s: Session) -> User | None:
    uid = request.session.get("reg_uid")
    if not uid or time.time() - int(request.session.get("reg_at", 0)) > UNCONFIRMED_MINUTES * 60:
        return None
    user = s.get(User, uid)
    return user if user is not None and user.approval == "unconfirmed" else None


def _twofa_page(request: Request, user: User, error: str | None = None, status: int = 200):
    secret = request.app.state.box.decrypt(user.totp_secret_enc)
    return render(request, "register_2fa.html", None, status_code=status, error=error,
                  secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                  qr=totp_qr_data_uri(totp_uri(secret, user.username)), username=user.username)


@router.get("/register/2fa")
def register_2fa_page(request: Request, s: Session = Depends(get_db)):
    user = _registering(request, s)
    if user is None:
        request.session.clear()
        return redirect("/register")
    return _twofa_page(request, user)


@router.post("/register/2fa")
def register_2fa(request: Request, form: FormData = Depends(checked_form), s: Session = Depends(get_db)):
    user = _registering(request, s)
    if user is None:
        request.session.clear()
        return redirect("/register")
    step = totp_match(request.app.state.box.decrypt(user.totp_secret_enc), str(form.get("code", "")), 0)
    if step is None:
        return _twofa_page(request, user, "Il codice non corrisponde. Controlla che l'ora del telefono sia giusta "
                                          "e riprova con il codice nuovo.", 400)
    user.totp_enabled, user.totp_last_step, user.approval = True, step, "pending"
    svc.audit(s, user, "register.request", user.full_name, client_ip(request))
    s.commit()
    request.session.clear()
    return render(request, "register_done.html", None, username=user.username)

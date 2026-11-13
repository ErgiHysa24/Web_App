"""Applicazione web (FastAPI): sessioni, protezioni e montaggio delle pagine e dell'API.

Protezioni applicate a tutte le risposte:
- cookie di sessione firmato, HttpOnly, SameSite=Lax (Secure se WATCHDOG_HTTPS_ONLY);
- token CSRF obbligatorio su ogni richiesta che modifica qualcosa dal browser;
- Content-Security-Policy senza script né stili inline, niente risorse esterne;
- il report HTML completo di WatchDog (che contiene testo proveniente dai sistemi
  analizzati) è servito in una sandbox con origine separata.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

from watchdog_web import __version__
from watchdog_web.config import Settings, load_settings
from watchdog_web.db import init_schema, make_engine, make_session_factory
from watchdog_web.security import SecretBox

HERE = Path(__file__).parent
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")
MAX_BODY_BYTES = 256 * 1024         # nessun modulo legittimo è più grande (una chiave SSH è pochi kB)


class NotAuthenticated(Exception):
    pass


class RedirectTo(Exception):
    """Prima di usare l'applicazione l'utente deve fare qualcosa (cambiare password, attivare 2FA)."""

    def __init__(self, url: str) -> None:
        self.url = url


class Forbidden(Exception):
    def __init__(self, message: str = "Non hai i permessi per questa operazione.") -> None:
        self.message = message


class BadRequest(Exception):
    def __init__(self, message: str) -> None:
        self.message = message


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    engine = make_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_schema(engine)
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        yield
        engine.dispose()

    # Lo schema dell'API è servito da api.py solo a chi ha un token (openapi_url=None qui).
    app = FastAPI(title="WatchDog Web", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.db = make_session_factory(engine)
    app.state.box = SecretBox(settings.secret_key)
    app.state.login_attempts = {}          # ip -> [istanti dei tentativi falliti]
    app.state.unknown_attempts = {}        # nome utente inesistente -> [istanti]
    app.state.register_attempts = {}       # ip -> [istanti delle registrazioni]
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.state.templates = templates

    from watchdog_web import api, insights, register, views
    views.register_filters(templates)
    app.include_router(views.router)
    app.include_router(insights.router)
    app.include_router(register.router)
    app.include_router(api.router)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            return PlainTextResponse("Richiesta troppo grande.", status_code=413)
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), usb=(), payment=(), browsing-topics=()")
        if settings.https_only:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    # Aggiunto dopo: avvolge il middleware qui sopra, quindi la sessione è disponibile ovunque.
    # Con HTTPS il cookie usa il prefisso __Host-: il browser lo accetta solo se Secure, senza
    # dominio e con path /, così nessun altro sito o sottodominio può sovrascriverlo.
    cookie = "__Host-watchdog" if settings.https_only else "watchdog_session"
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie=cookie,
                       max_age=settings.session_hours * 3600, same_site="lax", https_only=settings.https_only)

    def wants_json(request: Request) -> bool:
        return request.url.path.startswith("/api/")

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(request: Request, exc: NotAuthenticated):
        if wants_json(request):
            return JSONResponse({"error": "Autenticazione richiesta: token mancante o non valido."}, 401,
                                headers={"WWW-Authenticate": "Bearer"})
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(RedirectTo)
    async def redirect_to(request: Request, exc: RedirectTo):
        if wants_json(request):
            return JSONResponse({"error": "Completa prima la configurazione dell'account."}, 403)
        return RedirectResponse(exc.url, status_code=303)

    @app.exception_handler(Forbidden)
    async def forbidden(request: Request, exc: Forbidden):
        if wants_json(request):
            return JSONResponse({"error": exc.message}, 403)
        return templates.TemplateResponse(request, "error.html", {
            "title": "Operazione non consentita", "message": exc.message, "user": None}, status_code=403)

    @app.exception_handler(BadRequest)
    async def bad_request(request: Request, exc: BadRequest):
        if wants_json(request):
            return JSONResponse({"error": exc.message}, 400)
        return templates.TemplateResponse(request, "error.html", {
            "title": "Richiesta non valida", "message": exc.message, "user": None}, status_code=400)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        """Usato da Docker: risponde solo se anche il database risponde."""
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:
            return PlainTextResponse("database non raggiungibile", status_code=503)
        return {"status": "ok"}

    return app


def app_factory() -> FastAPI:
    """Punto d'ingresso per uvicorn: uvicorn --factory watchdog_web.app:app_factory"""
    return create_app()

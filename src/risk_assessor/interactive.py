"""Menu interattivo di WatchDog (Linux e macOS).

Solo libreria standard. Il menu non conosce i dettagli dell'esecuzione: parla con
un `backend` (vedi `Backend`) fornito da cli.py, così si può testare con input
simulato e un backend finto.

Principi:
- un errore di digitazione non chiude mai il programma: si rimane nel passo e si riprova;
- `0` torna indietro (o esce, dal menu principale); Ctrl+C torna al menu principale;
  Ctrl+D (fine input) esce;
- prima di avviare una scansione si vede un riepilogo di ciò che verrà fatto;
- niente di ciò che si imposta qui viene scritto su disco: le impostazioni valgono
  per la sessione, `config.yaml` non viene mai modificato.
"""
from __future__ import annotations

import getpass
import importlib.util
import json
import os
import platform
import shutil
import sys
import webbrowser
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from risk_assessor.sanitize import clean_text

VALID_FORMATS = ("json", "md", "html", "wazuh")
DEFAULT_FORMATS = ("json", "md", "html")

CHECK_LABELS = {
    "linux": "Informazioni di sistema",
    "users": "Utenti e gruppi",
    "ssh_config": "Configurazione SSH",
    "firewall": "Firewall",
    "services": "Servizi e porte",
    "filesystem": "File system",
    "packages": "Pacchetti e aggiornamenti",
    "auth_policy": "Password policy e sudoers",
    "kernel": "Hardening del kernel (sysctl)",
    "logging": "Log, audit e anti brute-force",
    "updates": "Aggiornamenti automatici",
    "persistence": "Persistenza e attività sospette",
    "protections": "Protezioni del sistema (SELinux/AppArmor, cifratura)",
    "nmap": "Nmap (porte e servizi)",
    "lynis": "Lynis (audit generale)",
    "rkhunter": "rkhunter (rootkit)",
    "chkrootkit": "chkrootkit (rootkit)",
    "openscap": "OpenSCAP (conformità)",
    "clamav": "ClamAV (malware)",
    "aide": "AIDE (integrità file)",
    "debsecan": "debsecan (vulnerabilità Debian)",
    "debsums": "debsums (integrità file dei pacchetti)",
    "trivy": "Trivy (vulnerabilità pacchetti)",
    "nmap_external": "Nmap dall'esterno",
}

EXTERNAL_BINARIES = [
    ("nmap", "nmap"), ("lynis", "lynis"), ("rkhunter", "rkhunter"),
    ("chkrootkit", "chkrootkit"), ("oscap", "oscap"), ("clamscan", "clamscan"),
    ("aide", "aide"), ("debsecan", "debsecan"), ("debsums", "debsums"), ("trivy", "trivy"),
]


# ------------------------------------------------------------------ modelli

class Back(Exception):
    """L'utente vuole tornare indietro."""


class Quit(Exception):
    """L'utente vuole uscire (Ctrl+D)."""


class ScanError(Exception):
    """La scansione non è partita o non è riuscita (messaggio già mostrato)."""


@dataclass
class Settings:
    """Impostazioni valide per la sessione (partono da config.yaml)."""
    allow_install: bool = True
    keep_tools: bool = False
    full_clamav: bool = False
    formats: list[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    output_dir: str = "reports"
    ask_sudo: bool = False
    allow_epel: bool = False
    # Tool opzionali aggiunti alla scansione completa per questa sessione.
    extra_tools: list[str] = field(default_factory=list)
    # Integrazioni (vedi la voce "Integrazioni" del menu)
    wazuh_log: str = ""                       # file di righe JSON letto da Wazuh
    attack_layer: str = ""                    # layer di ATT&CK Navigator con la copertura
    polyscan_reports: list[str] = field(default_factory=list)   # rapporti JSON da importare


@dataclass
class SshProfile:
    host: str = ""
    user: str = ""
    port: int = 22
    key: str | None = None
    use_password: bool = False
    accept_new_host_key: bool = False


@dataclass
class ScanPlan:
    mode: str                         # "local" | "ssh"
    label: str
    tools: list[str]
    settings: Settings
    ssh: SshProfile | None = None
    ssh_password: str | None = None
    sudo_password: str | None = None
    external_scan: bool = False       # Nmap dal PC dell'operatore verso l'host (solo SSH)

    @property
    def target(self) -> str:
        if self.mode == "ssh" and self.ssh:
            return f"{self.ssh.user}@{self.ssh.host}:{self.ssh.port}"
        return "questa macchina"


@dataclass
class ReportInfo:
    path: Path
    target: str
    level: str
    score: int
    total: int
    counts: dict[str, int]
    when: str
    started: str = ""          # data ISO (UTC) per ordinare e confrontare

    @property
    def html(self) -> Path | None:
        p = self.path / "assessment.html"
        return p if p.exists() else None


@dataclass
class LastScan:
    target: str
    level: str
    score: int
    total: int
    paths: list[Path]


class Backend(Protocol):
    config_path: str
    config_loaded: bool

    def defaults(self) -> Settings: ...
    def presets(self, extras=()) -> list[tuple[str, str, list[str]]]: ...  # (etichetta, nota, tools)
    def optional_tools(self) -> list[tuple[str, str, str, bool]]: ...     # (nome, etichetta, nota, in config)
    def checks(self) -> list[tuple[str, str]]: ...                   # (nome, "native"|"tool")
    def estimate(self, tools: list[str], settings: Settings,
                 external: bool = False) -> tuple[int, int]: ...
    def run_scan(self, plan: ScanPlan): ...                          # -> Assessment, o ScanError
    def write_reports(self, assessment, settings: Settings) -> list[Path]: ...
    def show_summary(self, assessment, paths: list[Path]) -> None: ...


# ------------------------------------------------------------------ console

_CODES = {
    "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "cyan": "36", "orange": "38;5;214", "grey": "90",
}
_LEVEL_STYLE = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "yellow",
                "LOW": "cyan", "INFO": "grey"}


class Console:
    """Input/output con colori opzionali e validazione. Tutto iniettabile per i test."""

    def __init__(self, input_fn: Callable[[str], str] = input,
                 secret_fn: Callable[[str], str] = getpass.getpass,
                 out=None, color: bool | None = None, width: int | None = None) -> None:
        self.input_fn = input_fn
        self.secret_fn = secret_fn
        self.out = out or sys.stdout
        if color is None:
            color = bool(getattr(self.out, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ
        self.color = color
        self.width = width or min(max(shutil.get_terminal_size((80, 24)).columns, 60), 78)

    # ---- output
    def c(self, style: str, text: str) -> str:
        if not self.color or style not in _CODES:
            return text
        return f"\x1b[{_CODES[style]}m{text}\x1b[0m"

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def rule(self, title: str = "") -> None:
        if title:
            line = f"── {title} " + "─" * max(0, self.width - len(title) - 4)
        else:
            line = "─" * self.width
        self.say(self.c("dim", line))

    def box(self, lines: list[tuple[str, str]]) -> None:
        """Riquadro con (stile, testo) per riga. Il testo è troncato alla larghezza."""
        inner = self.width - 4
        self.say(self.c("dim", "╭" + "─" * (self.width - 2) + "╮"))
        for style, text in lines:
            text = text if len(text) <= inner else text[: inner - 1] + "…"
            pad = " " * (inner - len(text))
            self.say(self.c("dim", "│ ") + self.c(style, text) + pad + self.c("dim", " │"))
        self.say(self.c("dim", "╰" + "─" * (self.width - 2) + "╯"))

    def error(self, text: str) -> None:
        self.say("  " + self.c("red", "✗ " + text))

    def ok(self, text: str) -> None:
        self.say("  " + self.c("green", "✓ " + text))

    def warn(self, text: str) -> None:
        self.say("  " + self.c("yellow", "! " + text))

    # ---- input
    def _read(self, prompt: str, secret: bool = False) -> str:
        try:
            return (self.secret_fn if secret else self.input_fn)(prompt)
        except KeyboardInterrupt:
            self.say()
            raise Back from None
        except EOFError:
            self.say()
            raise Quit from None

    def ask(self, label: str, default: str | None = None,
            validate: Callable[[str], str | None] | None = None,
            secret: bool = False) -> str:
        suffix = f" [{default}]" if default else ""
        while True:
            raw = self._read(f"  {label}{suffix}: ", secret=secret).strip()
            value = raw or (default or "")
            if not value:
                self.error("Campo obbligatorio.")
                continue
            problem = validate(value) if validate else None
            if problem:
                self.error(problem)
                continue
            return value

    def confirm(self, label: str, default: bool = False) -> bool:
        hint = "S/n" if default else "s/N"
        while True:
            raw = self._read(f"  {label} [{hint}]: ").strip().lower()
            if not raw:
                return default
            if raw in ("s", "si", "sì", "y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            self.error("Rispondi con s oppure n.")

    def choose(self, title: str, options: list[tuple[str, str, str]],
               zero: str = "Indietro", default: str | None = None) -> str:
        """Elenco numerato. Ritorna la chiave scelta; `0` solleva Back."""
        if title:
            self.say()
            self.say("  " + self.c("bold", title))
            self.say()
        width = max(len(label) for _, label, _ in options) + 2
        for i, (_, label, hint) in enumerate(options, 1):
            self.say("  " + self.c("cyan", str(i).rjust(2)) + f"  {label:<{width}}" + self.c("dim", hint))
        self.say("  " + self.c("cyan", " 0") + f"  {zero}")
        self.say()
        keys = [k for k, _, _ in options]
        while True:
            default_hint = ""
            if default in keys:
                default_hint = f" [{keys.index(default) + 1}]"
            raw = self._read(f"  {self.c('cyan', '›')} Scelta{default_hint}: ").strip().lower()
            if not raw and default in keys:
                return default  # type: ignore[return-value]
            if raw in ("0", "q", "b", "indietro"):
                raise Back
            if _digits(raw) and 1 <= int(raw) <= len(options):
                return keys[int(raw) - 1]
            self.error(f"Scegli un numero da 0 a {len(options)}.")

    def choose_many(self, title: str, options: list[tuple[str, str, str]]) -> list[str]:
        """Selezione multipla: `1,3,5-7`, oppure `tutti`. Invio vuoto = annulla (Back)."""
        self.say()
        self.say("  " + self.c("bold", title))
        self.say()
        width = max(len(label) for _, label, _ in options) + 2
        for i, (_, label, hint) in enumerate(options, 1):
            self.say("  " + self.c("cyan", str(i).rjust(2)) + f"  {label:<{width}}" + self.c("dim", hint))
        self.say()
        self.say(self.c("dim", "  Scrivi i numeri separati da virgola (es. 1,3,5-7) oppure 'tutti'. 0 per tornare."))
        keys = [k for k, _, _ in options]
        while True:
            raw = self._read(f"  {self.c('cyan', '›')} Selezione: ").strip().lower()
            if raw in ("0", ""):
                raise Back
            if raw in ("tutti", "all", "*"):
                return keys
            picked = parse_selection(raw, len(options))
            if picked is None:
                self.error(f"Selezione non valida: usa numeri da 1 a {len(options)}.")
                continue
            return [keys[i - 1] for i in picked]


def _digits(text: str) -> bool:
    """Solo cifre ASCII: "²".isdigit() è True ma int("²") fallisce."""
    return text.isascii() and text.isdigit()


def parse_selection(text: str, maximum: int) -> list[int] | None:
    """'1,3-5' -> [1,3,4,5]. None se non valido o fuori intervallo."""
    result: list[int] = []
    for part in text.replace(" ", "").split(","):
        if not part:
            return None
        if "-" in part:
            lo, _, hi = part.partition("-")
            if not (_digits(lo) and _digits(hi)) or int(lo) > int(hi):
                return None
            rng = range(int(lo), int(hi) + 1)
        elif _digits(part):
            rng = range(int(part), int(part) + 1)
        else:
            return None
        for n in rng:
            if not 1 <= n <= maximum:
                return None
            if n not in result:
                result.append(n)
    return result or None


# ------------------------------------------------------------------ utilità

def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"~{max(seconds, 1)} s"
    return f"~{round(seconds / 60)} min"


def validate_host(value: str) -> str | None:
    if any(ch.isspace() for ch in value) or len(value) > 253:
        return "Indirizzo non valido (niente spazi)."
    return None


def validate_port(value: str) -> str | None:
    if not _digits(value) or not 1 <= int(value) <= 65535:
        return "La porta deve essere un numero da 1 a 65535."
    return None


def default_ssh_key() -> str | None:
    for name in ("id_ed25519", "id_ecdsa", "id_rsa", "lra_cliente"):
        p = Path.home() / ".ssh" / name
        if p.exists():
            return str(p)
    return None


def find_reports(output_dir: str | Path, limit: int = 10) -> list[ReportInfo]:
    """Ultimi report generati in `output_dir` (cartelle `server-*` con assessment.json), dal più recente."""
    base = Path(output_dir)
    if not base.is_dir():
        return []

    def mtime(p: Path) -> float:
        try:
            return p.stat().st_mtime
        except OSError:
            return 0.0
    # Le cartelle si chiamano server-<target>-<data>: l'ordine alfabetico non è quello temporale.
    dirs = sorted((p for p in base.glob("server-*") if p.is_dir()), key=mtime, reverse=True)[:300]
    found: list[ReportInfo] = []
    for d in dirs:
        data_file = d / "assessment.json"
        if not data_file.exists():
            continue
        try:
            data = json.loads(data_file.read_text(encoding="utf-8"))
            risk = data.get("risk", {})
            counts = {str(k): int(v) for k, v in data.get("counts", {}).items()}
            started = str(data.get("started_at", ""))
            found.append(ReportInfo(
                path=d,
                target=clean_text(str(data.get("target", "?"))),
                level=str(risk.get("level", "?")),
                score=int(risk.get("score", 0)),
                total=len(data.get("findings", [])),
                counts=counts,
                when=_pretty_when(started),
                started=_sortable(started),
            ))
        except (OSError, ValueError, TypeError, AttributeError):
            continue   # file rovinato o non nostro: lo si ignora
    found.sort(key=lambda r: r.started, reverse=True)
    return found[:limit]


def _sortable(iso: str) -> str:
    """Data ISO in UTC, confrontabile come stringa ("" se non valida)."""
    try:
        when = datetime.fromisoformat(iso)
        if when.tzinfo is not None:
            when = when.astimezone(timezone.utc).replace(tzinfo=None)
        return when.isoformat()
    except ValueError:
        return ""


def _pretty_when(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return "?"


def check_environment() -> list[tuple[str, str, str]]:
    """Controlli sulla macchina da cui si lancia lo strumento: (stato, voce, dettaglio).

    stato: "ok" | "warn" | "fail".
    """
    rows: list[tuple[str, str, str]] = []
    v = sys.version_info
    rows.append(("ok" if v >= (3, 12) else "fail", "Python",
                 f"{v.major}.{v.minor}.{v.micro}" + ("" if v >= (3, 12) else " (serve 3.12 o superiore)")))
    for mod, label in (("paramiko", "paramiko (modalità SSH)"), ("yaml", "PyYAML (config)"),
                       ("defusedxml", "defusedxml (parser XML)")):
        ok = importlib.util.find_spec(mod) is not None
        rows.append(("ok" if ok else "fail", label, "installato" if ok else "mancante: pip install -e ."))
    system = platform.system()
    if system == "Linux":
        rows.append(("ok", "Sistema", "Linux: la scansione locale è supportata"))
    elif system == "Darwin":
        rows.append(("ok", "Sistema", "macOS: la scansione locale è supportata"))
    else:
        rows.append(("warn", "Sistema", f"{system}: per analizzare un Linux o un Mac usa la modalità SSH"))
        return rows
    for binary, label in EXTERNAL_BINARIES:
        path = shutil.which(binary)
        rows.append(("ok" if path else "warn", label,
                     path or "non installato (verrà installato se l'installazione automatica è attiva)"))
    return rows


# ------------------------------------------------------------------ app

class MenuApp:
    def __init__(self, backend: Backend, console: Console | None = None,
                 banner_fn: Callable[[], None] | None = None) -> None:
        self.backend = backend
        self.io = console or Console()
        self.banner_fn = banner_fn
        self.settings = backend.defaults()
        self.ssh = SshProfile(user=_current_user(), key=default_ssh_key())
        self.last: LastScan | None = None
        self.last_plan: ScanPlan | None = None

    # ---- ciclo principale
    def run(self) -> int:
        io = self.io
        if self.banner_fn:
            self.banner_fn()
        first = True
        while True:
            if not first:
                io.say()
            first = False
            self._header()
            try:
                choice = io.choose("Cosa vuoi fare?", [
                    ("scan", "Nuova scansione", "guidata: locale o SSH"),
                    ("quick", "Scansione rapida", "controlli nativi su questa macchina"),
                    ("again", "Ripeti l'ultima scansione", "stesso obiettivo e stessi controlli"),
                    ("reports", "Report precedenti", "elenco, apertura e confronto"),
                    ("optional", "Strumenti opzionali", "Trivy, AIDE, rkhunter nella scansione completa"),
                    ("settings", "Impostazioni", "per questa sessione"),
                    ("doctor", "Verifica ambiente", "cosa è installato su questa macchina"),
                    ("fleet", "Più host", "da un inventario YAML, in parallelo"),
                    ("integrations", "Integrazioni", "Wazuh, copertura ATT&CK, rapporti polyscan"),
                    ("help", "Guida", "come funziona"),
                ], zero="Esci")
            except Back:
                io.say("\n  Arrivederci.")
                return 0
            except Quit:
                return 0
            try:
                getattr(self, "_do_" + choice)()
            except Back:
                continue      # torna al menu principale
            except Quit:
                return 0

    def _header(self) -> None:
        io = self.io
        s = self.settings
        cfg = self.backend.config_path + ("" if self.backend.config_loaded else " (non trovato: valori di default)")
        lines = [
            ("bold", "WatchDog · Risk Assessor per Linux e macOS"),
            ("", f"Config: {cfg}"),
            ("", f"Installazione tool: {_yn(s.allow_install)} · Pulizia finale: {_yn(not s.keep_tools)}"),
            ("", f"Report: {s.output_dir}/ ({', '.join(s.formats)})"),
        ]
        if s.extra_tools:
            lines.append(("", f"Strumenti opzionali aggiunti: {', '.join(s.extra_tools)}"))
        if self.last:
            style = _LEVEL_STYLE.get(self.last.level, "")
            lines.append((style, f"Ultima scansione: {self.last.target} · {self.last.level} "
                                 f"{self.last.score}/100 · {self.last.total} finding"))
        io.box(lines)

    # ---- scansioni
    def _do_scan(self) -> None:
        io = self.io
        mode = io.choose("Dove vuoi eseguire la scansione?", [
            ("local", "Questa macchina", "Linux o macOS"),
            ("ssh", "Una macchina remota", "via SSH"),
        ])
        ssh = pw = None
        if mode == "ssh":
            ssh, pw = self._ask_ssh()
        elif platform.system() not in ("Linux", "Darwin"):
            io.warn(f"Questa macchina è {platform.system()}: i controlli sono pensati per Linux e macOS. "
                    "Per analizzare un server Linux scegli la modalità SSH.")
            if not io.confirm("Continuare comunque?", default=False):
                raise Back
        presets = self.backend.presets(tuple(self.settings.extra_tools))
        options = [(str(i), label, note) for i, (label, note, _) in enumerate(presets)]
        options.append(("custom", "Personalizzata…", "scegli i singoli controlli"))
        key = io.choose("Che tipo di scansione?", options, default="0")
        if key == "custom":
            tools = self._ask_custom()
            label = f"Personalizzata ({len(tools)} controlli)"
        else:
            label, _, tools = presets[int(key)]
        external = self._ask_external(ssh) if ssh else False
        self._confirm_and_run(ScanPlan(mode=mode, label=label, tools=tools,
                                       settings=replace(self.settings), ssh=ssh, ssh_password=pw,
                                       external_scan=external))

    def _ask_external(self, ssh: SshProfile) -> bool:
        """Scansione Nmap dall'esterno: richiede una conferma esplicita di autorizzazione."""
        io = self.io
        io.say()
        io.say(io.c("dim", f"  Nmap dall'esterno: scansiona {ssh.host} dal TUO PC, come farebbe un attaccante "
                           "in rete. Serve nmap installato qui."))
        if not io.confirm("Aggiungere la scansione dall'esterno?", default=False):
            return False
        return io.confirm(f"Hai l'autorizzazione a scansionare {ssh.host}?", default=False)

    def _do_quick(self) -> None:
        io = self.io
        tools = [name for name, kind in self.backend.checks() if kind == "native"]
        plan = ScanPlan(mode="local", label="Controlli nativi", tools=tools,
                        settings=replace(self.settings))
        if platform.system() not in ("Linux", "Darwin"):
            io.warn(f"Questa macchina è {platform.system()}: i controlli sono pensati per Linux e macOS.")
        self._confirm_and_run(plan)

    def _do_again(self) -> None:
        if not self.last_plan:
            self.io.warn("Non c'è ancora nessuna scansione da ripetere in questa sessione.")
            return
        old = self.last_plan
        plan = replace(old, settings=replace(self.settings), sudo_password=None)
        if plan.ssh and plan.ssh.use_password and not plan.ssh_password:
            plan.ssh_password = self.io.ask("Password SSH", secret=True)
        self._confirm_and_run(plan)

    def _ask_ssh(self) -> tuple[SshProfile, str | None]:
        io = self.io
        prev = self.ssh
        io.say()
        io.say("  " + io.c("bold", "Connessione SSH"))
        io.say(io.c("dim", "  Invio accetta il valore tra parentesi. Ctrl+C torna al menu."))
        io.say()
        host = io.ask("Host o indirizzo IP", prev.host or None, validate_host)
        user = io.ask("Utente", prev.user or None)
        port = int(io.ask("Porta", str(prev.port), validate_port))
        method = io.choose("Come ti autentichi?", [
            ("key", "Chiave SSH", "consigliato"),
            ("password", "Password", "verrà chiesta in modo nascosto"),
        ], default="password" if prev.use_password else "key")
        key: str | None = None
        password: str | None = None
        if method == "key":
            key = os.path.expanduser(io.ask("File della chiave privata", prev.key or None))
            if not Path(key).exists():
                io.warn(f"Il file {key} non esiste: la connessione fallirà se non è l'unica chiave disponibile.")
        else:
            password = io.ask("Password SSH", secret=True)
        accept = io.confirm("Accettare automaticamente la chiave host se sconosciuta? "
                            "(meno sicuro: solo su reti fidate)", default=prev.accept_new_host_key)
        profile = SshProfile(host=host, user=user, port=port, key=key,
                             use_password=method == "password", accept_new_host_key=accept)
        self.ssh = profile
        return profile, password

    def _ask_custom(self) -> list[str]:
        checks = self.backend.checks()
        options = [(name, CHECK_LABELS.get(name, name),
                    "controllo nativo" if kind == "native" else "tool esterno")
                   for name, kind in checks]
        return self.io.choose_many("Scegli i controlli da eseguire", options)

    def _confirm_and_run(self, plan: ScanPlan) -> None:
        io = self.io
        steps, seconds = self.backend.estimate(plan.tools, plan.settings, external=plan.external_scan)
        kinds = dict(self.backend.checks())
        native = [t for t in plan.tools if kinds.get(t) == "native"]
        external = [t for t in plan.tools if kinds.get(t) != "native"]
        io.say()
        io.rule("Riepilogo")
        io.say(f"  Obiettivo        {io.c('bold', plan.target)}" + (" (SSH)" if plan.mode == "ssh" else " (locale)"))
        io.say(f"  Tipo             {plan.label}")
        io.say(f"  Controlli        {len(native)} nativi, {len(external)} tool esterni")
        if plan.external_scan:
            io.say(f"  Dall'esterno     Nmap dal tuo PC verso {plan.ssh.host}")
        io.say(f"  Durata stimata   {format_duration(seconds)} " + io.c("dim", "(indicativa)"))
        s = plan.settings
        if external:
            install = "sì: i tool mancanti verranno installati" if s.allow_install else "no: solo i tool già presenti"
            io.say(f"  Installazione    {install}")
            if s.allow_install:
                io.say(f"  Pulizia finale   {'sì: rimuove solo ciò che ha installato' if not s.keep_tools else 'no: i tool restano installati'}")
                if s.allow_epel:
                    io.say("  EPEL             attivato se serve (RHEL e derivate), poi rimosso")
        else:
            io.say(f"  Installazione    {io.c('dim', 'nessuna: solo letture')}")
        io.say(f"  Report           {s.output_dir}/ ({', '.join(s.formats)})")
        io.rule()
        if plan.mode == "local":
            io.say(io.c("dim", "  Verranno eseguiti comandi sulla tua macchina."))
        else:
            io.say(io.c("dim", "  Usa lo strumento solo su sistemi per cui hai l'autorizzazione."))
        io.say()
        if not io.confirm("Avviare la scansione?", default=True):
            raise Back
        if s.allow_install and s.ask_sudo and plan.sudo_password is None:
            plan.sudo_password = io.ask("Password sudo (serve solo per installare/rimuovere pacchetti)",
                                        secret=True)
        self._run(plan)

    def _run(self, plan: ScanPlan) -> None:
        io = self.io
        io.say()
        try:
            assessment = self.backend.run_scan(plan)
        except KeyboardInterrupt:
            io.say("\n  Scansione interrotta. Nessun report generato.")
            raise Back from None
        except ScanError:
            return
        finally:
            plan.sudo_password = None
            plan.ssh_password = None      # non resta in memoria dopo l'uso
        paths = self.backend.write_reports(assessment, plan.settings)
        self.backend.show_summary(assessment, paths)
        self.last_plan = replace(plan, ssh_password=None, sudo_password=None)
        self.last = LastScan(target=clean_text(assessment.target), level=assessment.risk_level,
                             score=assessment.risk_score, total=len(assessment.findings), paths=paths)
        self._after_scan(paths)

    def _after_scan(self, paths: list[Path]) -> None:
        io = self.io
        html = next((p for p in paths if p.suffix == ".html"), None)
        options = []
        if html:
            options.append(("open", "Apri il report HTML nel browser", ""))
        options.append(("menu", "Torna al menu", ""))
        try:
            choice = io.choose("", options, zero="Esci", default="menu")
        except Back:
            raise Quit from None
        if choice == "open" and html:
            self._open(html)

    # ---- report precedenti
    def _do_reports(self) -> None:
        io = self.io
        reports = find_reports(self.settings.output_dir)
        if not reports:
            io.warn(f"Nessun report trovato in {self.settings.output_dir}/ "
                    "(la cartella cambia con le impostazioni o il file config.yaml).")
            return
        options = [(str(i), f"{r.when}  {r.target}",
                    f"{r.level} {r.score}/100 · {r.total} finding")
                   for i, r in enumerate(reports)]
        key = io.choose("Ultimi report", options)
        r = reports[int(key)]
        io.say()
        io.rule("Dettaglio")
        style = _LEVEL_STYLE.get(r.level, "")
        io.say(f"  Obiettivo   {r.target}")
        io.say(f"  Data        {r.when}")
        io.say(f"  Rischio     {io.c(style, r.level)}  ({r.score}/100)")
        parts = [f"{r.counts.get(s, 0)} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        io.say(f"  Finding     {' · '.join(parts)}")
        io.say(f"  Cartella    {r.path}")
        io.rule()
        actions = [("open", "Apri il report HTML", "nel browser")] if r.html else []
        others = [x for x in reports if x.path != r.path]
        if others and getattr(self.backend, "compare_reports", None):
            actions.append(("compare", "Confronta con un altro report", "nuovi, risolti, punteggio"))
        if not actions:
            return
        what = io.choose("Cosa vuoi fare?", actions)
        if what == "open":
            self._open(r.html)
            return
        other_options = [(str(i), f"{o.when}  {o.target}", f"{o.level} {o.score}/100")
                         for i, o in enumerate(others)]
        o = others[int(io.choose("Con quale report?", other_options))]
        older, newer = (o, r) if o.started <= r.started else (r, o)
        self.backend.compare_reports(older.path, newer.path)

    # ---- più host
    def _do_fleet(self) -> None:
        io = self.io
        if not getattr(self.backend, "run_fleet", None):
            io.warn("Non disponibile.")
            return
        io.say(io.c("dim", "  L'inventario è un file YAML con l'elenco degli host (esempio: docs/inventory.example.yaml)."))
        io.say(io.c("dim", "  Le password non vanno nel file: si indicano i nomi delle variabili d'ambiente."))

        def exists(value: str) -> str | None:
            return None if Path(value).expanduser().is_file() else "File non trovato."
        inventory = str(Path(io.ask("File dell'inventario", "inventory.yaml", exists)).expanduser())
        presets = self.backend.presets(tuple(self.settings.extra_tools))
        options = [(str(i), label, note) for i, (label, note, _) in enumerate(presets[:4])]
        label, _, tools = presets[int(io.choose("Che tipo di scansione su ogni host?", options, default="0"))]

        def number(value: str) -> str | None:
            return None if _digits(value) and 1 <= int(value) <= 16 else "Un numero da 1 a 16."
        parallel = int(io.ask("Quanti host alla volta", "4", number))
        if not io.confirm(f"Avviare '{label}' sugli host dell'inventario, {parallel} alla volta?", default=True):
            raise Back
        try:
            paths = self.backend.run_fleet(inventory, tools, replace(self.settings), parallel)
        except ScanError:
            return
        html = next((p for p in paths if str(p).endswith(".html")), None)
        if html and io.confirm("Aprire il riepilogo HTML nel browser?", default=True):
            self._open(html)

    # ---- integrazioni
    def _do_integrations(self) -> None:
        io = self.io
        while True:
            s = self.settings
            io.say()
            io.say(io.c("dim", "  Valide per questa sessione; dalla riga di comando: --wazuh-log, "
                               "--attack-layer, --import-polyscan."))
            try:
                key = io.choose("Integrazioni", [
                    ("wazuh", f"Invia a Wazuh: {s.wazuh_log or 'no'}",
                     "file di righe JSON letto dall'agente Wazuh (vedi integrations/wazuh)"),
                    ("layer", f"Copertura di rilevamento ATT&CK: {s.attack_layer or 'no'}",
                     "layer di ATT&CK Navigator, per esempio da detection-engineering-lab"),
                    ("poly", f"Rapporti polyscan da importare: {len(s.polyscan_reports) or 'nessuno'}",
                     "risultati su codice e applicazioni nello stesso report"),
                ])
            except Back:
                return

            def existing(value: str) -> str | None:
                return None if not value or Path(value).expanduser().is_file() else "File non trovato."
            if key == "wazuh":
                s.wazuh_log = io.ask("File per Wazuh (vuoto = disattiva)", s.wazuh_log or "/var/log/watchdog/wazuh.jsonl")
                if s.wazuh_log.strip().lower() in ("", "no"):
                    s.wazuh_log = ""
            elif key == "layer":
                value = io.ask("File del layer (vuoto = nessuno)", s.attack_layer, existing)
                s.attack_layer = str(Path(value).expanduser()) if value else ""
            elif key == "poly":
                value = io.ask("Rapporti JSON separati da virgola (vuoto = nessuno)",
                               ",".join(s.polyscan_reports),
                               lambda v: next((f"File non trovato: {x}" for x in v.split(",")
                                               if x.strip() and not Path(x.strip()).expanduser().is_file()), None))
                s.polyscan_reports = [str(Path(x.strip()).expanduser()) for x in value.split(",") if x.strip()]

    def _open(self, path: Path) -> None:
        io = self.io
        try:
            opened = webbrowser.open(path.resolve().as_uri())
        except Exception:
            opened = False
        if opened:
            io.ok("Aperto nel browser.")
        else:
            io.warn(f"Non riesco ad aprire il browser da qui. Apri il file a mano:\n    {path.resolve()}")

    # ---- strumenti opzionali
    def _do_optional(self) -> None:
        io = self.io
        get = getattr(self.backend, "optional_tools", None)
        tools = get() if get else []
        if not tools:
            io.warn("Nessuno strumento opzionale disponibile.")
            return
        while True:
            s = self.settings
            io.say()
            io.say(io.c("dim", "  Non fanno parte della scansione completa finché non li aggiungi. "
                               "La scelta vale per questa sessione"))
            io.say(io.c("dim", "  (per sempre: 'enabled: true' in config.yaml; da riga di comando: --all --with)."))
            options = []
            for name, label, note, in_config in tools:
                if in_config:
                    state = "sempre (config.yaml)"
                else:
                    state = "sì" if name in s.extra_tools else "no"
                options.append((name, f"{label}: {state}", note))
            try:
                key = io.choose("Aggiungere alla scansione completa", options)
            except Back:
                return
            in_config = next(c for n, _, _, c in tools if n == key)
            if in_config:
                io.warn("Già incluso da config.yaml: per toglierlo imposta 'enabled: false'.")
            elif key in s.extra_tools:
                s.extra_tools.remove(key)
            else:
                s.extra_tools.append(key)

    # ---- impostazioni
    def _do_settings(self) -> None:
        io = self.io
        while True:
            s = self.settings
            io.say()
            io.say(io.c("dim", "  Valide per questa sessione. Per renderle permanenti modifica config.yaml."))
            try:
                key = io.choose("Impostazioni", [
                    ("install", f"Installazione automatica dei tool: {_yn(s.allow_install)}",
                     "se no, usa solo i tool già presenti"),
                    ("keep", f"Rimuovi i tool a fine scansione: {_yn(not s.keep_tools)}",
                     "toglie solo ciò che è stato installato"),
                    ("clam", f"ClamAV su tutto il filesystem: {_yn(s.full_clamav)}", "molto lento"),
                    ("sudo", f"Chiedi la password sudo prima di ogni scansione: {_yn(s.ask_sudo)}",
                     "solo se serve installare"),
                    ("epel", f"Attiva EPEL se serve (RHEL, Rocky, Alma): {_yn(s.allow_epel)}",
                     "per Lynis, rkhunter e ClamAV; viene rimosso alla fine"),
                    ("formats", f"Formati dei report: {','.join(s.formats)}", "json, md, html"),
                    ("dir", f"Cartella dei report: {s.output_dir}", ""),
                ])
            except Back:
                return
            if key == "install":
                s.allow_install = not s.allow_install
            elif key == "keep":
                s.keep_tools = not s.keep_tools
            elif key == "clam":
                s.full_clamav = not s.full_clamav
            elif key == "sudo":
                s.ask_sudo = not s.ask_sudo
            elif key == "epel":
                s.allow_epel = not s.allow_epel
            elif key == "formats":
                s.formats = self._ask_formats(s.formats)
            elif key == "dir":
                s.output_dir = io.ask("Cartella dei report", s.output_dir)

    def _ask_formats(self, current: list[str]) -> list[str]:
        def check(value: str) -> str | None:
            items = [x.strip().lower() for x in value.split(",") if x.strip()]
            bad = [x for x in items if x not in VALID_FORMATS]
            if bad or not items:
                return f"Formati ammessi: {', '.join(VALID_FORMATS)} (separati da virgola)."
            return None
        raw = self.io.ask("Formati (json, md, html)", ",".join(current), check)
        out: list[str] = []
        for x in (i.strip().lower() for i in raw.split(",") if i.strip()):
            if x not in out:
                out.append(x)
        return out

    # ---- verifica ambiente e guida
    def _do_doctor(self) -> None:
        io = self.io
        io.say()
        io.rule("Verifica ambiente")
        symbol = {"ok": ("green", "✓"), "warn": ("yellow", "!"), "fail": ("red", "✗")}
        for status, label, detail in check_environment():
            style, mark = symbol[status]
            io.say(f"  {io.c(style, mark)} {label:<28}{io.c('dim', detail)}")
        io.rule()
        io.say(io.c("dim", "  Riguarda la macchina da cui lanci lo strumento; con SSH i tool "
                           "vengono cercati sul server."))

    def _do_help(self) -> None:
        io = self.io
        io.say()
        io.rule("Guida")
        for style, text in [
            ("bold", "Come muoversi"),
            ("", "  Scrivi il numero della voce e premi Invio. 0 torna indietro (o esce dal menu principale)."),
            ("", "  Ctrl+C annulla l'operazione e torna al menu. Ctrl+D esce."),
            ("", ""),
            ("bold", "Tipi di scansione"),
            ("", "  Completa: tutti i controlli nativi e i tool esterni abilitati in config.yaml."),
            ("", "  Nativi: leggono configurazione e stato del sistema, senza installare nulla."),
            ("", "  Tool esterni: Nmap, Lynis, chkrootkit… se mancano vengono installati e poi rimossi."),
            ("", "  Strumenti opzionali: Trivy, AIDE e rkhunter si aggiungono dalla voce del menu."),
            ("", "  Più host: un inventario YAML, analizzato in parallelo, con un riepilogo complessivo."),
            ("", ""),
            ("bold", "Report"),
            ("", "  L'HTML ha una heatmap delle aree: clicca un'area per vedere i controlli e i finding."),
            ("", "  Ogni scansione si confronta da sola con la precedente dello stesso obiettivo."),
            ("", "  Da 'Report precedenti' puoi confrontare due report a scelta."),
            ("", ""),
            ("bold", "Prima di avviare"),
            ("", "  Vedrai un riepilogo con obiettivo, controlli, durata stimata e cosa verrà installato."),
            ("", "  I report finiscono nella cartella indicata; contengono dettagli sensibili."),
            ("", ""),
            ("bold", "Per l'uso da script"),
            ("", "  python -m risk_assessor local --all    (tutte le opzioni: --help)"),
        ]:
            io.say(io.c(style, text) if style else text)
        io.rule()


def _yn(value: bool) -> str:
    return "sì" if value else "no"


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""

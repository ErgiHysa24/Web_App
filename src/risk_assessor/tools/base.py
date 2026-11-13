"""Base class for external security tools.

Ogni tool dichiara:
- `name`: il binario da cercare sul target;
- `packages`: i pacchetti da installare, per famiglia di distribuzione (vedi sotto);
- `platforms`: dove ha senso eseguirlo (linux, darwin).

Installazione e rimozione sono gestite dal ToolManager (tools/manager.py) tramite il
gestore dei pacchetti del target: i tool non installano nulla da soli.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from enum import Enum

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, privileges
from risk_assessor.models import Finding


class ToolState(str, Enum):
    """Stato del lifecycle di un tool."""
    UNKNOWN = "UNKNOWN"
    ABSENT = "ABSENT"
    PRE_EXISTING = "PRE_EXISTING"
    INSTALLED_BY_ASSESSOR = "INSTALLED_BY_ASSESSOR"
    REMOVED = "REMOVED"
    FAILED_CLEANUP = "FAILED_CLEANUP"


# Cartelle in cui cercare un binario se non è nel PATH: le shell SSH non interattive
# spesso non hanno /usr/sbin, e su macOS Homebrew sta in /opt/homebrew o /usr/local.
COMMON_BIN_PATHS = [
    "/usr/sbin", "/usr/bin", "/sbin", "/bin",
    "/usr/local/sbin", "/usr/local/bin",
    "/opt/homebrew/bin", "/opt/homebrew/sbin",
]

# Un solo comando: prima il PATH (command -v, builtin POSIX), poi le cartelle note.
# Il nome del tool arriva come argomento ($1), mai concatenato nello script.
_FIND_SCRIPT = (
    'command -v "$1" 2>/dev/null && exit 0; '
    'for d in ' + " ".join(COMMON_BIN_PATHS) + '; do '
    'if [ -x "$d/$1" ]; then echo "$d/$1"; exit 0; fi; done; exit 1'
)


def find_tool(executor: BaseExecutor, name: str) -> str | None:
    """Percorso assoluto del binario sul target, o None se non c'è."""
    out, _, rc = executor.execute_command(["sh", "-c", _FIND_SCRIPT, "sh", name])
    lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
    if rc == 0 and lines:
        return lines[0]
    return None


# Quali dei file passati come argomenti esistono già (uno per riga).
EXISTING_FILES_SCRIPT = 'for f in "$@"; do [ -e "$f" ] && printf "%s\\n" "$f"; done; exit 0'


def track_new_files(executor: BaseExecutor, tracker, record_name: str, candidates: list[str]) -> None:
    """Registra la rimozione, a fine assessment, dei file che il tool creerà.

    Si chiama subito dopo l'installazione, prima di eseguire il tool: dei `candidates` si
    rimuoveranno solo quelli che in questo momento NON esistono. Se non si riesce a
    verificarlo non si registra nulla (meglio un file in più sul sistema che cancellare
    una baseline dell'amministratore).
    """
    from risk_assessor.lifecycle.installation import InstallState

    priv = privileges(executor)
    if priv is None:
        return
    out, _, rc = executor.execute_command(priv + ["sh", "-c", EXISTING_FILES_SCRIPT, "sh", *candidates])
    if rc != 0:
        return
    existing = {ln.strip() for ln in out.splitlines() if ln.strip()}
    files = [f for f in candidates if f not in existing]
    if not files:
        return

    def remover(ex: BaseExecutor, _sudo=None) -> bool:
        p = privileges(ex)
        if p is None:
            return False
        return ex.execute_command(p + ["rm", "-f", "--", *files])[2] == 0

    tracker.record(record_name, "", InstallState.INSTALLED_BY_ASSESSOR, remover)


class SecurityTool(ABC):
    """Abstract base per tool esterni (nmap, lynis, ...).

    Il ciclo di vita è:
        detect -> (install) -> run -> collect_results -> (cleanup)
    """

    name: str = ""
    # Nome "storico" del pacchetto, usato se la famiglia del target non è in `packages`.
    package: str | None = None
    # Pacchetti per famiglia (debian, fedora, rhel, suse, arch, alpine, macos).
    # None = non disponibile nei repository di quella famiglia. "*" vale per le altre.
    packages: dict[str, list[str] | None] = {}
    # Famiglie in cui i pacchetti stanno nel repository EPEL (non attivo di default).
    epel_families: frozenset[str] = frozenset()
    # Piattaforme su cui il tool ha senso.
    platforms: frozenset[str] = frozenset({"linux"})

    def __init__(self) -> None:
        self.state: ToolState = ToolState.UNKNOWN
        self._path: str = self.name or ""

    # ---- metodi che i tool DEVONO implementare ----

    @abstractmethod
    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        """Esegue il tool e ritorna l'output grezzo (stdout)."""
        ...

    @abstractmethod
    def parse(self, raw_output: str) -> list[Finding]:
        """Trasforma l'output grezzo in finding normalizzati."""
        ...

    # ---- compatibilità con il target ----

    def unsupported_reason(self, host: HostInfo) -> str | None:
        """Perché il tool non si può usare su questo target (None = si può)."""
        if host.system != "unknown" and host.system not in self.platforms:
            return f"non disponibile su {host.platform_label}"
        return None

    def packages_for(self, host: HostInfo) -> list[str] | None:
        """Pacchetti da installare sul target, o None se non esistono per la sua famiglia."""
        if host.family in self.packages:
            pkgs = self.packages[host.family]
            return list(pkgs) if pkgs else None
        if "*" in self.packages:
            pkgs = self.packages["*"]
            return list(pkgs) if pkgs else None
        return [self.package] if self.package else None

    def unavailable_message(self, host: HostInfo) -> str:
        """Perché non si può installare (quando packages_for restituisce None)."""
        return f"non disponibile nei repository di {host.pretty or host.family_label}"

    def needs_epel(self, host: HostInfo) -> bool:
        return host.family in self.epel_families

    # ---- metodi con default sensato ----

    def detect(self, executor: BaseExecutor) -> bool:
        """Ritorna True se il tool è installato. Salva il path in self._path."""
        path = find_tool(executor, self.name)
        if path:
            self._path = path
            self.state = ToolState.PRE_EXISTING
            return True
        self.state = ToolState.ABSENT
        return False

    def install_custom(self, executor: BaseExecutor, tracker, sudo_ctx=None):
        """Installazione alternativa al package manager (per tool non presenti nei repository).

        Ritorna None se il tool usa il normale package manager; altrimenti ritorna lo
        `InstallState` risultante, dopo aver registrato nel `tracker` ciò che serve alla
        rimozione (un `remover`). Default: None.
        """
        return None

    def post_install(self, executor: BaseExecutor, tracker, sudo_ctx=None) -> None:
        """Hook chiamato dal ToolManager DOPO che l'assessor ha installato il tool.

        Serve ai tool che hanno bisogno di componenti aggiuntivi (es. OpenSCAP
        e il contenuto SCAP). Ogni pacchetto extra installato qui DEVE essere
        registrato nel `tracker`, altrimenti il cleanup non lo rimuoverebbe.
        Default: non fa nulla.
        """
        return None

    def version(self, executor: BaseExecutor) -> str | None:
        """Ritorna la versione del tool, se disponibile."""
        return None

"""Gestori di pacchetti: apt, dnf, yum, zypper, pacman, apk (Linux) e Homebrew (macOS).

Ogni gestore è descritto da una tabella di comandi; il comportamento comune (sudo,
aggiornamento degli indici e nuovo tentativo) sta in un solo punto.

Scelte:
- apt gira in modalità non interattiva e senza i pacchetti "consigliati": un pacchetto
  che fa domande (debconf) bloccherebbe l'assessment fino al timeout.
- pacman non aggiorna mai gli indici da solo (`-Sy` seguito da `-S` è un aggiornamento
  parziale, sconsigliato su Arch): se l'installazione fallisce lo si dice.
- Homebrew non va mai eseguito come root e non aggiorna se stesso a ogni installazione.
- Installare non deve mai togliere nulla (apt `--no-remove`) e rimuovere tocca solo i
  pacchetti installati dall'assessment: niente rimozione "a cascata" delle dipendenze
  (dnf/yum senza clean_requirements_on_remove, zypper senza --clean-deps, pacman senza -s),
  perché una dipendenza potrebbe nel frattempo servire ad altro. Le dipendenze installate
  insieme ai tool possono quindi restare sul sistema (apk e Homebrew le gestiscono da soli).
"""
from __future__ import annotations

from dataclasses import dataclass

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import command_path, host_info
from risk_assessor.lifecycle.sudo import run_with_sudo

_BREW_ENV = ("env", "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_INSTALL_CLEANUP=1",
             "HOMEBREW_NO_ENV_HINTS=1", "HOMEBREW_NO_ANALYTICS=1")


def error_summary(text: str, rc: int) -> str:
    """Ultima riga significativa di un errore, corta e su una riga (per il report)."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    # Le righe di avviso non spiegano il fallimento: si preferiscono quelle d'errore.
    errors = [ln for ln in lines if ln.lower().startswith(("e:", "error", "errore", "sudo:", "fatal"))]
    line = (errors or lines or [f"codice di uscita {rc}"])[-1]
    return line[:160]


# Messaggi con cui i gestori dicono "questo pacchetto nei repository non c'è".
_NOT_FOUND = ("unable to locate package", "has no installation candidate", "no match for argument",
              "unable to find a match", "no provider of", "target not found",
              "unable to select packages", "no such package", "no available formula")


def is_not_found(error: str) -> bool:
    low = (error or "").lower()
    return any(m in low for m in _NOT_FOUND)


def _as_list(packages: str | list[str] | tuple[str, ...]) -> list[str]:
    if isinstance(packages, str):
        return packages.split()
    return [p for p in packages if p]


@dataclass(frozen=True)
class PackageManager:
    name: str
    install_prefix: tuple[str, ...]
    remove_prefix: tuple[str, ...]
    query_prefix: tuple[str, ...]          # + nome del pacchetto: rc 0 se installato
    refresh: tuple[str, ...] | None = None  # aggiornamento degli indici (nuovo tentativo)
    needs_root: bool = True
    status_text: str | None = None          # testo che conferma l'installazione (dpkg)

    def install_command(self, packages) -> list[str]:
        return list(self.install_prefix) + _as_list(packages)

    def remove_command(self, packages) -> list[str]:
        return list(self.remove_prefix) + _as_list(packages)

    def _run(self, executor: BaseExecutor, command: list[str], sudo_ctx=None):
        if self.needs_root:
            return run_with_sudo(executor, command, sudo_ctx=sudo_ctx)
        return executor.execute_command(command)

    def install(self, executor: BaseExecutor, packages, sudo_ctx=None) -> bool:
        return self.install_result(executor, packages, sudo_ctx)[0]

    def install_result(self, executor: BaseExecutor, packages, sudo_ctx=None) -> tuple[bool, str]:
        """(riuscita, motivo del fallimento): il motivo è l'ultima riga d'errore del gestore."""
        pkgs = _as_list(packages)
        if not pkgs:
            return False, "nessun pacchetto indicato"
        out, err, rc = self._run(executor, self.install_command(pkgs), sudo_ctx)
        if rc == 0:
            return True, ""
        if self.refresh is not None:
            # Indici vecchi o assenti (tipico di apt e apk appena installati): aggiorna e riprova.
            self._run(executor, list(self.refresh), sudo_ctx)
            out, err, rc = self._run(executor, self.install_command(pkgs), sudo_ctx)
            if rc == 0:
                return True, ""
        text = f"{out}\n{err}"
        if is_not_found(text):
            # La riga che lo dice può non essere l'ultima (dnf, apt): la si mette in evidenza.
            line = next(ln.strip() for ln in text.splitlines() if is_not_found(ln))
            return False, line[:160]
        return False, error_summary(err or out, rc)

    def remove(self, executor: BaseExecutor, packages, sudo_ctx=None) -> bool:
        pkgs = _as_list(packages)
        if not pkgs:
            return True
        _, _, rc = self._run(executor, self.remove_command(pkgs), sudo_ctx)
        return rc == 0

    def is_installed(self, executor: BaseExecutor, packages) -> bool:
        """True se TUTTI i pacchetti indicati sono installati."""
        pkgs = _as_list(packages)
        if not pkgs:
            return False
        for pkg in pkgs:
            out, _, rc = executor.execute_command(list(self.query_prefix) + [pkg])
            if rc != 0:
                return False
            if self.status_text is not None and self.status_text not in (out or ""):
                return False
        return True


def _apt() -> PackageManager:
    env = ("env", "DEBIAN_FRONTEND=noninteractive")
    return PackageManager(
        name="apt",
        install_prefix=env + ("apt-get", "install", "-y", "-qq", "--no-install-recommends", "--no-remove"),
        remove_prefix=env + ("apt-get", "remove", "-y", "-qq"),
        # dpkg -s dà rc 0 anche per pacchetti rimossi con la configurazione rimasta
        query_prefix=("dpkg-query", "-W", "-f=${Status}"),
        status_text="install ok installed",
        refresh=env + ("apt-get", "update", "-qq"),
    )


def _dnf(binary: str = "dnf") -> PackageManager:
    return PackageManager(
        name=binary,
        install_prefix=(binary, "install", "-y", "-q"),
        remove_prefix=(binary, "remove", "-y", "-q", "--setopt=clean_requirements_on_remove=False"),
        query_prefix=("rpm", "-q"),
    )


def _zypper() -> PackageManager:
    return PackageManager(
        name="zypper",
        install_prefix=("zypper", "--non-interactive", "--quiet", "install", "--no-recommends"),
        remove_prefix=("zypper", "--non-interactive", "--quiet", "remove"),
        query_prefix=("rpm", "-q"),
        refresh=("zypper", "--non-interactive", "--quiet", "refresh"),
    )


def _pacman() -> PackageManager:
    return PackageManager(
        name="pacman",
        install_prefix=("pacman", "-S", "--needed", "--noconfirm"),
        remove_prefix=("pacman", "-Rn", "--noconfirm"),
        query_prefix=("pacman", "-Q"),
    )


def _apk() -> PackageManager:
    return PackageManager(
        name="apk",
        install_prefix=("apk", "add", "-q"),
        remove_prefix=("apk", "del", "-q"),
        query_prefix=("apk", "info", "-e"),
        refresh=("apk", "update", "-q"),
    )


def _brew(path: str = "brew") -> PackageManager:
    return PackageManager(
        name="brew",
        install_prefix=_BREW_ENV + (path, "install", "-q"),
        remove_prefix=_BREW_ENV + (path, "uninstall", "-q"),
        query_prefix=(path, "list", "--versions"),
        needs_root=False,
    )


# Nomi storici, usati anche dai test.
def AptManager() -> PackageManager:      # noqa: N802
    return _apt()


def DnfManager() -> PackageManager:      # noqa: N802
    return _dnf("dnf")


def YumManager() -> PackageManager:      # noqa: N802
    return _dnf("yum")


def ZypperManager() -> PackageManager:   # noqa: N802
    return _zypper()


def PacmanManager() -> PackageManager:   # noqa: N802
    return _pacman()


def ApkManager() -> PackageManager:      # noqa: N802
    return _apk()


def BrewManager(path: str = "brew") -> PackageManager:  # noqa: N802
    return _brew(path)


def manager_by_name(name: str | None, executor: BaseExecutor | None = None) -> PackageManager | None:
    if name == "apt":
        return _apt()
    if name in ("dnf", "yum"):
        return _dnf(name)
    if name == "zypper":
        return _zypper()
    if name == "pacman":
        return _pacman()
    if name == "apk":
        return _apk()
    if name == "brew":
        path = command_path(executor, "brew") if executor is not None else None
        return _brew(path or "brew")
    return None


def detect_package_manager(executor: BaseExecutor) -> PackageManager | None:
    """Gestore dei pacchetti del target (quello tipico della sua famiglia, se presente)."""
    info = host_info(executor)
    if info.commands is not None:
        return manager_by_name(info.package_manager, executor)
    # Rilevamento iniziale non riuscito: chiedi i comandi uno per uno.
    for binary, name in (("apt-get", "apt"), ("dnf", "dnf"), ("yum", "yum"), ("zypper", "zypper"),
                         ("pacman", "pacman"), ("apk", "apk"), ("brew", "brew")):
        if command_path(executor, binary):
            return manager_by_name(name, executor)
    return None

"""Tracks which packages were installed by the assessor."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable
from enum import Enum

from risk_assessor.executor import BaseExecutor
from risk_assessor.lifecycle.package_manager import (
    detect_package_manager,
)


class InstallState(str, Enum):
    UNKNOWN = "UNKNOWN"
    PRE_EXISTING = "PRE_EXISTING"
    INSTALLED_BY_ASSESSOR = "INSTALLED_BY_ASSESSOR"
    REMOVED = "REMOVED"
    FAILED_INSTALL = "FAILED_INSTALL"
    FAILED_CLEANUP = "FAILED_CLEANUP"


@dataclass
class ToolRecord:
    tool_name: str
    package: str
    state: InstallState = InstallState.UNKNOWN
    # Rimozione personalizzata per i tool non installati dal package manager:
    # remover(executor, sudo_ctx) -> bool. Se assente si usa il package manager.
    remover: Callable | None = None
    # Motivo di un'installazione non riuscita (ultima riga d'errore del gestore).
    error: str = ""


@dataclass
class InstallationTracker:
    records: dict[str, ToolRecord] = field(default_factory=dict)

    def record(self, tool_name: str, package: str, state: InstallState,
               remover: Callable | None = None, error: str = "") -> None:
        self.records[tool_name] = ToolRecord(tool_name, package, state, remover, error)

    def get(self, tool_name: str) -> ToolRecord | None:
        return self.records.get(tool_name)

    def installed_by_assessor(self) -> list[ToolRecord]:
        return [
            r for r in self.records.values()
            if r.state == InstallState.INSTALLED_BY_ASSESSOR
        ]


def _install_package(pm, executor, package, sudo_ctx) -> tuple[bool, str]:
    """Installa uno o più pacchetti (separati da spazi) con il gestore dato."""
    if hasattr(pm, "install_result"):
        return pm.install_result(executor, package, sudo_ctx=sudo_ctx)
    return bool(pm.install(executor, package, sudo_ctx=sudo_ctx)), ""


def ensure_tool_installed(
    tracker: InstallationTracker,
    tool_name: str,
    package: str,
    executor: BaseExecutor,
    allow_install: bool = True,
    sudo_ctx=None,
) -> InstallState:
    """Verifica se il tool è installato. Se assente e allow_install, lo installa
    e lo registra nel tracker. Ritorna lo stato risultante.

    `package` può contenere più pacchetti separati da spazi: si installano (e quindi si
    registrano per la rimozione) SOLO quelli che mancano. Un pacchetto già presente, per
    esempio binutils per chkrootkit, appartiene al sistema e non va mai rimosso.
    """
    pm = detect_package_manager(executor)

    if pm is None:
        tracker.record(tool_name, package, InstallState.UNKNOWN)
        return InstallState.UNKNOWN

    missing = [p for p in package.split() if not pm.is_installed(executor, p)]
    if not missing:
        tracker.record(tool_name, package, InstallState.PRE_EXISTING)
        return InstallState.PRE_EXISTING

    if not allow_install:
        tracker.record(tool_name, package, InstallState.UNKNOWN)
        return InstallState.UNKNOWN

    to_install = " ".join(missing)
    ok, error = _install_package(pm, executor, to_install, sudo_ctx)
    if ok:
        tracker.record(tool_name, to_install, InstallState.INSTALLED_BY_ASSESSOR)
        return InstallState.INSTALLED_BY_ASSESSOR

    tracker.record(tool_name, package, InstallState.FAILED_INSTALL, error=error)
    return InstallState.FAILED_INSTALL

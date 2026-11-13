"""Cleanup of packages installed by the assessor."""
from __future__ import annotations
from dataclasses import dataclass, field

from risk_assessor.executor import BaseExecutor
from risk_assessor.lifecycle.installation import (
    InstallationTracker, InstallState,
)
from risk_assessor.lifecycle.package_manager import detect_package_manager


@dataclass
class CleanupReport:
    removed: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return not self.failed

    def summary(self) -> str:
        if self.success:
            return "SUCCESS"
        return f"WARNING: {len(self.failed)} pacchetti non rimossi"


def _remove_package(pm, executor, package, sudo_ctx) -> bool:
    """Rimuove uno o più pacchetti (separati da spazi) con il gestore dato."""
    return pm.remove(executor, package, sudo_ctx=sudo_ctx)


def run_cleanup(
    tracker: InstallationTracker,
    executor: BaseExecutor,
    sudo_ctx=None,
) -> CleanupReport:
    """Rimuove SOLO i pacchetti installati dall'assessor. Non tocca i pre-esistenti."""
    report = CleanupReport()

    # Tool installati senza package manager (es. un binario in una cartella temporanea):
    # si rimuovono con il loro remover, anche se il target non ha apt/dnf/...
    for rec in tracker.records.values():
        if rec.remover is None or rec.state != InstallState.INSTALLED_BY_ASSESSOR:
            continue
        try:
            ok = bool(rec.remover(executor, sudo_ctx))
        except Exception:
            ok = False
        rec.state = InstallState.REMOVED if ok else InstallState.FAILED_CLEANUP
        (report.removed if ok else report.failed).append(rec.tool_name)

    pm = detect_package_manager(executor)

    if pm is None:
        # Nessun package manager: marca pre-esistenti come kept, altri come failed
        for rec in tracker.records.values():
            if rec.state == InstallState.PRE_EXISTING:
                report.kept.append(rec.tool_name)
        for rec in tracker.installed_by_assessor():
            report.failed.append(rec.tool_name)
        return report

    # In ordine inverso rispetto all'installazione: prima i tool, poi ciò che è servito
    # a installarli (per esempio il repository EPEL).
    for rec in reversed(list(tracker.records.values())):
        if rec.state == InstallState.PRE_EXISTING:
            # NON rimuovere mai un pacchetto che era già presente
            report.kept.append(rec.tool_name)
            continue

        if rec.state != InstallState.INSTALLED_BY_ASSESSOR or rec.remover is not None:
            continue

        if _remove_package(pm, executor, rec.package, sudo_ctx):
            rec.state = InstallState.REMOVED
            report.removed.append(rec.tool_name)
        else:
            rec.state = InstallState.FAILED_CLEANUP
            report.failed.append(rec.tool_name)

    return report

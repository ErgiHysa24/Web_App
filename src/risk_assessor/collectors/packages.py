"""Pacchetti installati e aggiornamenti disponibili (sola lettura).

Funziona con il gestore del target: apt, dnf/yum, zypper, pacman, apk. Gli aggiornamenti
sono calcolati sugli indici già presenti sul sistema (nessun download): se gli indici
sono vecchi, il numero reale può essere più alto.
"""
from __future__ import annotations

from risk_assessor.collectors._platform import unverifiable, upgrade_hint
from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.lifecycle.package_manager import detect_package_manager
from risk_assessor.models import Confidence, Finding, Severity


def _installed(count: int, pm: str, how: str) -> Finding:
    return Finding(
        title=f"Pacchetti installati: {count}",
        category="packages",
        severity=Severity.INFO,
        description=f"Rilevati {count} pacchetti installati via {pm}.",
        evidence=f"{how} -> {count} pacchetti",
        recommendation="Nessuna azione richiesta.",
        source=f"packages:{pm}-installed",
        confidence=Confidence.HIGH,
    )


def _upgradable(lines: list[str], pm: str, reco: str, host: HostInfo) -> Finding:
    return Finding(
        title=f"Aggiornamenti disponibili: {len(lines)}",
        category="packages",
        severity=Severity.MEDIUM,
        description=f"{len(lines)} pacchetti hanno aggiornamenti disponibili.",
        evidence="\n".join(ln.strip() for ln in lines[:20])[:500],
        recommendation=reco,
        source=f"packages:{pm}-upgradable",
        confidence=Confidence.HIGH,
        command=upgrade_hint(host),
    )


def _updates_unknown(cmd: str, err: str) -> Finding:
    return unverifiable(
        "Aggiornamenti disponibili non verificabili",
        f"'{cmd}' non è riuscito: non si sa se ci sono aggiornamenti in attesa (per esempio "
        "senza accesso ai repository o senza permessi).",
        (err or "").strip()[:300] or f"{cmd}: errore", "packages:updates-unverifiable", "packages")


class PackagesCollector:
    name = "packages"

    def collect(self, executor: BaseExecutor) -> list[Finding]:
        host = host_info(executor)
        pm = host.package_manager
        if pm is None and host.commands is None:
            found = detect_package_manager(executor)
            pm = found.name if found else None
        if pm == "apt":
            return self._check_apt(executor, host)
        if pm in ("dnf", "yum"):
            return self._check_dnf(executor, pm, host)
        if pm == "zypper":
            return self._check_zypper(executor, host)
        if pm == "pacman":
            return self._check_pacman(executor, host)
        if pm == "apk":
            return self._check_apk(executor, host)
        return [unverifiable(
            "Pacchetti non verificabili",
            "Non è stato riconosciuto un gestore di pacchetti supportato (apt, dnf, yum, zypper, "
            "pacman, apk): aggiornamenti mancanti non controllati.",
            f"sistema: {host.pretty or 'sconosciuto'}", "packages:unverifiable", "packages")]

    # ---------------------------------------------------------------------- apt
    def _check_apt(self, executor, host: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["apt", "list", "--installed"])
        if rc == 0 and out.strip():
            findings.append(_installed(self._count_apt_lines(out), "apt", "apt list --installed"))

        out, err, rc = executor.execute_command(["apt", "list", "--upgradable"])
        if rc != 0:
            findings.append(_updates_unknown("apt list --upgradable", err))
        elif out.strip():
            lines = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("Listing")]
            if lines:
                findings.append(_upgradable(
                    lines, "apt", "Applicare gli aggiornamenti: 'apt update && apt upgrade'.", host))
        return findings

    # ------------------------------------------------------------------ dnf/yum
    def _check_dnf(self, executor, pm: str, host: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["rpm", "-qa"])
        if rc == 0 and out.strip():
            findings.append(_installed(len([ln for ln in out.splitlines() if ln.strip()]), pm, "rpm -qa"))

        # check-update esce con 100 quando ci sono aggiornamenti. Prima solo con la cache
        # (veloce, niente rete); se la cache non c'è, si scaricano gli indici.
        out, err, rc = executor.execute_command([pm, "-C", "-q", "check-update"])
        if rc not in (0, 100):
            out, err, rc = executor.execute_command([pm, "-q", "check-update"], timeout=300)
        if rc not in (0, 100):
            findings.append(_updates_unknown(f"{pm} check-update", err or out))
        elif rc == 100 and out.strip():
            updates = [
                line.strip() for line in out.splitlines()
                if line.strip() and len(line.split()) >= 2
                and not line.startswith(("Last metadata", "Obsoleting", "Security:", "Ultima"))
            ]
            if updates:
                findings.append(_upgradable(updates, pm, f"Applicare gli aggiornamenti: '{pm} upgrade'.", host))
        return findings

    # ------------------------------------------------------------------- zypper
    def _check_zypper(self, executor, host: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["rpm", "-qa"])
        if rc == 0 and out.strip():
            findings.append(_installed(len([ln for ln in out.splitlines() if ln.strip()]), "zypper", "rpm -qa"))

        out, err, rc = executor.execute_command(["zypper", "--non-interactive", "--no-refresh", "list-updates"])
        # 106 = alcuni repository saltati: l'elenco degli altri è comunque valido.
        if rc not in (0, 106):
            findings.append(_updates_unknown("zypper list-updates", err or out))
            return findings
        if not out.strip():
            return findings
        updates = [
            line for line in out.splitlines()
            if "|" in line and not line.lstrip().startswith(("S |", "--", "Repository"))
        ]
        if updates:
            findings.append(_upgradable(updates, "zypper", "Applicare gli aggiornamenti: 'zypper update'.", host))
        return findings

    # ------------------------------------------------------------------- pacman
    def _check_pacman(self, executor, host: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["pacman", "-Q"])
        if rc == 0 and out.strip():
            findings.append(_installed(len(out.strip().splitlines()), "pacman", "pacman -Q"))
        # -Qu confronta con gli indici locali (esce con 1 se non c'è niente da aggiornare).
        out, _, rc = executor.execute_command(["pacman", "-Qu"])
        lines = [ln for ln in out.splitlines() if ln.strip()] if rc == 0 else []
        if lines:
            findings.append(_upgradable(lines, "pacman", "Aggiornare tutto il sistema: 'pacman -Syu'.", host))
        return findings

    # ---------------------------------------------------------------------- apk
    def _check_apk(self, executor, host: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        out, _, rc = executor.execute_command(["apk", "info"])
        if rc == 0 and out.strip():
            findings.append(_installed(len(out.strip().splitlines()), "apk", "apk info"))
        out, _, rc = executor.execute_command(["apk", "version", "-l", "<"])
        lines = [ln for ln in out.splitlines() if " < " in ln] if rc == 0 else []
        if lines:
            findings.append(_upgradable(lines, "apk", "Applicare gli aggiornamenti: 'apk upgrade'.", host))
        return findings

    @staticmethod
    def _count_apt_lines(out: str) -> int:
        return sum(
            1 for line in out.splitlines()
            if line.strip() and not line.startswith("Listing")
        )

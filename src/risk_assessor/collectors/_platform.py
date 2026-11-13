"""Aiuti comuni ai controlli nativi per lavorare su qualsiasi distribuzione.

- stato dei servizi con l'init del target (systemd, OpenRC, runit);
- socket in ascolto con `ss` o, se manca, `netstat`;
- comandi di correzione scritti per il gestore di pacchetti e l'init del target;
- un finding esplicito quando qualcosa non si può verificare (mai "tutto a posto" in silenzio).
"""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.host import HostInfo, host_info
from risk_assessor.models import Confidence, Finding, Severity
from risk_assessor.tools.base import find_tool

# Nome del pacchetto quando cambia tra famiglie (altrimenti si usa il nome generico).
PACKAGE_NAMES: dict[str, dict[str, str]] = {
    "auditd": {"debian": "auditd", "fedora": "audit", "rhel": "audit", "suse": "audit",
               "arch": "audit", "alpine": "audit"},
    "pwquality": {"debian": "libpam-pwquality", "fedora": "libpwquality", "rhel": "libpwquality",
                  "suse": "pam_pwquality", "arch": "libpwquality", "alpine": "libpwquality"},
    "auto-updates": {"debian": "unattended-upgrades", "fedora": "dnf-automatic",
                     "rhel": "dnf-automatic"},
}

_INSTALL = {
    "apt": "sudo apt-get install {pkg}", "dnf": "sudo dnf install {pkg}", "yum": "sudo yum install {pkg}",
    "zypper": "sudo zypper install {pkg}", "pacman": "sudo pacman -S {pkg}", "apk": "sudo apk add {pkg}",
}
_UPGRADE = {
    "apt": "sudo apt-get update && sudo apt-get upgrade", "dnf": "sudo dnf upgrade",
    "yum": "sudo yum update", "zypper": "sudo zypper update", "pacman": "sudo pacman -Syu",
    "apk": "sudo apk update && sudo apk upgrade",
}


def package_name(host: HostInfo, generic: str) -> str:
    return PACKAGE_NAMES.get(generic, {}).get(host.family, generic)


def install_hint(host: HostInfo, generic: str) -> str:
    """Comando per installare un pacchetto sul target ("" se il gestore non è noto)."""
    template = _INSTALL.get(host.package_manager or "")
    return template.format(pkg=package_name(host, generic)) if template else ""


def upgrade_hint(host: HostInfo) -> str:
    return _UPGRADE.get(host.package_manager or "", "")


def enable_hint(host: HostInfo, service: str) -> str:
    """Comando per attivare un servizio subito e all'avvio, con l'init del target."""
    if host.init == "systemd":
        return f"sudo systemctl enable --now {service}"
    if host.init == "openrc":
        return f"sudo rc-update add {service} default && sudo rc-service {service} start"
    return ""


def join_hints(*parts: str) -> str:
    return " && ".join(p for p in parts if p)


def service_active(executor: BaseExecutor, *names: str) -> bool | None:
    """True se almeno uno dei servizi è attivo, False se nessuno, None se non verificabile.

    Accetta più nomi perché cambiano tra distribuzioni (ssh/sshd, rsyslog/syslog...).
    """
    host = host_info(executor)
    init = host.init
    if init == "unknown" and host.commands is None:
        init = "systemd"      # rilevamento fallito: si prova comunque con systemctl
    if init == "systemd":
        for name in names:
            out, _, _ = executor.execute_command(["systemctl", "is-active", name])
            if out.strip() == "active":
                return True
        return False
    if init == "openrc":
        for name in names:
            out, _, rc = executor.execute_command(["rc-service", name, "status"])
            if rc == 0 and "started" in out.lower():
                return True
        return False
    if init == "runit":
        for name in names:
            out, _, rc = executor.execute_command(["sv", "status", name])
            if rc == 0 and out.lstrip().startswith("run:"):
                return True
        return False
    return None


def listening_sockets(executor: BaseExecutor) -> tuple[list[tuple[str, str, str]], str] | None:
    """Socket in ascolto: [(protocollo, indirizzo locale, porta)] e comando usato.

    None se né `ss` né `netstat` sono disponibili (non verificabile).
    """
    for name, args in (("ss", ["-H", "-tuln"]), ("ss", ["-tuln"]), ("netstat", ["-tuln"])):
        path = find_tool(executor, name)
        if not path:
            continue
        out, _, rc = executor.execute_command([path, *args])
        if rc != 0:
            continue
        sockets = parse_sockets(out, name)
        return sockets, f"{name} {' '.join(args)}"
    return None


def parse_sockets(text: str, tool: str) -> list[tuple[str, str, str]]:
    """Righe di `ss -tuln` o `netstat -tuln` -> [(tcp|udp, indirizzo, porta)] (solo LISTEN per TCP)."""
    result: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if tool == "ss":
            if proto not in ("tcp", "udp"):
                continue
            state, local = parts[1].upper(), parts[4] if len(parts) > 4 else ""
            if proto == "tcp" and state != "LISTEN":
                continue
        else:   # netstat: Proto Recv-Q Send-Q Local Foreign [State]
            if not proto.startswith(("tcp", "udp")):
                continue
            local = parts[3]
            if proto.startswith("tcp") and (len(parts) < 6 or parts[5].upper() != "LISTEN"):
                continue
            proto = "tcp" if proto.startswith("tcp") else "udp"
        addr, sep, port = local.rpartition(":")
        if not sep or not port.isdigit():
            continue
        result.append((proto, addr, port))
    return result


def unverifiable(title: str, description: str, evidence: str, source: str, category: str) -> Finding:
    """Finding INFO per un controllo che su questo sistema non si è potuto fare."""
    return Finding(
        title=title, category=category, severity=Severity.INFO, description=description,
        evidence=evidence[:500],
        recommendation="Verificare a mano su questo sistema: l'assenza di segnalazioni qui non "
                       "significa che vada tutto bene.",
        source=source, confidence=Confidence.LOW,
    )

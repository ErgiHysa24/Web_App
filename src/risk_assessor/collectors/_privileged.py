"""Lettura di informazioni che a volte richiedono root (ufw, nft, iptables, /etc/shadow).

Regole (pensate per non cambiare nulla sul target):
- si prova SEMPRE prima il comando normale, senza sudo;
- solo se fallisce per mancanza di permessi si riprova con `sudo -n`
  (non interattivo: non chiede mai password e non usa la password di --ask-sudo-password);
- i comandi passati qui sono solo di LETTURA e sono scritti nel codice, mai derivati
  da input del target;
- l'esito è esplicito: ok / absent / denied / failed. Chi chiama NON deve trattare
  "denied" come "la risorsa non esiste": significa che il controllo non è stato possibile.
"""
from __future__ import annotations

from dataclasses import dataclass

from risk_assessor.executor import BaseExecutor

_DENIED_MARKERS = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "root privileges",
    "are you root",
    "superuser",
    "insufficient privileges",
    "no hostkeys available",      # sshd -T senza root
)
_ABSENT_MARKERS = ("command not found", "not found", "no such file")


@dataclass(frozen=True)
class PrivResult:
    status: str          # "ok" | "absent" | "denied" | "failed"
    out: str = ""
    err: str = ""
    rc: int = 0
    used_sudo: bool = False

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def inconclusive(self) -> bool:
        """True se non sappiamo com'è la situazione (permessi o errore inatteso)."""
        return self.status in ("denied", "failed")


# sudo stesso ha rifiutato (password richiesta, utente non autorizzato, sudo assente).
_SUDO_REFUSED = ("password is required", "a terminal is required", "not in the sudoers",
                 "not allowed to execute", "may not run sudo", "sudo: not found",
                 "sudo: command not found", "pam account", "unable to initialize")


def _sudo_refused(err: str) -> bool:
    low = (err or "").lower()
    return any(m in low for m in _SUDO_REFUSED)


def _looks_denied(out: str, err: str) -> bool:
    text = f"{out}\n{err}".lower()
    return any(m in text for m in _DENIED_MARKERS)


def run_privileged(executor: BaseExecutor, cmd: list[str]) -> PrivResult:
    """Esegue un comando di sola lettura, con retry `sudo -n` solo se serve.

    Se il comando sembra non esistere, lo si cerca anche fuori dal PATH: via SSH un utente
    normale spesso non ha /usr/sbin nel PATH, dove stanno ufw, nft e iptables. Senza questo
    passaggio un firewall attivo risulterebbe "assente".
    """
    result = _run(executor, cmd)
    if result.status == "absent" and not cmd[0].startswith("/"):
        from risk_assessor.tools.base import find_tool
        path = find_tool(executor, cmd[0])
        if path and path != cmd[0]:
            return _run(executor, [path, *cmd[1:]])
    return result


def _run(executor: BaseExecutor, cmd: list[str]) -> PrivResult:
    out, err, rc = executor.execute_command(cmd)
    if rc == 0:
        return PrivResult("ok", out, err, rc)

    if _looks_denied(out, err):
        s_out, s_err, s_rc = executor.execute_command(["sudo", "-n"] + cmd)
        if s_rc == 0:
            return PrivResult("ok", s_out, s_err, s_rc, used_sudo=True)
        if _sudo_refused(s_err) or _looks_denied(s_out, s_err):
            return PrivResult("denied", s_out or out, s_err or err, s_rc, used_sudo=True)
        # Con sudo il comando è partito: il suo esito è la risposta vera (per esempio il
        # file non esiste: senza root si vedeva solo "permesso negato" sulla cartella).
        if any(m in s_err.lower() for m in _ABSENT_MARKERS):
            return PrivResult("absent", s_out, s_err, s_rc, used_sudo=True)
        return PrivResult("failed", s_out, s_err, s_rc, used_sudo=True)

    low = err.lower()
    if rc == 127 or any(m in low for m in _ABSENT_MARKERS) or (rc == -1 and not err):
        return PrivResult("absent", out, err, rc)

    return PrivResult("failed", out, err, rc)

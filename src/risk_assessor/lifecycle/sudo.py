"""Sudo privilege management.

Regole:
- Prova prima `sudo -n` (non-interactive). Se funziona, nessun prompt.
- Se fallisce e c'è una password in memoria, usa `sudo -S` (legge da stdin).
- La password NON viene mai loggata, mai serializzata, mai passata come argv.
- Viene azzerata con `clear()` dopo l'ultimo uso.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from risk_assessor.executor import BaseExecutor


@dataclass
class SudoContext:
    """Gestisce l'escalation sudo per un singolo assessment."""

    password: str | None = None
    available: bool = False
    checked: bool = False
    _password_used: bool = field(default=False, init=False)

    def probe(self, executor: BaseExecutor) -> bool:
        """Verifica se sudo è disponibile senza password (NOPASSWD)."""
        if self.checked:
            return self.available
        _, _, rc = executor.execute_command(["sudo", "-n", "true"])
        self.available = (rc == 0)
        self.checked = True
        return self.available

    def run(
        self,
        executor: BaseExecutor,
        command: list[str],
    ) -> tuple[str, str, int]:
        """Esegue un comando con sudo.

        - Se NOPASSWD: usa `sudo -n cmd args`
        - Se password disponibile: usa `sudo -S cmd args` con password su stdin
        - Altrimenti: ritorna errore pulito
        """
        self.probe(executor)

        if self.available:
            return executor.execute_command(["sudo", "-n"] + command)

        if self.password:
            self._password_used = True
            return executor.execute_command(
                ["sudo", "-S", "-p", ""] + command,
                stdin=self.password + "\n",
            )

        return ("", "sudo richiede una password: configurare sudo senza password (NOPASSWD) "
                    "o usare --ask-sudo-password", 1)

    def clear(self) -> None:
        """Azzera la password dalla memoria."""
        self.password = None
        self._password_used = False


def _needs_sudo(executor: BaseExecutor) -> bool:
    """Ritorna True se l'utente corrente NON è root (UID != 0)."""
    out, _, rc = executor.execute_command(["id", "-u"])
    if rc != 0:
        return False
    return out.strip() != "0"


def run_with_sudo(
    executor: BaseExecutor,
    command: list[str],
    sudo_ctx: SudoContext | None = None,
) -> tuple[str, str, int]:
    """Esegue un comando con sudo se necessario.

    Se `sudo_ctx` è fornito, usa SudoContext (NOPASSWD o password).
    Altrimenti usa `sudo -n` (solo NOPASSWD).
    """
    if not _needs_sudo(executor):
        return executor.execute_command(command)

    if sudo_ctx is not None:
        return sudo_ctx.run(executor, command)

    return executor.execute_command(["sudo", "-n"] + command)


def prompt_sudo_password() -> str | None:
    """Chiede la password sudo in modo nascosto. Ritorna None se annullato."""
    import getpass
    try:
        pw = getpass.getpass("Sudo password (target): ")
        return pw or None
    except (KeyboardInterrupt, EOFError):
        return None

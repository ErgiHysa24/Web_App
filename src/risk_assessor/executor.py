"""Executors for running assessment commands."""
from __future__ import annotations
import logging
import shlex
import socket
import subprocess
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# Tempo massimo (secondi) di un singolo comando se il chiamante non ne indica uno.
# Evita che un tool bloccato congeli l'assessment per sempre.
DEFAULT_COMMAND_TIMEOUT = 900
# Codice di uscita convenzionale per "interrotto per timeout" (come `timeout(1)`).
TIMEOUT_RC = 124


class BaseExecutor(ABC):
    """Abstract base class for command execution."""

    @abstractmethod
    def execute_command(
        self,
        command: list[str],
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> tuple[str, str, int]:
        """Execute command. Returns (stdout, stderr, returncode).

        Args:
            command: Lista di argomenti [exe, arg1, ...]
            stdin: testo opzionale da inviare allo stdin del comando
            timeout: secondi massimi (default DEFAULT_COMMAND_TIMEOUT). Allo
                scadere ritorna rc TIMEOUT_RC (124) e un messaggio in stderr.
        """
        ...

    @abstractmethod
    def get_remote_hostname(self) -> str | None:
        """Get the hostname of the target."""
        ...

    def close(self) -> None:
        """Release resources. Default: no-op."""
        return None


class LocalExecutor(BaseExecutor):
    """Executes commands locally via subprocess."""

    def __init__(self, command_list: list[str] | None = None) -> None:
        self.command_list = command_list or []

    def execute_command(
        self,
        command: list[str],
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> tuple[str, str, int]:
        logger.debug(f"Local command: {command}")
        limit = timeout or DEFAULT_COMMAND_TIMEOUT
        try:
            result = subprocess.run(  # nosec B603 - argv list, niente shell
                args=command,
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Nomi di file e output del sistema possono non essere UTF-8 validi: un solo
                # byte sbagliato non deve far perdere tutto l'output (un malware con un nome
                # in Latin-1 sparirebbe dal report di ClamAV).
                encoding="utf-8",
                errors="replace",
                timeout=limit,
            )
            return (result.stdout or "", result.stderr or "", result.returncode)
        except subprocess.TimeoutExpired as e:
            # subprocess.run ha già terminato il processo figlio
            logger.warning("Comando interrotto dopo %ss: %s", limit, command[0])
            partial = e.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            return (partial, f"timeout: comando interrotto dopo {limit}s", TIMEOUT_RC)
        except FileNotFoundError:
            return ("", f"Command '{command[0]}' not found", 127)
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return ("", str(e), -1)

    def get_remote_hostname(self) -> str | None:
        out, _, rc = self.execute_command(["hostname"])
        if rc == 0:
            return out.strip()
        return "local"

    def close(self) -> None:
        return None


class SSHConnectionError(RuntimeError):
    """La connessione SSH al target non è riuscita (host, credenziali, chiave host)."""


class SSHExecutor(BaseExecutor):
    """Executes commands remotely via SSH using Paramiko.

    Sicurezza delle chiavi host: di default la chiave del server DEVE essere già
    nota (known_hosts di sistema/utente), altrimenti la connessione è rifiutata.
    Con ``accept_new_host_key=True`` le chiavi sconosciute vengono accettate
    (trust-on-first-use); una chiave diversa da quella già registrata resta
    comunque un errore.
    """

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        key_file: str | None = None,
        password: str | None = None,
        timeout: int = 15,
        accept_new_host_key: bool = False,
        known_host_key: str | None = None,
    ) -> None:
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.password = password
        self.timeout = timeout
        self.accept_new_host_key = accept_new_host_key
        # Chiave attesa del server ("ssh-ed25519 AAAA..."): se indicata, è l'unica accettata
        # (chi usa l'executor da un'applicazione la ricorda dalla prima connessione).
        self.known_host_key = (known_host_key or "").strip() or None
        # Chiave presentata dal server, disponibile dopo connect().
        self.server_host_key: str | None = None
        self._client = None

    def connect(self) -> None:
        """Apre subito la connessione. Solleva SSHConnectionError se fallisce.

        Da chiamare prima di lanciare l'assessment: senza questo passaggio un
        errore di connessione emergerebbe solo come codice -1 su ogni comando e
        produrrebbe un report apparentemente valido ma privo di significato.
        """
        try:
            self._connect()
        except Exception as e:
            raise SSHConnectionError(f"{type(e).__name__}: {e}") from e

    def _connect(self):
        import paramiko
        if self._client is not None:
            return self._client
        client = paramiko.SSHClient()
        if self.known_host_key:
            entry_host = self.host if self.port == 22 else f"[{self.host}]:{self.port}"
            entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{entry_host} {self.known_host_key}")
            if entry is None or entry.key is None:
                raise ValueError("chiave host attesa non valida")
            client.get_host_keys().add(entry_host, entry.key.get_name(), entry.key)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif self.accept_new_host_key:
            try:
                client.load_system_host_keys()  # include ~/.ssh/known_hosts
            except Exception:
                pass
            logger.warning("Accettazione automatica delle nuove chiavi host SSH attiva")
            # Opt-in esplicito dell'utente (--accept-new-host-key); il default è RejectPolicy.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507
        else:
            try:
                client.load_system_host_keys()  # include ~/.ssh/known_hosts
            except Exception:
                pass
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.user,
            "timeout": self.timeout,
        }
        if self.key_file:
            # Espandi ~ se presente (Paramiko non lo fa)
            import os as _os
            kwargs["key_filename"] = _os.path.expanduser(self.key_file)
        if self.password:
            kwargs["password"] = self.password
        try:
            client.connect(**kwargs)
        except Exception:
            try:
                client.close()
            except Exception:
                pass
            raise
        # Keepalive ogni 30s: evita che sshd chiuda la connessione per inattività
        # durante comandi lunghi (es. Lynis che ci mette 2+ minuti)
        try:
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(30)
                key = transport.get_remote_server_key()
                self.server_host_key = f"{key.get_name()} {key.get_base64()}"
        except Exception:
            pass
        self._client = client
        return client

    def execute_command(
        self,
        command: list[str],
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> tuple[str, str, int]:
        cmd_str = " ".join(shlex.quote(c) for c in command)
        limit = timeout or DEFAULT_COMMAND_TIMEOUT
        logger.debug(f"SSH command: {cmd_str}")
        try:
            client = self._connect()
            # cmd_str: ogni argomento è già quotato con shlex.quote
            chan_in, stdout, stderr = client.exec_command(cmd_str, timeout=limit)  # nosec B601
            if stdin is not None:
                chan_in.write(stdin)
                if not stdin.endswith("\n"):
                    chan_in.write("\n")
                chan_in.flush()
                try:
                    chan_in.channel.shutdown_write()
                except Exception:
                    pass
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return (out, err, rc)
        except socket.timeout:
            # nessun output per `limit` secondi: chiudo il canale (la sessione resta valida)
            logger.warning("Comando SSH interrotto dopo %ss: %s", limit, command[0])
            try:
                stdout.channel.close()
            except Exception:
                pass
            return ("", f"timeout: comando interrotto dopo {limit}s", TIMEOUT_RC)
        except Exception as e:
            last_error = f"{type(e).__name__}: {str(e) or 'no message'}"
            logger.error(f"SSH execution error: {last_error}")
            return ("", last_error, -1)

    def get_remote_hostname(self) -> str | None:
        out, _, rc = self.execute_command(["hostname"])
        if rc == 0:
            return out.strip()
        return None

    def reconnect(self) -> None:
        """Chiude e riapre la connessione SSH."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
        try:
            self._connect()
        except Exception:
            pass

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        # La password serve solo per (ri)connettersi: a sessione chiusa la scarto.
        self.password = None

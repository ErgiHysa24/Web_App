"""AIDE integration.

AIDE richiede privilegi root per accedere a /var/lib/aide/ e /etc/aide/aide.conf.
Come root i comandi girano direttamente, altrimenti con `sudo -n` (NOPASSWD). Senza
privilegi il tool ritorna un marker che il parser trasforma in finding INFO esplicito.
"""
from __future__ import annotations

from risk_assessor.executor import BaseExecutor
from risk_assessor.models import Finding
from risk_assessor.parsers.aide import parse_aide, BASELINE_CREATED_MARKER, NO_DATABASE_MARKER
from risk_assessor.host import privileges
from risk_assessor.tools.base import EXISTING_FILES_SCRIPT, SecurityTool, ToolState, track_new_files


# init/check leggono tutto il filesystem monitorato: su server grandi servono minuti.
AIDE_TIMEOUT = 3600

# File di configurazione: Debian/Ubuntu, poi RHEL e derivate.
_CONFIG_CANDIDATES = ("/etc/aide/aide.conf", "/etc/aide.conf")


# Cartella del database: uguale ovunque; il nome cambia (aide.db su Debian e SUSE,
# aide.db.gz su RHEL e Fedora).
DB_DIR = "/var/lib/aide"
_DB_SUFFIXES = ("", ".gz")


_EXISTING_SCRIPT = EXISTING_FILES_SCRIPT


class AideTool(SecurityTool):
    name = "aide"
    package = "aide"
    packages = {"debian": ["aide"], "fedora": ["aide"], "rhel": ["aide"], "suse": ["aide"],
                "arch": None, "alpine": None}

    def run(self, executor: BaseExecutor, target: str | None = None) -> str:
        # AIDE richiede root per /var/lib/aide/ e /etc/aide/
        priv = privileges(executor)
        if priv is None:
            return "__SUDO_REQUIRED__"

        # Le versioni recenti di AIDE (>= 0.18) vogliono --config: senza, falliscono con
        # "missing configuration". Se non troviamo un file noto, si prova senza (versioni vecchie).
        conf = self._config_args(executor, priv)

        # 1. Inizializza il database se non esiste o è vuoto (un database vuoto, per
        #    esempio da un'inizializzazione interrotta, non serve a confrontare nulla).
        #    In questo caso NON eseguiamo il check: confronterebbe il filesystem con una
        #    fotografia scattata un istante prima e darebbe sempre "nessuna modifica".
        if self._existing(executor, priv, "aide.db") is None:
            if self.state == ToolState.PRE_EXISTING:
                # AIDE dell'amministratore senza database: crearlo noi vorrebbe dire lasciare sul
                # sistema una baseline scattata dall'assessment, di cui poi ci si fiderebbe.
                return NO_DATABASE_MARKER
            _, err_init, rc_init = executor.execute_command(
                priv + [self._path, *conf, "--init"], timeout=AIDE_TIMEOUT,
            )
            if rc_init != 0:
                return err_init or f"aide --init non riuscito (codice {rc_init})"
            new = self._existing(executor, priv, "aide.db.new")
            if new is None:
                return "aide --init non ha creato il database (file assente o vuoto)"
            suffix = new[len(f"{DB_DIR}/aide.db.new"):]
            executor.execute_command(priv + ["cp", new, f"{DB_DIR}/aide.db{suffix}"])
            return BASELINE_CREATED_MARKER

        # 2. Esegui il check
        out, err, rc = executor.execute_command(
            priv + [self._path, *conf, "--check"], timeout=AIDE_TIMEOUT,
        )
        # AIDE ritorna 0-7 (differenze trovate), altri = errore
        if rc not in (0, 1, 2, 3, 4, 5, 6, 7) and not out:
            return err or ""
        return (out or "") + "\n" + (err or "")

    @staticmethod
    def _existing(executor: BaseExecutor, priv: list[str], base: str) -> str | None:
        """Percorso del file di database `base` (con o senza .gz) se esiste e non è vuoto."""
        for suffix in _DB_SUFFIXES:
            path = f"{DB_DIR}/{base}{suffix}"
            if executor.execute_command(priv + ["test", "-s", path])[2] == 0:
                return path
        return None

    @staticmethod
    def _config_args(executor: BaseExecutor, priv: list[str]) -> list[str]:
        """["--config", <file>] se esiste un file di configurazione noto, altrimenti []."""
        for path in _CONFIG_CANDIDATES:
            _, _, rc = executor.execute_command(priv + ["test", "-f", path])
            if rc == 0:
                return ["--config", path]
        return []

    def post_install(self, executor: BaseExecutor, tracker, sudo_ctx=None) -> None:
        """AIDE installato dall'assessment: anche il database che creerà va tolto alla fine.

        Un database di un AIDE già presente invece appartiene all'amministratore e non
        si tocca (questo hook gira solo dopo un'installazione fatta da noi).
        """
        candidates = [f"{DB_DIR}/{name}{suffix}" for name in ("aide.db", "aide.db.new")
                      for suffix in _DB_SUFFIXES]
        # Si rimuovono solo i file che non esistevano prima (vedi track_new_files).
        track_new_files(executor, tracker, "aide-db", candidates)

    def parse(self, raw_output: str) -> list[Finding]:
        return parse_aide(raw_output)

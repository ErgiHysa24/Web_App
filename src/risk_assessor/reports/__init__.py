"""Report generators e utilità condivise."""
from __future__ import annotations
import os
from pathlib import Path


def private_dir(path: Path | str) -> Path:
    """Crea la cartella (se serve) accessibile solo al proprietario (0700).

    I report contengono dettagli sensibili (porte aperte, file SUID, pacchetti
    vulnerabili, utenti): non devono essere leggibili dagli altri utenti.
    Su filesystem che non supportano i permessi POSIX (es. Windows) è un no-op.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def private_file(path: Path | str) -> Path:
    """Rende il file leggibile/scrivibile solo dal proprietario (0600)."""
    path = Path(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path

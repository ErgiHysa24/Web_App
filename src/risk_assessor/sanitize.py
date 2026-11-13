"""Pulizia del testo che proviene dal target analizzato.

Titoli ed evidenze dei finding contengono stringhe scritte dal sistema sotto
analisi (nomi di file, banner di servizi, righe di config, output dei tool). Un
target ostile può inserirci sequenze di escape del terminale: quando l'operatore
legge il riepilogo in console o apre il report Markdown con `cat`, queste possono
cancellare righe, cambiare colori o il titolo della finestra, nascondere un
finding o falsificarne uno.

`clean_text` rimuove le sequenze di escape e sostituisce gli altri caratteri di
controllo con "?", lasciando intatti a capo e tabulazioni.
"""
from __future__ import annotations

import re

# ESC [ ... (CSI), ESC ] ... BEL/ST (OSC), ESC P/X/^/_ ... ST (DCS/SOS/PM/APC),
# altre sequenze ESC a due caratteri. Più gli equivalenti C1 a 8 bit (0x9b, 0x9d, ...).
_ESCAPE_SEQ = re.compile(
    r"""
    (?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]              # CSI
  | (?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)      # OSC (titolo finestra, link)
  | (?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c|$)  # DCS / SOS / PM / APC
  | \x1b[@-Z\\-_]                                 # altre sequenze Fe a 2 caratteri
  | \x1b[ -/]*[0-~]                               # sequenze nF / Fp / Fs
    """,
    re.VERBOSE | re.DOTALL,
)

# Controlli C0 (tranne \t e \n), DEL, C1 e caratteri di override bidirezionale
# (usati per far apparire il testo in un ordine diverso da quello reale).
_CONTROL = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]"
)


def clean_text(value: str) -> str:
    """Rende sicura per terminale/report una stringa proveniente dal target."""
    if not value:
        return value
    text = value.replace("\r\n", "\n")
    text = _ESCAPE_SEQ.sub("", text)
    return _CONTROL.sub("?", text)


_SAFE_ARG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+:@-]{0,63}")


def safe_shell_arg(value: str) -> str | None:
    """Restituisce `value` solo se è un nome semplice (utente, pacchetto), altrimenti None.

    Serve a costruire comandi di rimedio copiabili a partire da nomi provenienti dal
    target: se il nome contiene qualcosa di inusuale, il comando non viene proposto.
    """
    return value if isinstance(value, str) and _SAFE_ARG.fullmatch(value) else None

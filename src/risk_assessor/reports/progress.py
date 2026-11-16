"""Progress bar per l'intero assessment.

Formato:
    [████████░░░░░░░░░░░░]  40% | Connessione SSH.............
    [████████████░░░░░░░░]  50% | Collector: linux............ OK
    [██████████████░░░░░░]  60% | Tool: nmap.................. (in corso)
    [██████████████████░░]  85% | Tool: lynis................. OK
    [████████████████████] 100% | Analisi e report............ OK

Usa \r per aggiornare la stessa riga. Il `current` step viene aggiornato
quando chiami `ok()` o `fail()`. `start_step` mostra il nome del tool
in corso.
"""
from __future__ import annotations
import sys
import time


class ProgressReporter:
    """Barra di caricamento per l'intero assessment."""

    BAR_WIDTH = 20

    def __init__(self, total_steps: int = 0, enabled: bool = True, stream=None):
        self.total = max(1, total_steps)
        self.enabled = enabled
        self.stream = stream or sys.stdout
        self.current = 0
        self._step_start = time.monotonic()
        self._last_line_len = 0
        self._current_label = ""

    # ---- helpers di rendering ----

    def _bar(self, pct: int) -> str:
        filled = int(round(self.BAR_WIDTH * pct / 100))
        return "█" * filled + "░" * (self.BAR_WIDTH - filled)

    def _pct(self) -> int:
        return min(100, int(round(self.current * 100 / self.total)))

    def _write(self, text: str, newline: bool = False) -> None:
        """Scrive sulla stessa riga (carriage return)."""
        if not self.enabled:
            return
        # padding per cancellare residui della riga precedente
        pad = " " * max(0, self._last_line_len - len(text))
        end = "\n" if newline else ""
        print(f"\r{text}{pad}", end=end, file=self.stream, flush=True)
        self._last_line_len = len(text) if not newline else 0

    # ---- API pubblica ----

    def banner(self, text: str) -> None:
        if not self.enabled:
            return
        if self._last_line_len > 0:
            print(file=self.stream, flush=True)
            self._last_line_len = 0
        print(text, file=self.stream, flush=True)

    def blank(self) -> None:
        self.banner("")

    def start_step(self, label: str) -> None:
        """Mostra lo step corrente con la barra."""
        if not self.enabled:
            return
        self._current_label = label
        self._step_start = time.monotonic()
        pct = self._pct()
        bar = self._bar(pct)
        dots = "." * max(3, 40 - len(label))
        line = f"[{bar}] {pct:3d}% | {label}{dots}"
        self._write(line)

    def ok(self, extra: str = "") -> None:
        """Completa lo step. Aggiorna la percentuale."""
        if not self.enabled:
            return
        self.current += 1
        elapsed = time.monotonic() - self._step_start
        pct = self._pct()
        bar = self._bar(pct)
        suffix = " OK"
        if elapsed >= 1.0:
            suffix += f" ({elapsed:.0f}s)"
        if extra:
            suffix += f" {extra}"
        label = self._current_label
        dots = "." * max(3, 40 - len(label))
        line = f"[{bar}] {pct:3d}% | {label}{dots}{suffix}"
        self._write(line, newline=True)

    def fail(self, reason: str = "") -> None:
        if not self.enabled:
            return
        self.current += 1
        pct = self._pct()
        bar = self._bar(pct)
        line = f"[{bar}] {pct:3d}% | FAIL: {reason}"
        self._write(line, newline=True)

    def skip(self, reason: str = "") -> None:
        if not self.enabled:
            return
        self.current += 1
        pct = self._pct()
        bar = self._bar(pct)
        line = f"[{bar}] {pct:3d}% | SKIP: {reason}"
        self._write(line, newline=True)

    def info(self, text: str) -> None:
        self.banner(text)


class NullProgress:
    """No-op per test e contesti non interattivi."""
    enabled = False
    total = 0
    def banner(self, *a, **k): pass
    def blank(self, *a, **k): pass
    def start_step(self, *a, **k): pass
    def ok(self, *a, **k): pass
    def fail(self, *a, **k): pass
    def skip(self, *a, **k): pass
    def info(self, *a, **k): pass

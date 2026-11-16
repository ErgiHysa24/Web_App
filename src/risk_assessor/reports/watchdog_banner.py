"""WatchDog startup banner.

Legge i banner ASCII dai file .txt nella cartella banners/ e sceglie quello
adatto in base alla larghezza del terminale e al tema (dark/light).
"""
from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path

# Forza UTF-8 sullo stdout (Windows usa cp1252, che non ha i caratteri Braille)
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

_DIR = Path(__file__).resolve().parent / "banners"

_VARIANTS = [
    (140, "watchdog_banner_140.txt", "dark"),
    (100, "watchdog_banner_100.txt", "dark"),
]
_LIGHT = (100, "watchdog_banner_100_light.txt")

RESET = "\x1b[0m"
ART_COLOR = "\x1b[38;2;230;230;230m"
TITLE_COLOR = "\x1b[38;2;255;170;60m"


def _pick(theme: str, cols: int):
    if theme == "light":
        return _LIGHT[1] if cols >= _LIGHT[0] else None
    for min_cols, name, _ in _VARIANTS:
        if cols >= min_cols:
            return name
    return None


def get_banner(theme: str = "dark", color: bool | None = None) -> str:
    cols = shutil.get_terminal_size((100, 40)).columns
    name = _pick(theme, cols)
    if name is None:
        return "  🐕 WatchDog"

    path = _DIR / name
    if not path.exists():
        return "  🐕 WatchDog"

    text = path.read_text(encoding="utf-8").rstrip("\n")

    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    if not color:
        return text

    lines = text.split("\n")
    split = len(lines)
    for i, line in enumerate(lines):
        if "██╗" in line or "W A T C H" in line or "╔" in line:
            split = i
            break

    head = [ART_COLOR + l + RESET for l in lines[:split]]
    tail = [TITLE_COLOR + l + RESET for l in lines[split:]]
    return "\n".join(head + tail)


def print_banner(theme: str = "dark", color: bool | None = None) -> None:
    print(get_banner(theme, color))


if __name__ == "__main__":
    print_banner(theme="light" if "--light" in sys.argv else "dark")

"""Animated ASCII banner for OSAID PT."""
from __future__ import annotations
import sys
import time


BANNER = r"""
   ____  _____    _    ___ ____    ____  _____
  / __ \/ ___/   / \  |_ _|  _ \  |  _ \_   _|
 | |  | \___ \  / _ \  | || | | | | |_) || |
 | |__| |___) |/ ___ \ | || |_| | |  __/ | |
  \____/|____//_/   \_\___|____/  |_|    |_|
"""

SUBTITLE = "Assumption Engine + Boundary Violation Mapper"
VERSION = "v4.0"


def _supports_color() -> bool:
    return sys.stdout.isatty() and sys.platform != "win32"


def _color(code: str, text: str) -> str:
    if not _supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def banner_static() -> str:
    """Banner as a plain string for embedding in reports."""
    return (BANNER.strip("\n") + "\n"
            + f"  OSAID PT  |  {SUBTITLE}  |  {VERSION}\n")


def animate_banner(enable: bool = True, delay: float = 0.04) -> None:
    """Print the OSAID PT banner with a reveal animation."""
    if not enable or not sys.stdout.isatty():
        print(_color("36", BANNER.strip("\n")))
        print(_color("90", f"  OSAID PT  |  {SUBTITLE}  |  {VERSION}"))
        print()
        return

    lines = BANNER.strip("\n").split("\n")

    # Phase 1: reveal each banner line
    for line in lines:
        print(_color("36", line))
        sys.stdout.flush()
        time.sleep(delay)

    # Phase 2: subtitle typed character by character on the current line
    sub = f"  OSAID PT  |  {SUBTITLE}  |  {VERSION}"
    for i in range(1, len(sub) + 1):
        sys.stdout.write("\033[2K\r" + _color("90", sub[:i]))
        sys.stdout.flush()
        time.sleep(delay / 10)
    print()
    print()


if __name__ == "__main__":
    animate_banner()

"""Startup banner — BEACHHEAD in the Bloody FIGlet font."""

from __future__ import annotations

from beachhead import __version__

_BLOODY = r"""
 ▄▄▄▄   ▓█████ ▄▄▄       ▄████▄   ██░ ██  ██░ ██ ▓█████ ▄▄▄      ▓█████▄
▓█████▄ ▓█   ▀▒████▄    ▒██▀ ▀█  ▓██░ ██▒▓██░ ██▒▓█   ▀▒████▄    ▒██▀ ██▌
▒██▒ ▄██▒███  ▒██  ▀█▄  ▒▓█    ▄ ▒██▀▀██░▒██▀▀██░▒███  ▒██  ▀█▄  ░██   █▌
▒██░█▀  ▒▓█  ▄░██▄▄▄▄██ ▒▓▓▄ ▄██▒░▓█ ░██ ░▓█ ░██ ▒▓█  ▄░██▄▄▄▄██ ░▓█▄   ▌
░▓█  ▀█▓░▒████▒▓█   ▓██▒▒ ▓███▀ ░░▓█▒░██▓░▓█▒░██▓░▒████▒▓█   ▓██▒░▒████▓
░▒▓███▀▒░░ ▒░ ░▒▒   ▓▒█░░ ░▒ ▒  ░ ▒ ░░▒░▒ ▒ ░░▒░▒░░ ▒░ ░▒▒   ▓▒█░ ▒▒▓  ▒
▒░▒   ░  ░ ░  ░ ▒   ▒▒ ░  ░  ▒    ▒ ░▒░ ░ ▒ ░▒░ ░ ░ ░  ░ ▒   ▒▒ ░ ░ ▒  ▒
 ░    ░    ░    ░   ▒   ░         ░  ░░ ░ ░  ░░ ░   ░    ░   ▒    ░ ░  ░
 ░         ░  ░     ░  ░░ ░       ░  ░  ░ ░  ░  ░   ░  ░     ░  ░   ░
      ░                 ░                                         ░
"""

_TAGLINE = "Azure DevOps post-exploitation framework"

_GRADIENT = [
    "bold #ff0000",
    "bold #ee1111",
    "bold #dd2222",
    "bold #cc3333",
    "#bb3333",
    "#aa4444",
    "#994444",
    "#884444",
    "#774444",
    "#664444",
]


def print_banner(console: object) -> None:
    """Print the Bloody-font banner with a red gradient to a Rich console.

    Suppressed when stdout is not a terminal (piped output, test runners, --json).
    """
    import sys

    from rich.console import Console

    if not isinstance(console, Console):
        return
    if not sys.stdout.isatty():
        return
    lines = _BLOODY.strip("\n").splitlines()
    for i, line in enumerate(lines):
        style = _GRADIENT[i] if i < len(_GRADIENT) else _GRADIENT[-1]
        console.print(line, style=style, highlight=False)
    console.print(
        f"  v{__version__}  —  {_TAGLINE}",
        style="dim",
        highlight=False,
    )
    console.print()

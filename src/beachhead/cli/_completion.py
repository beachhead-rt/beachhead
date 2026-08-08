"""Auto-install shell tab completion on first CLI run."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_PROG = "bh"
_COMPLETE_VAR = "_BH_COMPLETE"
_MARKER_NAME = ".completion_installed"
_MARKER_DIR = Path.home() / ".beachhead"

_PS_SCRIPT = """\
Import-Module PSReadLine
Set-PSReadLineKeyHandler -Chord Tab -Function MenuComplete
$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $Env:%(complete_var)s = "complete_powershell"
    $Env:_TYPER_COMPLETE_ARGS = $commandAst.ToString()
    $Env:_TYPER_COMPLETE_WORD_TO_COMPLETE = $wordToComplete
    %(prog)s | ForEach-Object {
        $commandArray = $_ -Split ":::"
        $command = $commandArray[0]
        $helpString = $commandArray[1]
        [System.Management.Automation.CompletionResult]::new(
            $command, $command, 'ParameterValue', $helpString)
    }
    $Env:%(complete_var)s = ""
    $Env:_TYPER_COMPLETE_ARGS = ""
    $Env:_TYPER_COMPLETE_WORD_TO_COMPLETE = ""
}
Register-ArgumentCompleter -Native -CommandName %(prog)s -ScriptBlock $scriptblock
"""

_BASH_SCRIPT = """\
_%(func)s() {
    local IFS=$'\\n'
    COMPREPLY=( $( env COMP_WORDS="${COMP_WORDS[*]}" \\
                   COMP_CWORD=$COMP_CWORD \\
                   %(complete_var)s=complete_bash %(prog)s ) )
    return 0
}
complete -o default -F _%(func)s %(prog)s
"""

_ZSH_SCRIPT = """\
#compdef %(prog)s
_%(func)s() {
  eval $(env _TYPER_COMPLETE_ARGS="${words[1,$CURRENT]}" %(complete_var)s=complete_zsh %(prog)s)
}
compdef _%(func)s %(prog)s
"""


def _script_for_shell(shell: str) -> str:
    ctx = {"prog": _PROG, "complete_var": _COMPLETE_VAR, "func": _PROG + "_completion"}
    if shell in ("powershell", "pwsh"):
        return _PS_SCRIPT % ctx
    if shell == "bash":
        return _BASH_SCRIPT % ctx
    if shell == "zsh":
        return _ZSH_SCRIPT % ctx
    return ""


def _detect_shell() -> str | None:
    try:
        import shellingham

        name, _ = shellingham.detect_shell()
        return name.lower() if name else None
    except Exception:  # noqa: BLE001
        return None


def _get_profile_path(shell: str) -> Path | None:
    if shell in ("powershell", "pwsh"):
        try:
            r = subprocess.run(  # noqa: S603
                [shell, "-NoProfile", "-Command", "echo", "$profile"],
                capture_output=True,
                timeout=5,
            )
            if r.returncode == 0 and r.stdout:
                raw = r.stdout.decode("utf-8", errors="replace").strip()
                if raw:
                    return Path(raw)
        except Exception:  # noqa: BLE001, S110
            pass
        return None
    if shell == "bash":
        return Path.home() / ".bashrc"
    if shell == "zsh":
        return Path.home() / ".zshrc"
    return None


def _already_installed(profile: Path) -> bool:
    if not profile.is_file():
        return False
    try:
        content = profile.read_text(encoding="utf-8", errors="replace")
        return f"Register-ArgumentCompleter -Native -CommandName {_PROG}" in content or \
               f"complete -o default -F _{_PROG}_completion {_PROG}" in content or \
               f"compdef _{_PROG}_completion {_PROG}" in content
    except Exception:  # noqa: BLE001
        return False


def ensure_completion() -> None:
    """Install shell completion for ``bh`` if not already present.

    Called once per CLI invocation; fast-exits on the marker file so the
    typical case costs a single Path.exists() check (~0.1 ms).
    """
    if (_MARKER_DIR / _MARKER_NAME).exists():
        return

    # Don't run during completion resolution itself
    import os

    if os.environ.get(_COMPLETE_VAR):
        return

    try:
        _do_install()
    except Exception:  # noqa: BLE001, S110
        pass


def _do_install() -> None:
    shell = _detect_shell()
    if not shell:
        return

    script = _script_for_shell(shell)
    if not script:
        return

    profile = _get_profile_path(shell)
    if not profile:
        return

    if _already_installed(profile):
        _write_marker()
        return

    if not sys.stderr.isatty():
        return

    profile.parent.mkdir(parents=True, exist_ok=True)
    with profile.open("a", encoding="utf-8") as f:
        f.write(f"\n{script}\n")

    _write_marker()

    if sys.stderr.isatty():
        sys.stderr.write(
            f"\x1b[2m[bh] Tab completion installed in {profile}. "
            "Restart your shell to activate.\x1b[0m\n"
        )


def _write_marker() -> None:
    _MARKER_DIR.mkdir(parents=True, exist_ok=True)
    (_MARKER_DIR / _MARKER_NAME).write_text("1")

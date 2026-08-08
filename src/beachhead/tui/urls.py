"""Map ado:// resource IDs to ADO web URLs and SpyGlass deep links, and open them."""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path
from urllib.parse import quote as _quote
from urllib.parse import urlparse

from beachhead.core.urls import (
    resolve_finding_url,
    resource_id_to_url,
)

__all__ = [
    "resolve_finding_url",
    "resource_id_to_url",
    "open_url",
    "ensure_spyglass",
    "stop_spyglass",
    "open_in_spyglass",
    "extract_project",
    "spyglass_resource_url",
    "spyglass_finding_url",
    "spyglass_credential_url",
]


def open_url(url: str) -> bool:
    """Open a URL in the default browser. Returns True on success."""
    if not url:
        return False
    if _is_wsl():
        return _open_wsl(url)
    try:
        webbrowser.open(url)
        return True
    except Exception:  # noqa: BLE001
        return False


def _is_wsl() -> bool:
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _open_wsl(url: str) -> bool:
    for cmd in ("wslview", "xdg-open"):
        if shutil.which(cmd):
            try:
                subprocess.Popen(  # noqa: S603
                    [cmd, url],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
            except OSError:
                continue
    try:
        webbrowser.open(url)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# SpyGlass server management + deep-link URL builders
# ---------------------------------------------------------------------------

_SPYGLASS_BASE = os.environ.get("BH_SPYGLASS_URL", "http://127.0.0.1:5057")
_SPYGLASS_PROC: subprocess.Popen[bytes] | None = None


def stop_spyglass() -> None:
    """Terminate the SpyGlass subprocess if we started it."""
    global _SPYGLASS_PROC  # noqa: PLW0603
    proc = _SPYGLASS_PROC
    if proc is None:
        return
    _SPYGLASS_PROC = None
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:  # noqa: BLE001, S110
        try:
            proc.kill()
        except Exception:  # noqa: BLE001, S110
            pass

_PROJECT_RESOURCE_TYPES = frozenset({
    "repo", "pipeline", "build", "release", "vargroup",
    "endpoint", "wi", "feed", "wiki", "policy",
})


def extract_project(resource_id: str) -> str:
    """Extract the project name from an ``ado://org/project/type/...`` resource ID."""
    if not resource_id or not resource_id.startswith("ado://"):
        return ""
    parts = resource_id[6:].split("/")
    if len(parts) >= 4 and parts[2] in _PROJECT_RESOURCE_TYPES:
        return parts[1]
    return ""


def _spyglass_port() -> tuple[str, int]:
    parsed = urlparse(_SPYGLASS_BASE)
    return (parsed.hostname or "127.0.0.1", parsed.port or 5057)


def _spyglass_reachable() -> bool:
    host, port = _spyglass_port()
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _spyglass_url(fragment: str, project: str = "") -> str:
    """Build a SpyGlass deep-link URL, prefixing the project when available."""
    if project:
        return f"{_SPYGLASS_BASE}#/p/{_quote(project, safe='')}/{fragment}"
    return f"{_SPYGLASS_BASE}#/{fragment}"


def _find_spyglass_script() -> str:
    explicit = os.environ.get("BH_SPYGLASS_PATH", "")
    if explicit and Path(explicit).is_file():
        return explicit
    bundled = Path(__file__).resolve().parent.parent / "contrib" / "spyglass.py"
    if bundled.is_file():
        return str(bundled)
    return ""


def _get_ado_pat() -> str:
    """Retrieve the ADO PAT from env or token cache."""
    pat = os.environ.get("BEACHHEAD_ADO_PAT", "")
    if pat:
        return pat
    try:
        from beachhead.core.auth.token_cache import load_tokens
        entry = load_tokens().get("ado")
        if entry:
            return entry.access_token
    except Exception:  # noqa: BLE001, S110
        pass
    return ""


def _spyglass_has_auto_auth() -> bool:
    """Return True if the running SpyGlass supports auto-auth (new code)."""
    from urllib.request import urlopen

    try:
        with urlopen(f"{_SPYGLASS_BASE}/api/version", timeout=2) as resp:  # noqa: S310
            return resp.status == 200
    except Exception:  # noqa: BLE001
        return False


def _is_spyglass_process(pid: str) -> bool:
    """Check whether a PID belongs to a SpyGlass process."""
    if platform.system() == "Windows":
        try:
            result = subprocess.run(  # noqa: S603
                ["wmic", "process", "where", f"ProcessId={pid}",  # noqa: S607
                 "get", "CommandLine", "/FORMAT:LIST"],
                capture_output=True, text=True, timeout=5,
            )
            return "spyglass" in result.stdout.lower()
        except (OSError, subprocess.TimeoutExpired):
            return False
    else:
        try:
            result = subprocess.run(  # noqa: S603
                ["ps", "-p", pid, "-o", "args="],  # noqa: S607
                capture_output=True, text=True, timeout=5,
            )
            return "spyglass" in result.stdout.lower()
        except (OSError, subprocess.TimeoutExpired):
            return False


def _kill_spyglass_on_port() -> None:
    """Kill SpyGlass processes listening on the SpyGlass port."""
    _, port = _spyglass_port()
    if platform.system() == "Windows":
        try:
            out = subprocess.run(  # noqa: S603
                ["netstat", "-ano"],  # noqa: S607
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    pid = line.strip().split()[-1]
                    if pid.isdigit() and _is_spyglass_process(pid):
                        subprocess.run(  # noqa: S603
                            ["taskkill", "/F", "/PID", pid],  # noqa: S607
                            capture_output=True, timeout=5,
                        )
        except Exception:  # noqa: BLE001, S110
            pass
    else:
        try:
            out = subprocess.run(  # noqa: S603
                ["lsof", "-ti", f":{port}"],  # noqa: S607
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            for pid in out.split():
                if pid.isdigit() and _is_spyglass_process(pid):
                    import signal

                    os.kill(int(pid), signal.SIGTERM)
        except Exception:  # noqa: BLE001, S110
            pass
    time.sleep(1)


def _start_spyglass(
    script: str, *, pat: str = "", org: str = "",
) -> str:
    """Launch SpyGlass subprocess. Returns error message or empty on success."""
    global _SPYGLASS_PROC  # noqa: PLW0603
    _, port = _spyglass_port()
    env = os.environ.copy()
    env["SPYGLASS_PORT"] = str(port)
    resolved_pat = pat or _get_ado_pat()
    if resolved_pat:
        env["SPYGLASS_TOKEN"] = resolved_pat
    if org:
        env["SPYGLASS_ORG"] = org
    try:
        _SPYGLASS_PROC = subprocess.Popen(  # noqa: S603
            [sys.executable, script],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return f"Failed to start SpyGlass: {exc}"
    for _ in range(20):
        time.sleep(0.25)
        if _spyglass_reachable():
            return ""
    return "SpyGlass started but not responding. Check flask/requests are installed."


def ensure_spyglass(*, pat: str = "", org: str = "") -> str:
    """Start SpyGlass if not already running, passing credentials for auto-auth.

    If an old SpyGlass instance without auto-auth support is detected,
    it is killed and replaced with the bundled version.

    Returns an empty string on success, or an error message.
    """
    if _spyglass_reachable():
        if _spyglass_has_auto_auth():
            return ""
        _kill_spyglass_on_port()
    script = _find_spyglass_script()
    if not script:
        return "SpyGlass not found. Set BH_SPYGLASS_PATH or place spyglass.py in contrib/."
    return _start_spyglass(script, pat=pat, org=org)


def open_in_spyglass(
    url: str, *, pat: str = "", org: str = "", project: str = "",
) -> tuple[bool, str]:
    """Ensure SpyGlass is running and open *url*.

    Credentials are passed to SpyGlass via environment at startup (never in the
    URL).  Returns ``(success, display_url)``.
    """
    err = ensure_spyglass(pat=pat, org=org)
    if err:
        return False, err
    if open_url(url):
        return True, url
    return False, f"Failed to open browser. URL: {url}"


# ---------------------------------------------------------------------------
# ado:// resource ID → SpyGlass hash fragment mapping
# ---------------------------------------------------------------------------

_SPYGLASS_RESOURCE_MAP: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^ado://[^/]+/[^/]+/repo/(.+)$"), "repos"),
    (re.compile(r"^ado://[^/]+/[^/]+/(?:pipeline|build)/(\d+)"), "pipelines/{1}"),
    (re.compile(r"^ado://[^/]+/[^/]+/vargroup/(\d+)$"), "library/{1}"),
    (re.compile(r"^ado://[^/]+/[^/]+/endpoint/([^/]+)"), "connections/{1}"),
    (re.compile(r"^ado://[^/]+/[^/]+/wi/(\d+)$"), "boards/{1}"),
    (re.compile(r"^ado://[^/]+/(?:[^/]+/)?feed/([^/]+)"), "artifacts/{1}"),
    (re.compile(r"^ado://[^/]+/[^/]+/release/"), "pipelines"),
    (re.compile(r"^ado://[^/]+/[^/]+/wiki/(.+)$"), "wiki/{1}"),
    (re.compile(r"^ado://[^/]+/[^/]+/([^/]+)/pr/\d+$"), "repos/{1}"),
]


def spyglass_resource_url(
    resource_id: str, name: str = "", file_path: str = "",
) -> str:
    """Convert an ado:// resource ID to a SpyGlass deep-link URL, or ``''``."""
    if not resource_id or not resource_id.startswith("ado://"):
        return ""
    project = extract_project(resource_id)
    for pattern, template in _SPYGLASS_RESOURCE_MAP:
        m = pattern.match(resource_id)
        if m:
            fragment = template
            for i, group in enumerate(m.groups(), 1):
                fragment = fragment.replace(f"{{{i}}}", _quote(group, safe=""))
            if fragment == "repos" and name:
                fragment = f"repos/{_quote(name, safe='')}"
                if file_path:
                    fragment += f"/{_quote(file_path.lstrip('/'), safe='/')}"
            return _spyglass_url(fragment, project)
    return ""


def spyglass_finding_url(details: dict, resource_id: str = "") -> str:
    """Return the best SpyGlass URL for a finding."""
    details = details or {}
    project = details.get("project", "") or extract_project(resource_id)
    repo = details.get("repo_name", "")
    file_path = details.get("file_path", "")
    pipeline_id = details.get("pipeline_id", "")
    wiki_name = details.get("wiki_name", "")
    if wiki_name:
        frag = f"wiki/{_quote(wiki_name, safe='')}"
        page_path = details.get("page_path", "")
        if page_path:
            frag += f"/{_quote(page_path.lstrip('/'), safe='/')}"
        return _spyglass_url(frag, project)
    if repo:
        frag = f"repos/{_quote(repo, safe='')}"
        if file_path:
            frag += f"/{_quote(file_path.lstrip('/'), safe='/')}"
        return _spyglass_url(frag, project)
    if pipeline_id:
        return _spyglass_url(f"pipelines/{_quote(str(pipeline_id), safe='')}", project)
    if details.get("group_name") or "variable" in details.get("kind", "").lower():
        group_id = details.get("group_id", "")
        if group_id:
            return _spyglass_url(f"library/{_quote(str(group_id), safe='')}", project)
        return _spyglass_url("library", project)
    if details.get("endpoint_name") or "endpoint" in details.get("kind", "").lower():
        endpoint_id = details.get("endpoint_id", "")
        if endpoint_id:
            return _spyglass_url(f"connections/{_quote(str(endpoint_id), safe='')}", project)
        return _spyglass_url("connections", project)
    name = ""
    for key in ("repo_name", "name"):
        name = details.get(key, "")
        if name:
            break
    return spyglass_resource_url(resource_id, name=name, file_path=file_path)


def spyglass_credential_url(details: dict) -> str:
    """Return the best SpyGlass URL for a credential."""
    if not details:
        return ""
    project = details.get("project", "")
    wiki_name = details.get("wiki_name", "")
    if wiki_name:
        frag = f"wiki/{_quote(wiki_name, safe='')}"
        page_path = details.get("page_path", "")
        if page_path:
            frag += f"/{_quote(page_path.lstrip('/'), safe='/')}"
        return _spyglass_url(frag, project)
    repo = details.get("repo_name", "")
    file_path = details.get("file_path", "")
    pipeline_id = details.get("pipeline_id", "")
    if repo:
        frag = f"repos/{_quote(repo, safe='')}"
        if file_path:
            frag += f"/{_quote(file_path.lstrip('/'), safe='/')}"
        return _spyglass_url(frag, project)
    if pipeline_id:
        return _spyglass_url(f"pipelines/{_quote(str(pipeline_id), safe='')}", project)
    if details.get("group_name") or details.get("variable_name"):
        group_id = details.get("group_id", "")
        if group_id:
            return _spyglass_url(f"library/{_quote(str(group_id), safe='')}", project)
        return _spyglass_url("library", project)
    return ""

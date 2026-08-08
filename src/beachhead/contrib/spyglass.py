#!/usr/bin/env python3
"""
SpyGlass - an Azure DevOps browser driven by a PAT.

Paste an Azure DevOps PAT (or an aud=499b84ac-1321-427f-aa17-267ca6975798 access
token) and an org. SpyGlass probes what the token can reach, then lets you browse
and interact with the org through a UI styled like Azure DevOps - repos, files,
pipelines, work items, and the variable-group library - without ever signing in
to Entra.

The twist: the capability probe drives the chrome. Any left-nav section the token
cannot reach is greyed and locked, so "what does this PAT unlock" is answered by
the navigation itself rather than a separate screen.

Principles:
  * Read-only. Browse and inspect - no mutations, no writes to the target org.
  * No persistence. Token lives in server-side memory for the session, never on
    disk, never returned to the browser. Clear wipes it.
  * No external calls. System fonts, inline SVG icons - nothing beacons out.
  * Local by default. Binds 127.0.0.1, debug off, runtime-random secret key.
  * Honest errors. 403 (valid token, scope denied) is never called "invalid".

Run:  python spyglass.py   ->   http://127.0.0.1:5057
"""

from __future__ import annotations

import os
import re
import base64
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import requests
from flask import Flask, request, jsonify, session, Response

HTTP_TIMEOUT = 15
USER_AGENT = "SpyGlass/2.0"
API = "7.1"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
_TOKENS: dict[str, dict] = {}  # sid -> {"auth","org","project"}
_PENDING: dict[str, dict] = {}  # claim_token -> {"token","org","project","expires"}
_MAX_SESSIONS = 100

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def build_auth_header(token: str) -> str:
    token = token.strip()
    if JWT_RE.match(token):
        return f"Bearer {token}"
    return "Basic " + base64.b64encode(f":{token}".encode("ascii")).decode("ascii")


# --------------------------------------------------------------------------- #
# Capability probe (drives the scope-aware chrome)
# --------------------------------------------------------------------------- #
@dataclass
class Probe:
    id: str
    label: str
    scope: str
    tier: str
    url: str
    method: str = "GET"
    body: Optional[dict] = None


PROBES = [
    Probe("projects", "Overview", "Project & Team", "org",
          "https://dev.azure.com/{org}/_apis/projects?api-version=" + API),
    Probe("feeds", "Artifacts", "Packaging", "org",
          "https://feeds.dev.azure.com/{org}/_apis/packaging/feeds?api-version=" + API),
    Probe("work_items", "Boards", "Work Items", "project",
          "https://dev.azure.com/{org}/{project}/_apis/wit/wiql?api-version=" + API,
          method="POST", body={"query": "SELECT [System.Id] FROM WorkItems"}),
    Probe("service_endpoints", "Connections", "Service Connections", "project",
          "https://dev.azure.com/{org}/{project}/_apis/serviceendpoint/endpoints?api-version=" + API + "-preview.4"),
    Probe("graph_users", "Directory", "Graph", "org",
          "https://vssps.dev.azure.com/{org}/_apis/graph/users?api-version=" + API + "-preview.1"),
    Probe("variable_groups", "Library", "Variable Groups", "project",
          "https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=" + API),
    Probe("pipelines", "Pipelines", "Build", "project",
          "https://dev.azure.com/{org}/{project}/_apis/pipelines?api-version=" + API),
    Probe("repositories", "Repos", "Code", "project",
          "https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=" + API),
    Probe("test_plans", "Test Plans", "Test Management", "project",
          "https://dev.azure.com/{org}/{project}/_apis/testplan/plans?api-version=" + API),
    Probe("wikis", "Wiki", "Wiki", "project",
          "https://dev.azure.com/{org}/{project}/_apis/wiki/wikis?api-version=" + API),
]
PROBES_BY_ID = {p.id: p for p in PROBES}

OK, EMPTY, DENIED, UNAUTH, NOTFOUND, UNTESTED, ERROR = (
    "confirmed", "empty", "denied", "unauthorized", "not_found", "untested", "error")
LIST_KEYS = ("value", "workItems")


def extract_count(data):
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in LIST_KEYS:
            if isinstance(data.get(k), list):
                return len(data[k])
        if isinstance(data.get("count"), int):
            return data["count"]
    return None


def classify(resp):
    ct = resp.headers.get("Content-Type", "").lower()
    code = resp.status_code
    if code in (203, 302) or (code == 200 and "text/html" in ct):
        return UNAUTH, None
    if code == 401:
        return UNAUTH, None
    if code == 403:
        return DENIED, None
    if code == 404:
        return NOTFOUND, None
    if code == 200:
        try:
            n = extract_count(resp.json())
        except ValueError:
            return ERROR, None
        return OK, n
    return ERROR, None


def run_probe(sess, probe, org, project, auth):
    if probe.tier == "project" and not project:
        return {"id": probe.id, "label": probe.label, "scope": probe.scope,
                "tier": probe.tier, "status": UNTESTED, "http": None, "count": None}
    url = probe.url.format(org=org, project=project or "")
    h = {"Authorization": auth, "Accept": "application/json", "User-Agent": USER_AGENT}
    try:
        r = (sess.post(url, headers=h, json=probe.body, timeout=HTTP_TIMEOUT)
             if probe.method == "POST" else sess.get(url, headers=h, timeout=HTTP_TIMEOUT))
    except requests.RequestException:
        return {"id": probe.id, "label": probe.label, "scope": probe.scope,
                "tier": probe.tier, "status": ERROR, "http": None, "count": None}
    status, count = classify(r)
    return {"id": probe.id, "label": probe.label, "scope": probe.scope,
            "tier": probe.tier, "status": status, "http": r.status_code, "count": count}


def sid():
    if "sid" not in session:
        session["sid"] = secrets.token_urlsafe(24)
    return session["sid"]


# --------------------------------------------------------------------------- #
# Read-only Azure DevOps GET helper (used by all browse endpoints)
# --------------------------------------------------------------------------- #
def ado_get(path, params=None):
    st = _TOKENS.get(sid())
    if not st:
        return None, ("no_session", "Run a scan first.")
    url = path if path.startswith("http") else f"https://dev.azure.com/{st['org']}/{path}"
    p = {"api-version": API}
    if params:
        p.update(params)
    try:
        r = requests.get(url, headers={"Authorization": st["auth"], "Accept": "application/json",
                                       "User-Agent": USER_AGENT}, params=p, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return None, ("network", e.__class__.__name__)
    ct = r.headers.get("Content-Type", "").lower()
    if r.status_code in (203, 302) or (r.status_code == 200 and "text/html" in ct):
        return None, ("unauth", "Token not accepted for this resource.")
    if r.status_code == 401:
        return None, ("unauth", "401 - token not accepted.")
    if r.status_code == 403:
        return None, ("denied", "403 - this scope is not granted to the token.")
    if r.status_code == 404:
        return None, ("not_found", "404 - not found.")
    if r.status_code != 200:
        return None, ("error", f"HTTP {r.status_code}")
    try:
        return r.json(), None
    except ValueError:
        return {"_text": r.text, "_encoding": r.encoding or "utf-8"}, None


def _ado_mutate(method, path, body=None, params=None, content_type="application/json"):
    st = _TOKENS.get(sid())
    if not st:
        return None, ("no_session", "Run a scan first.")
    url = path if path.startswith("http") else f"https://dev.azure.com/{st['org']}/{path}"
    p = {"api-version": API}
    if params:
        p.update(params)
    h = {"Authorization": st["auth"], "Accept": "application/json",
         "Content-Type": content_type, "User-Agent": USER_AGENT}
    try:
        r = requests.request(method, url, headers=h, json=body, params=p, timeout=HTTP_TIMEOUT)
    except requests.RequestException as e:
        return None, ("network", e.__class__.__name__)
    ct = r.headers.get("Content-Type", "").lower()
    if r.status_code in (203, 302) or (r.status_code == 200 and "text/html" in ct):
        return None, ("unauth", "Token not accepted for this resource.")
    if r.status_code == 401:
        return None, ("unauth", "401 - token not accepted.")
    if r.status_code == 403:
        return None, ("denied", "403 - this scope is not granted to the token.")
    if r.status_code == 404:
        return None, ("not_found", "404 - not found.")
    if r.status_code not in (200, 201):
        try:
            msg = r.json().get("message", f"HTTP {r.status_code}")
        except (ValueError, AttributeError):
            msg = f"HTTP {r.status_code}"
        return None, ("error", msg)
    try:
        return r.json(), None
    except ValueError:
        return None, ("error", "Invalid JSON response")


def ado_post(path, body, params=None):
    return _ado_mutate("POST", path, body, params)



def _err(pair):
    kind, msg = pair
    code = {"no_session": 400, "unauth": 401, "denied": 403, "not_found": 404}.get(kind, 502)
    return jsonify({"error": msg, "kind": kind}), code


def _shortbranch(ref):
    return (ref or "").replace("refs/heads/", "") if ref else ""


@app.get("/api/version")
def api_version():
    return jsonify({"version": 2, "auto_auth": True})


# --------------------------------------------------------------------------- #
# API: scope
# --------------------------------------------------------------------------- #
def _execute_probe(token, org, project=None):
    """Run the capability probe and return the result dict (includes 'auth' key)."""
    auth = build_auth_header(token)
    sess = requests.Session()
    surfaces = []
    for p in [p for p in PROBES if p.tier == "org"]:
        surfaces.append(run_probe(sess, p, org, None, auth))

    project_used, project_source = project, ("supplied" if project else None)
    projects_list = []
    proj_row = next((s for s in surfaces if s["id"] == "projects"), None)
    if proj_row and proj_row["status"] == OK:
        try:
            projects_list = sess.get(
                f"https://dev.azure.com/{org}/_apis/projects?api-version={API}",
                headers={"Authorization": auth, "Accept": "application/json",
                         "User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT).json().get("value", [])
        except (requests.RequestException, ValueError):
            projects_list = []
        if not project_used and projects_list:
            project_used, project_source = projects_list[0].get("name"), "auto"

    for p in [p for p in PROBES if p.tier == "project"]:
        surfaces.append(run_probe(sess, p, org, project_used, auth))

    reach = [s for s in surfaces if s["status"] in (OK, EMPTY)]
    authed = [s for s in surfaces if s["status"] in (OK, EMPTY, DENIED)]
    unauth = [s for s in surfaces if s["status"] == UNAUTH]
    if reach:
        verdict = "live"
    elif authed:
        verdict = "live_narrow"
    elif unauth and not authed:
        verdict = "dead"
    else:
        verdict = "indeterminate"

    return {
        "_auth": auth, "org": org, "verdict": verdict,
        "scheme": auth.split(" ", 1)[0],
        "project_used": project_used, "project_source": project_source,
        "projects": [{"id": p.get("id"), "name": p.get("name"),
                      "visibility": p.get("visibility")} for p in projects_list],
        "surfaces": surfaces,
    }


@app.post("/api/probe")
def api_probe():
    payload = request.get_json(silent=True) or {}
    token = (payload.get("token") or "").strip()
    org = (payload.get("org") or "").strip().strip("/")
    project = (payload.get("project") or "").strip() or None
    if not token or not org:
        return jsonify({"error": "Both a token and an organization are required."}), 400
    result = _execute_probe(token, org, project)
    auth = result.pop("_auth")
    while len(_TOKENS) >= _MAX_SESSIONS:
        _TOKENS.pop(next(iter(_TOKENS)))
    _TOKENS[sid()] = {"auth": auth, "org": result["org"], "project": result["project_used"]}
    return jsonify(result)


@app.post("/api/preauth")
def api_preauth():
    """Auto-authenticate using SPYGLASS_TOKEN / SPYGLASS_ORG env vars (set by Beachhead)."""
    if _TOKENS.get(sid()):
        st = _TOKENS[sid()]
        return jsonify({"preauth": True, "org": st["org"], "already": True})
    token = os.environ.get("SPYGLASS_TOKEN", "").strip()
    org = os.environ.get("SPYGLASS_ORG", "").strip().strip("/")
    if not token or not org:
        return jsonify({"preauth": False})
    result = _execute_probe(token, org, os.environ.get("SPYGLASS_PROJECT", "").strip() or None)
    auth = result.pop("_auth")
    while len(_TOKENS) >= _MAX_SESSIONS:
        _TOKENS.pop(next(iter(_TOKENS)))
    _TOKENS[sid()] = {"auth": auth, "org": result["org"], "project": result["project_used"]}
    result["preauth"] = True
    return jsonify(result)


@app.post("/api/inject")
def api_inject():
    """Accept credentials from a host framework, return a one-time claim token."""
    payload = request.get_json(silent=True) or {}
    token = (payload.get("token") or "").strip()
    org = (payload.get("org") or "").strip().strip("/")
    project = (payload.get("project") or "").strip() or None
    if not token or not org:
        return jsonify({"error": "token and org required"}), 400
    claim = secrets.token_urlsafe(16)
    now = time.time()
    for k in [k for k, v in _PENDING.items() if v["expires"] < now]:
        _PENDING.pop(k, None)
    _PENDING[claim] = {"token": token, "org": org, "project": project, "expires": now + 120}
    return jsonify({"claim": claim})


@app.post("/api/claim")
def api_claim():
    """Claim injected credentials by one-time token, run probe, establish session."""
    payload = request.get_json(silent=True) or {}
    claim = (payload.get("claim") or "").strip()
    pending = _PENDING.pop(claim, None) if claim else None
    if not pending or time.time() > pending["expires"]:
        return jsonify({"claimed": False})
    result = _execute_probe(pending["token"], pending["org"], pending["project"])
    auth = result.pop("_auth")
    while len(_TOKENS) >= _MAX_SESSIONS:
        _TOKENS.pop(next(iter(_TOKENS)))
    _TOKENS[sid()] = {"auth": auth, "org": result["org"], "project": result["project_used"]}
    result["claimed"] = True
    return jsonify(result)


@app.post("/api/clear")
def api_clear():
    _TOKENS.pop(sid(), None)
    return jsonify({"cleared": True})


@app.post("/api/reprobe")
def api_reprobe():
    """Re-run project-scoped probes when the operator switches projects."""
    st = _TOKENS.get(sid())
    if not st:
        return jsonify({"error": "No active session."}), 400
    payload = request.get_json(silent=True) or {}
    project = (payload.get("project") or "").strip()
    if not project:
        return jsonify({"error": "Project is required."}), 400
    st["project"] = project
    sess = requests.Session()
    surfaces = []
    for p in [p for p in PROBES if p.tier == "project"]:
        surfaces.append(run_probe(sess, p, st["org"], project, st["auth"]))
    return jsonify({"surfaces": surfaces, "project": project})


# --------------------------------------------------------------------------- #
# API: browse (read-only)
# --------------------------------------------------------------------------- #
@app.get("/api/repos")
def api_repos():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/git/repositories")
    if err:
        return _err(err)
    repos = data.get("value", [])
    return jsonify([{"id": r["id"], "name": r["name"],
                     "defaultBranch": _shortbranch(r.get("defaultBranch")),
                     "size": r.get("size", 0), "webUrl": r.get("webUrl", "")} for r in repos])


@app.get("/api/tree")
def api_tree():
    project = request.args.get("project", "")
    repo = request.args.get("repo", "")
    path = request.args.get("path", "/") or "/"
    branch = request.args.get("branch", "")
    params = {"scopePath": path, "recursionLevel": "OneLevel"}
    if branch:
        params["versionDescriptor.version"] = branch
        params["versionDescriptor.versionType"] = "branch"
    data, err = ado_get(f"{project}/_apis/git/repositories/{repo}/items", params)
    if err:
        return _err(err)
    items = []
    for it in data.get("value", []):
        if it.get("path", "") == path:  # skip the folder itself
            continue
        items.append({"path": it.get("path", ""),
                      "isFolder": bool(it.get("isFolder") or it.get("gitObjectType") == "tree"),
                      "name": it.get("path", "").rstrip("/").split("/")[-1]})
    items.sort(key=lambda x: (not x["isFolder"], x["name"].lower()))
    return jsonify(items)


@app.get("/api/file")
def api_file():
    project = request.args.get("project", "")
    repo = request.args.get("repo", "")
    path = request.args.get("path", "")
    branch = request.args.get("branch", "")
    params = {"path": path, "includeContent": "true"}
    if branch:
        params["versionDescriptor.version"] = branch
        params["versionDescriptor.versionType"] = "branch"
    data, err = ado_get(f"{project}/_apis/git/repositories/{repo}/items", params)
    if err:
        return _err(err)
    content = data.get("content", data.get("_text", "")) if isinstance(data, dict) else ""
    return jsonify({"path": path, "content": content, "size": len(content or "")})


@app.get("/api/branches")
def api_branches():
    project = request.args.get("project", "")
    repo = request.args.get("repo", "")
    data, err = ado_get(f"{project}/_apis/git/repositories/{repo}/refs", {"filter": "heads/"})
    if err:
        return _err(err)
    return jsonify([{"name": _shortbranch(r.get("name")),
                     "objectId": (r.get("objectId") or "")[:8],
                     "creator": (r.get("creator") or {}).get("displayName", "")}
                    for r in data.get("value", [])])


@app.get("/api/commits")
def api_commits():
    project = request.args.get("project", "")
    repo = request.args.get("repo", "")
    branch = request.args.get("branch", "")
    params = {"searchCriteria.$top": "30"}
    if branch:
        params["searchCriteria.itemVersion.version"] = branch
    data, err = ado_get(f"{project}/_apis/git/repositories/{repo}/commits", params)
    if err:
        return _err(err)
    return jsonify([{"commitId": (c.get("commitId") or "")[:8],
                     "comment": c.get("comment", ""),
                     "author": (c.get("author") or {}).get("name", ""),
                     "date": (c.get("author") or {}).get("date", "")}
                    for c in data.get("value", [])])


@app.get("/api/pipelines")
def api_pipelines():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/pipelines")
    if err:
        return _err(err)
    return jsonify([{"id": p.get("id"), "name": p.get("name"),
                     "folder": p.get("folder", "")} for p in data.get("value", [])])


@app.get("/api/pipeline")
def api_pipeline():
    project = request.args.get("project", "")
    pid = request.args.get("id", "")
    data, err = ado_get(f"{project}/_apis/pipelines/{pid}")
    if err:
        return _err(err)
    cfg = data.get("configuration", {}) or {}
    result = {"id": data.get("id"), "name": data.get("name"),
              "type": cfg.get("type", "unknown"),
              "path": cfg.get("path", ""),
              "repoId": ((cfg.get("repository") or {}).get("id", "")),
              "yaml": None}
    # For YAML pipelines the definition lives in the repo; fetch it read-only.
    if cfg.get("path") and result["repoId"]:
        fdata, ferr = ado_get(
            f"{project}/_apis/git/repositories/{result['repoId']}/items",
            {"path": cfg["path"], "includeContent": "true"})
        if not ferr and isinstance(fdata, dict):
            result["yaml"] = fdata.get("content", fdata.get("_text"))
    return jsonify(result)


@app.get("/api/variablegroups")
def api_variablegroups():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/distributedtask/variablegroups")
    if err:
        return _err(err)
    out = []
    for g in data.get("value", []):
        variables = []
        for name, meta in (g.get("variables") or {}).items():
            meta = meta or {}
            variables.append({"name": name, "isSecret": bool(meta.get("isSecret")),
                              "value": (None if meta.get("isSecret") else meta.get("value", ""))})
        variables.sort(key=lambda v: v["name"].lower())
        out.append({"id": g.get("id"), "name": g.get("name"),
                    "type": g.get("type", "Vsts"),
                    "vault": ((g.get("providerData") or {}).get("vault", "")),
                    "description": g.get("description", ""),
                    "variables": variables})
    return jsonify(out)


# --------------------------------------------------------------------------- #
# API: boards (work items)
# --------------------------------------------------------------------------- #
@app.get("/api/workitems")
def api_workitems():
    project = request.args.get("project", "")
    wiql = {"query": "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project ORDER BY [System.ChangedDate] DESC"}
    data, err = ado_post(f"{project}/_apis/wit/wiql", wiql, {"$top": "200"})
    if err:
        return _err(err)
    ids = [wi["id"] for wi in data.get("workItems", [])]
    if not ids:
        return jsonify([])
    ids_str = ",".join(str(i) for i in ids[:200])
    fields = "System.Id,System.Title,System.State,System.WorkItemType,System.AssignedTo,System.CreatedDate,System.ChangedDate,System.IterationPath,System.AreaPath"
    items_data, items_err = ado_get(f"{project}/_apis/wit/workitems", {"ids": ids_str, "fields": fields})
    if items_err:
        return _err(items_err)
    out = []
    for wi in items_data.get("value", []):
        f = wi.get("fields", {})
        out.append({
            "id": wi.get("id"), "title": f.get("System.Title", ""),
            "state": f.get("System.State", ""), "type": f.get("System.WorkItemType", ""),
            "assignedTo": (f.get("System.AssignedTo") or {}).get("displayName", ""),
            "createdDate": f.get("System.CreatedDate", ""),
            "changedDate": f.get("System.ChangedDate", ""),
            "iteration": f.get("System.IterationPath", ""),
            "area": f.get("System.AreaPath", ""),
        })
    return jsonify(out)


@app.get("/api/workitem")
def api_workitem():
    project = request.args.get("project", "")
    wid = request.args.get("id", "")
    data, err = ado_get(f"{project}/_apis/wit/workitems/{wid}", {"$expand": "all"})
    if err:
        return _err(err)
    f = data.get("fields", {})
    clean = {}
    for k, v in f.items():
        if isinstance(v, dict) and "displayName" in v:
            clean[k] = v["displayName"]
        elif isinstance(v, dict) and "name" in v:
            clean[k] = v["name"]
        else:
            clean[k] = v
    return jsonify({"id": data.get("id"), "rev": data.get("rev"), "url": data.get("url", ""),
                    "fields": clean,
                    "relations": [{"rel": r.get("rel", ""), "url": r.get("url", ""),
                                   "name": (r.get("attributes") or {}).get("name", r.get("rel", ""))}
                                  for r in (data.get("relations") or [])]})


# --------------------------------------------------------------------------- #
# API: test plans
# --------------------------------------------------------------------------- #
@app.get("/api/testplans")
def api_testplans():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/testplan/plans")
    if err:
        return _err(err)
    return jsonify([{"id": p.get("id"), "name": p.get("name", ""),
                     "state": p.get("state", ""), "iteration": p.get("iteration", ""),
                     "owner": (p.get("owner") or {}).get("displayName", ""),
                     "startDate": p.get("startDate", ""), "endDate": p.get("endDate", "")}
                    for p in data.get("value", [])])


@app.get("/api/testsuites")
def api_testsuites():
    project = request.args.get("project", "")
    plan_id = request.args.get("plan", "")
    data, err = ado_get(f"{project}/_apis/testplan/Plans/{plan_id}/suites")
    if err:
        return _err(err)
    return jsonify([{"id": s.get("id"), "name": s.get("name", ""),
                     "suiteType": s.get("suiteType", ""),
                     "testCaseCount": s.get("testCaseCount", 0),
                     "parentSuite": (s.get("parentSuite") or {}).get("name", "")}
                    for s in data.get("value", [])])


@app.get("/api/testcases")
def api_testcases():
    project = request.args.get("project", "")
    plan_id = request.args.get("plan", "")
    suite_id = request.args.get("suite", "")
    data, err = ado_get(f"{project}/_apis/testplan/Plans/{plan_id}/Suites/{suite_id}/TestCase")
    if err:
        return _err(err)
    return jsonify([{"id": (tc.get("workItem") or {}).get("id"),
                     "name": (tc.get("workItem") or {}).get("name", ""),
                     "pointAssignments": tc.get("pointAssignments", [])}
                    for tc in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: artifacts (feeds & packages)
# --------------------------------------------------------------------------- #
@app.get("/api/feeds")
def api_feeds():
    st = _TOKENS.get(sid())
    if not st:
        return jsonify({"error": "Run a scan first."}), 400
    data, err = ado_get(f"https://feeds.dev.azure.com/{st['org']}/_apis/packaging/feeds")
    if err:
        return _err(err)
    return jsonify([{"id": f.get("id"), "name": f.get("name", ""),
                     "description": f.get("description", ""),
                     "upstreamEnabled": f.get("upstreamEnabled", False),
                     "project": (f.get("project") or {}).get("name", "")}
                    for f in data.get("value", [])])


@app.get("/api/packages")
def api_packages():
    st = _TOKENS.get(sid())
    if not st:
        return jsonify({"error": "Run a scan first."}), 400
    feed_id = request.args.get("feed", "")
    data, err = ado_get(f"https://feeds.dev.azure.com/{st['org']}/_apis/packaging/Feeds/{feed_id}/packages",
                        {"$top": "100"})
    if err:
        return _err(err)
    return jsonify([{"id": p.get("id"), "name": p.get("name", ""),
                     "protocolType": p.get("protocolType", ""),
                     "version": ((p.get("versions") or [{}])[0]).get("version", "") if p.get("versions") else ""}
                    for p in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: pull requests
# --------------------------------------------------------------------------- #
@app.get("/api/pullrequests")
def api_pullrequests():
    project = request.args.get("project", "")
    repo = request.args.get("repo", "")
    status = request.args.get("status", "all")
    data, err = ado_get(f"{project}/_apis/git/repositories/{repo}/pullrequests",
                        {"searchCriteria.status": status, "$top": "50"})
    if err:
        return _err(err)
    return jsonify([{"id": pr.get("pullRequestId"), "title": pr.get("title", ""),
                     "status": pr.get("status", ""),
                     "createdBy": (pr.get("createdBy") or {}).get("displayName", ""),
                     "creationDate": pr.get("creationDate", ""),
                     "sourceBranch": _shortbranch(pr.get("sourceRefName")),
                     "targetBranch": _shortbranch(pr.get("targetRefName")),
                     "mergeStatus": pr.get("mergeStatus", ""),
                     "reviewers": [{"name": rv.get("displayName", ""), "vote": rv.get("vote", 0)}
                                   for rv in (pr.get("reviewers") or [])]}
                    for pr in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: pipeline runs
# --------------------------------------------------------------------------- #
@app.get("/api/runs")
def api_runs():
    project = request.args.get("project", "")
    pid = request.args.get("pipeline", "")
    data, err = ado_get(f"{project}/_apis/pipelines/{pid}/runs")
    if err:
        return _err(err)
    return jsonify([{"id": r.get("id"), "name": r.get("name", ""),
                     "state": r.get("state", ""), "result": r.get("result", ""),
                     "createdDate": r.get("createdDate", ""),
                     "finishedDate": r.get("finishedDate", "")}
                    for r in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: service connections
# --------------------------------------------------------------------------- #
@app.get("/api/serviceendpoints")
def api_serviceendpoints():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/serviceendpoint/endpoints")
    if err:
        return _err(err)
    return jsonify([{"id": e.get("id"), "name": e.get("name", ""),
                     "type": e.get("type", ""), "url": e.get("url", ""),
                     "description": e.get("description", ""),
                     "isReady": e.get("isReady", False),
                     "createdBy": (e.get("createdBy") or {}).get("displayName", ""),
                     "scheme": ((e.get("authorization") or {}).get("scheme", ""))}
                    for e in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: organization members
# --------------------------------------------------------------------------- #
@app.get("/api/members")
def api_members():
    st = _TOKENS.get(sid())
    if not st:
        return jsonify({"error": "Run a scan first."}), 400
    data, err = ado_get(
        f"https://vssps.dev.azure.com/{st['org']}/_apis/graph/users",
        {"api-version": API + "-preview.1"})
    if err:
        return _err(err)
    return jsonify([{"displayName": u.get("displayName", ""),
                     "mailAddress": u.get("mailAddress", ""),
                     "origin": u.get("origin", ""),
                     "originId": u.get("originId", ""),
                     "descriptor": u.get("descriptor", "")}
                    for u in data.get("value", [])])


# --------------------------------------------------------------------------- #
# API: wiki
# --------------------------------------------------------------------------- #
@app.get("/api/wikis")
def api_wikis():
    project = request.args.get("project", "")
    data, err = ado_get(f"{project}/_apis/wiki/wikis")
    if err:
        return _err(err)
    return jsonify([{"id": w.get("id", ""), "name": w.get("name", ""),
                     "type": w.get("type", ""), "versions": [
                         v.get("version", "") for v in (w.get("versions") or [])],
                     "projectId": (w.get("mappedPath") or w.get("projectId", "")),
                     "repositoryId": w.get("repositoryId", "")}
                    for w in data.get("value", [])])


@app.get("/api/wiki/pages")
def api_wiki_pages():
    project = request.args.get("project", "")
    wiki_id = request.args.get("wiki", "")
    path = request.args.get("path", "/")
    data, err = ado_get(f"{project}/_apis/wiki/wikis/{wiki_id}/pages",
                        {"path": path, "recursionLevel": "full"})
    if err:
        return _err(err)

    def _flatten(page, depth=0):
        out = [{"path": page.get("path", "/"), "order": page.get("order", 0),
                "depth": depth, "pageId": page.get("id", 0)}]
        for child in page.get("subPages") or []:
            out.extend(_flatten(child, depth + 1))
        return out

    return jsonify(_flatten(data))


@app.get("/api/wiki/page")
def api_wiki_page():
    project = request.args.get("project", "")
    wiki_id = request.args.get("wiki", "")
    path = request.args.get("path", "/")
    if path != "/" and path.endswith(".md"):
        path = path[:-3]
    data, err = ado_get(f"{project}/_apis/wiki/wikis/{wiki_id}/pages",
                        {"path": path, "includeContent": "true"})
    if err:
        return _err(err)
    return jsonify({"path": data.get("path", path),
                    "content": data.get("content", ""),
                    "pageId": data.get("id", 0)})


@app.get("/")
def index():
    return Response(PAGE, mimetype="text/html")


# --------------------------------------------------------------------------- #
# UI - single-page app, Azure DevOps visual language, all data via /api/*
# --------------------------------------------------------------------------- #
PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SpyGlass</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%23ff5c57'/%3E%3Cg transform='rotate(-25 16 16)'%3E%3Crect x='1' y='14.2' width='2.5' height='3.6' rx='0.8' fill='%23fff'/%3E%3Crect x='4.5' y='14' width='7.5' height='4' rx='0.8' fill='%23fff'/%3E%3Crect x='13' y='13' width='8' height='6' rx='0.8' fill='%23fff'/%3E%3Crect x='22' y='11.8' width='8' height='8.4' rx='1' fill='%23fff'/%3E%3C/g%3E%3C/svg%3E">
<style>
  /* grimdark theme - ember red / cyan / green on near-black. Layout unchanged. */
  :root{
    --bg:#0b0e14; --panel:#0f131b; --panel2:#141b26; --chrome:#0f131b;
    --ink:#e6e9ef; --ink2:#9aa4b2; --muted:#5c6675;
    --line:#1e2632; --line2:#28323f; --row:#141b26;
    --red:#ff5c57; --red-h:#ff7d78; --cyan:#4cd3e3; --green:#3fb950; --amber:#e0a45c;
    --folder:#e0a45c; --ok:#3fb950; --warn:#e0a45c; --err:#ff5c57;
    --sans:"Segoe UI","Selawik",-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif;
    --mono:"Cascadia Code",Consolas,"SF Mono",Menlo,monospace;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%}
  body{font-family:var(--sans);color:var(--ink);font-size:14px;
       background:radial-gradient(1100px 460px at 72% -12%,rgba(76,211,227,.05),transparent),var(--bg)}
  a{color:var(--cyan);text-decoration:none;cursor:pointer} a:hover{text-decoration:underline}
  button{font-family:var(--sans);cursor:pointer}
  select option{background:var(--panel);color:var(--ink)}
  #app{height:100%}

  /* landing - terminal card */
  .landing{min-height:100%;display:flex;align-items:center;justify-content:center;background:transparent}
  .card{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:6px;box-shadow:0 12px 44px rgba(0,0,0,.55);width:420px;padding:48px 30px 28px}
  .card::before{content:"";position:absolute;top:0;left:0;right:0;height:34px;background:var(--panel2);border-bottom:1px solid var(--line);border-radius:6px 6px 0 0}
  .card::after{content:"";position:absolute;top:12px;left:16px;width:10px;height:10px;border-radius:50%;background:#ff5f57;box-shadow:16px 0 0 #febc2e,32px 0 0 #28c840}
  .card .brand{display:flex;align-items:center;gap:10px;margin-bottom:4px}
  .logo{width:26px;height:26px;border-radius:4px;background:var(--red);display:inline-flex;align-items:center;justify-content:center;box-shadow:0 0 14px rgba(255,92,87,.4)}
  .card h1{font-size:20px;font-weight:600;margin:0;font-family:var(--mono);letter-spacing:.5px;color:var(--ink)}
  .card .sub{color:var(--ink2);font-size:13px;margin:8px 0 20px;line-height:1.5}
  .field{margin-bottom:14px}
  .field label{display:block;font-size:12px;color:var(--ink2);margin-bottom:5px}
  .field input{width:100%;height:32px;border:1px solid var(--line2);border-radius:3px;padding:0 10px;font-family:var(--mono);font-size:13px;background:var(--bg);color:var(--ink)}
  .field input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 1px var(--cyan),0 0 12px rgba(76,211,227,.2)}
  .primary{background:var(--red);border:1px solid var(--red);color:#0b0e14;font-weight:600;height:32px;padding:0 18px;border-radius:3px;font-size:14px;box-shadow:0 0 14px rgba(255,92,87,.32)}
  .primary:hover{background:var(--red-h);border-color:var(--red-h)} .primary:disabled{opacity:.6;cursor:progress}
  .landing .err{margin-top:12px;color:var(--red);font-size:13px}
  .hint{margin-top:16px;color:var(--muted);font-size:12px;line-height:1.5}

  /* shell */
  .top{height:44px;background:var(--panel);color:var(--ink);display:flex;align-items:center;padding:0 14px;gap:10px;border-bottom:1px solid var(--line)}
  .top .org{font-size:15px} .top .sep{color:var(--muted)}
  .top .spacer{flex:1}
  .top .tbtn{color:var(--ink2);font-size:13px;border:1px solid var(--line2);background:transparent;border-radius:3px;padding:5px 10px}
  .top .tbtn:hover{background:var(--panel2);color:var(--ink)}
  .shell{display:flex;height:calc(100% - 44px)}
  .rail{width:220px;border-right:1px solid var(--line);background:var(--panel);overflow:auto;flex:none}
  .phdr{display:flex;align-items:center;gap:10px;padding:14px 16px}
  .phdr .pn{font-weight:600;color:var(--ink)}
  .phdr select.pn{border:none;background:transparent;font-family:var(--sans);font-size:14px;outline:none;cursor:pointer}
  .nav{list-style:none;margin:0;padding:0}
  .nav li{display:flex;align-items:center;gap:12px;padding:9px 16px;font-size:14px;color:var(--ink2);position:relative;cursor:pointer}
  .nav li:hover{background:var(--panel2)}
  .nav li.on{background:rgba(255,92,87,.12);color:var(--ink);font-weight:600}
  .nav li.on::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--red);box-shadow:0 0 10px rgba(255,92,87,.55)}
  .nav li.locked{color:var(--muted);cursor:not-allowed}
  .nav li.locked:hover{background:transparent}
  .nav li .ic{width:16px;height:16px;flex:none;display:inline-flex}
  .nav li .lock{margin-left:auto;width:12px;height:12px;opacity:.7}
  .content{flex:1;overflow:auto;background:var(--bg)}

  .toolbar{display:flex;align-items:center;gap:8px;padding:12px 20px;border-bottom:1px solid var(--line)}
  .drop{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line2);border-radius:3px;padding:6px 10px;background:var(--panel);color:var(--ink);font-size:14px}
  .drop:hover{background:var(--panel2)} .drop b{font-weight:600;color:var(--ink)}
  .drop select{border:none;background:transparent;font-family:var(--sans);font-size:14px;outline:none;color:var(--ink)}
  .toolbar .spacer{flex:1}
  .btn{border:1px solid var(--line2);background:var(--panel);color:var(--ink2);border-radius:3px;padding:6px 12px;font-size:14px}
  .btn:hover{background:var(--panel2);color:var(--ink)}
  .tabs{display:flex;gap:0;border-bottom:1px solid var(--line);padding:0 20px}
  .tab{padding:11px 14px;font-size:14px;color:var(--ink2);border-bottom:2px solid transparent;cursor:pointer}
  .tab.on{color:var(--ink);border-bottom-color:var(--cyan);font-weight:600}
  .tab:hover{color:var(--ink)}

  .h{font-size:20px;font-weight:600;padding:14px 20px 6px;color:var(--ink)}
  .h .path{color:var(--ink2);font-size:14px;font-weight:400}
  .crumbs{padding:10px 20px;color:var(--ink2);font-size:13px}
  .crumbs a{color:var(--cyan)} .crumbs .s{margin:0 6px;color:var(--muted)}

  table.grid{width:100%;border-collapse:collapse}
  table.grid thead td{color:var(--ink2);font-size:12px;font-weight:600;padding:8px 20px;border-bottom:1px solid var(--line)}
  table.grid tbody td{padding:9px 20px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
  table.grid tbody tr:hover{background:var(--panel2)}
  table.grid tbody tr.hl{background:rgba(76,211,227,.1);outline:2px solid var(--cyan)}
  .fn{display:flex;align-items:center;gap:10px}
  .msg{color:var(--ink2)} .when{color:var(--muted);text-align:right;white-space:nowrap}
  .cm{width:22px;height:22px;border-radius:50%;color:#fff;display:inline-flex;align-items:center;justify-content:center;font-size:10px;flex:none;margin-right:8px}

  .readme{margin:22px 20px;border:1px solid var(--line);border-radius:6px;background:var(--panel);overflow:hidden}
  .readme .rh{border-bottom:1px solid var(--line);padding:10px 16px;background:var(--panel2);font-size:13px;color:var(--ink2);font-weight:600;display:flex;align-items:center;gap:8px}
  .readme .rh::before{content:"";flex:none;width:10px;height:10px;border-radius:50%;background:#ff5f57;box-shadow:16px 0 0 #febc2e,32px 0 0 #28c840;margin-right:34px}
  .readme .rb{padding:8px 22px}
  .readme .rb pre{white-space:pre-wrap;font-family:var(--mono);font-size:12.5px;color:var(--ink)}

  .code{position:relative;display:flex;font-family:var(--mono);font-size:12.5px;border:1px solid var(--line);margin:0 20px 24px;border-radius:6px;overflow:auto;padding-top:34px;background:var(--panel)}
  .code::before{content:"";position:absolute;top:0;left:0;right:0;height:34px;background:var(--panel2);border-bottom:1px solid var(--line);border-radius:6px 6px 0 0}
  .code::after{content:"";position:absolute;top:12px;left:16px;width:10px;height:10px;border-radius:50%;background:#ff5f57;box-shadow:16px 0 0 #febc2e,32px 0 0 #28c840;z-index:1}
  .code .gutter{color:var(--muted);text-align:right;padding:12px 10px;background:var(--panel2);border-right:1px solid var(--line);user-select:none;white-space:pre;flex:none}
  .code .src{padding:12px 14px;white-space:pre;overflow:auto;flex:1;color:var(--ink)}

  .pill{display:inline-block;font-size:11px;padding:2px 8px;border-radius:3px;border:1px solid var(--line2);white-space:nowrap;background:var(--panel2)}
  .pill.ok{color:var(--green);border-color:rgba(63,185,80,.4);background:rgba(63,185,80,.1)}
  .pill.dn{color:var(--red);border-color:rgba(255,92,87,.4);background:rgba(255,92,87,.1)}
  .pill.wn{color:var(--amber);border-color:rgba(224,164,92,.4);background:rgba(224,164,92,.1)}
  .pill.na{color:var(--muted)}

  .ov{padding:18px 20px}
  .ov .lead{color:var(--ink2);margin-bottom:16px}
  .ov-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
  .ov-card{border:1px solid var(--line);border-radius:6px;padding:13px 15px;background:var(--panel);transition:border-color .15s,box-shadow .15s}
  .ov-card.ov-link{cursor:pointer} .ov-card.ov-link:hover{border-color:var(--cyan);box-shadow:0 0 0 1px var(--cyan)}
  .ov-card .n{font-weight:600;color:var(--ink)} .ov-card .sc{color:var(--ink2);font-size:12px;margin:4px 0 10px}
  .ov-card .ft{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:12px}

  .vg{margin:0 20px 24px;border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--panel)}
  .vg .vh{display:flex;align-items:center;gap:10px;padding:11px 16px;background:var(--panel2);border-bottom:1px solid var(--line);cursor:pointer}
  .vg .vh::before{content:"";flex:none;width:10px;height:10px;border-radius:50%;background:#ff5f57;box-shadow:16px 0 0 #febc2e,32px 0 0 #28c840;margin-right:34px}
  .vg .vh .nm{font-weight:600;color:var(--ink)} .vg .vh .ty{color:var(--ink2);font-size:12px;margin-left:auto}
  .vg table{width:100%;border-collapse:collapse}
  .vg td{padding:8px 16px;border-bottom:1px solid var(--line);font-size:13px}
  .vg .k{color:var(--cyan);font-family:var(--mono);font-size:12.5px;width:40%}
  .vg .v{color:var(--ink2);font-family:var(--mono);font-size:12.5px}
  .secret{color:var(--amber);font-style:italic;font-family:var(--sans)}

  .empty{padding:40px 20px;color:var(--ink2);text-align:center}
  .msgbox{margin:20px;padding:12px 16px;border:1px solid var(--line2);border-left:3px solid var(--amber);border-radius:3px;background:var(--panel);color:var(--ink2);font-size:13px}
  .loading{padding:30px 20px;color:var(--muted)}

  .wiki-body{margin:0 20px 16px;padding:18px 22px;border:1px solid var(--line);border-radius:6px;background:var(--panel);font-size:14px;line-height:1.7;color:var(--ink2);overflow:auto}
  .wiki-body h1,.wiki-body h2,.wiki-body h3{color:var(--ink);margin:18px 0 8px;font-weight:600}
  .wiki-body h1{font-size:22px;border-bottom:1px solid var(--line);padding-bottom:6px}
  .wiki-body h2{font-size:18px;border-bottom:1px solid var(--line);padding-bottom:4px}
  .wiki-body h3{font-size:15px}
  .wiki-body p{margin:8px 0}
  .wiki-body code{background:var(--panel2);padding:2px 5px;border-radius:3px;font-family:var(--mono);font-size:12.5px}
  .wiki-body pre{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:12px;overflow-x:auto;margin:10px 0}
  .wiki-body pre code{background:none;padding:0}
  .wiki-body ul,.wiki-body ol{padding-left:24px;margin:8px 0}
  .wiki-body li{margin:4px 0}
  .wiki-body a{color:var(--cyan)}
  .wiki-body blockquote{border-left:3px solid var(--line2);padding:4px 14px;margin:10px 0;color:var(--ink2)}
  .wiki-body table{border-collapse:collapse;margin:10px 0}
  .wiki-body th,.wiki-body td{border:1px solid var(--line);padding:6px 10px;font-size:13px}
  .wiki-body th{background:var(--panel2);font-weight:600}
  .wiki-body hr{border:none;border-top:1px solid var(--line);margin:16px 0}
  .wiki-tree{margin:0 20px}
  .wiki-tree .wp{display:flex;align-items:center;padding:7px 12px;cursor:pointer;border-radius:4px;color:var(--ink);font-size:13.5px;gap:8px}
  .wiki-tree .wp:hover{background:var(--panel2)}
  .wiki-tree .wp .ic{flex:none;opacity:.5}

  .wi-type{display:inline-block;font-size:11px;padding:2px 8px;border-radius:3px;color:#fff;white-space:nowrap;font-weight:600}
  .wi-desc{margin:0 20px 16px;padding:14px 18px;border:1px solid var(--line);border-radius:6px;background:var(--panel);font-size:13px;line-height:1.6;color:var(--ink2);overflow:auto}
  .wi-desc img{max-width:100%}
  .wi-desc b{color:var(--ink)}
  .detail-grid{display:grid;grid-template-columns:160px 1fr;gap:0;margin:0 20px 16px;border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--panel)}
  .detail-grid .dk{padding:9px 14px;font-size:12px;color:var(--ink2);border-bottom:1px solid var(--line);background:var(--panel2)}
  .detail-grid .dv{padding:9px 14px;font-size:13px;color:var(--ink);border-bottom:1px solid var(--line)}


  .filter-wrap{position:relative;display:inline-flex;align-items:center}
  .filter-ic{position:absolute;left:8px;color:var(--muted);pointer-events:none}
  .filter-input{width:200px;height:28px;border:1px solid var(--line2);border-radius:3px;padding:0 28px;font-size:13px;background:var(--bg);color:var(--ink);font-family:var(--sans)}
  .filter-input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 1px var(--cyan),0 0 12px rgba(76,211,227,.2)}
  .filter-input::placeholder{color:var(--muted)}
  .filter-x{position:absolute;right:4px;background:none;border:none;color:var(--muted);cursor:pointer;font-size:16px;padding:2px 4px;line-height:1}
  .filter-x:hover{color:var(--ink)}
  .filter-hint{color:var(--muted);font-size:11px;margin-left:6px}
  .filter-count{color:var(--ink2);font-size:12px;padding:4px 20px}
</style>
</head>
<body>
<div id="app"></div>
<script>
const S = { org:null, project:null, projects:[], scope:{}, verdict:null,
  repos:[], repo:null, branch:"main", branches:[], path:"/", view:"overview", reposTab:"files", filter:"" };

const app = () => document.getElementById("app");
const esc = s => String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const initials = s => (s||"?").split(/[ @.]/).filter(Boolean).slice(0,2).map(x=>x[0]).join("").toUpperCase();
const AVA = ["#0078d4","#d83b01","#498205","#8764b8","#5c2d91","#008272"];
const avaColor = s => AVA[(s||"").split("").reduce((a,c)=>a+c.charCodeAt(0),0)%AVA.length];
const rel = iso => { if(!iso) return ""; const d=(Date.now()-new Date(iso))/86400000;
  if(d<1) return "today"; if(d<2) return "yesterday"; if(d<30) return Math.floor(d)+" days ago";
  if(d<60) return "a month ago"; return Math.floor(d/30)+" months ago"; };

const IC = {
  overview:'<svg viewBox="0 0 16 16" width="16" height="16"><rect x="1" y="1" width="6" height="6" fill="currentColor"/><rect x="9" y="1" width="6" height="6" fill="currentColor"/><rect x="1" y="9" width="6" height="6" fill="currentColor"/><rect x="9" y="9" width="6" height="6" fill="currentColor"/></svg>',
  boards:'<svg viewBox="0 0 16 16" width="16" height="16"><rect x="1" y="2" width="4" height="12" fill="currentColor"/><rect x="6" y="2" width="4" height="8" fill="currentColor"/><rect x="11" y="2" width="4" height="10" fill="currentColor"/></svg>',
  repos:'<svg viewBox="0 0 16 16" width="16" height="16"><circle cx="4" cy="3" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="4" cy="13" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="12" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M4 5 L4 11 M4 8 Q4 5 10 5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>',
  pipelines:'<svg viewBox="0 0 16 16" width="16" height="16"><path d="M8 1 L10 6 L15 6 L11 9 L13 15 L8 11 L3 15 L5 9 L1 6 L6 6 Z" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>',
  testplans:'<svg viewBox="0 0 16 16" width="16" height="16"><rect x="2" y="2" width="12" height="12" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M5 8 L7 10 L11 5" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>',
  artifacts:'<svg viewBox="0 0 16 16" width="16" height="16"><path d="M2 5 L8 2 L14 5 L8 8 Z" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M2 5 L2 11 L8 14 L14 11 L14 5" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>',
  library:'<svg viewBox="0 0 16 16" width="16" height="16"><rect x="2" y="2" width="3" height="12" fill="currentColor"/><rect x="6.5" y="2" width="3" height="12" fill="currentColor"/><path d="M11 3 L14 13 L11.5 13.5 Z" fill="currentColor"/></svg>',
  folder:'<svg viewBox="0 0 18 14" width="16" height="14"><path d="M1 2 L7 2 L9 4 L17 4 L17 13 L1 13 Z" fill="#e0a45c"/></svg>',
  file:'<svg viewBox="0 0 14 16" width="14" height="16"><path d="M2 1 L9 1 L12 4 L12 15 L2 15 Z" fill="none" stroke="#8892a0" stroke-width="1.2"/><path d="M9 1 L9 4 L12 4" fill="none" stroke="#8892a0" stroke-width="1.2"/></svg>',
  branch:'<svg viewBox="0 0 16 16" width="14" height="14"><circle cx="4" cy="4" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="4" cy="12" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="12" cy="4" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M4 6 L4 10 M4 8 Q4 4 10 4" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>',
  lock:'<svg viewBox="0 0 16 16" width="12" height="12"><rect x="3" y="7" width="10" height="7" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M5 7 V5 a3 3 0 0 1 6 0 V7" fill="none" stroke="currentColor" stroke-width="1.3"/></svg>',
  logo:'<svg viewBox="0 0 32 32" width="16" height="16"><g transform="rotate(-25 16 16)"><rect x="1" y="14.2" width="2.5" height="3.6" rx="0.8" fill="#fff"/><rect x="4.5" y="14" width="7.5" height="4" rx="0.8" fill="#fff"/><rect x="13" y="13" width="8" height="6" rx="0.8" fill="#fff"/><rect x="22" y="11.8" width="8" height="8.4" rx="1" fill="#fff"/></g></svg>',
  connections:'<svg viewBox="0 0 16 16" width="16" height="16"><circle cx="5" cy="8" r="2.5" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="11" cy="8" r="2.5" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M7.5 8 L8.5 8" stroke="currentColor" stroke-width="1.3"/></svg>',
  members:'<svg viewBox="0 0 16 16" width="16" height="16"><circle cx="6" cy="5" r="2.5" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M2 14 Q2 10 6 10 Q10 10 10 14" fill="none" stroke="currentColor" stroke-width="1.3"/><circle cx="11" cy="5" r="2" fill="none" stroke="currentColor" stroke-width="1.2"/><path d="M11 9 Q14 9 14 13" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>',
  pr:'<svg viewBox="0 0 16 16" width="16" height="16"><circle cx="4" cy="4" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="4" cy="12" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><circle cx="12" cy="12" r="2" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M4 6 L4 10 M12 6 L12 10" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M12 4 L10 2 M12 4 L14 2" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>',
  wiki:'<svg viewBox="0 0 16 16" width="16" height="16"><path d="M3 2 L13 2 L13 14 L3 14 Z" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M5 5 L11 5 M5 7.5 L11 7.5 M5 10 L9 10" stroke="currentColor" stroke-width="1.1"/></svg>',
};

const NAV = [
  {view:"overview", label:"Overview", ic:"overview", probe:"projects"},
  {view:"artifacts", label:"Artifacts", ic:"artifacts", probe:"feeds"},
  {view:"boards", label:"Boards", ic:"boards", probe:"work_items"},
  {view:"connections", label:"Connections", ic:"connections", probe:"service_endpoints"},
  {view:"directory", label:"Directory", ic:"members", probe:"graph_users"},
  {view:"library", label:"Library", ic:"library", probe:"variable_groups"},
  {view:"pipelines", label:"Pipelines", ic:"pipelines", probe:"pipelines"},
  {view:"repos", label:"Repos", ic:"repos", probe:"repositories"},
  {view:"testplans", label:"Test Plans", ic:"testplans", probe:"test_plans"},
  {view:"wiki", label:"Wiki", ic:"wiki", probe:"wikis"},
];
const reachable = probe => ["confirmed","empty"].includes(S.scope[probe]);

function handleDeepLink(){
  const hash = window.location.hash.replace(/^#\/?/,'');
  if(!hash) return false;
  let parts = hash.split('/').map(decodeURIComponent);
  if(parts[0]==='p' && parts.length>=3){
    const tp=parts[1];
    if(S.projects && S.projects.find(p=>p.name===tp)){
      if(S.project!==tp){ S.project=tp; S.repos=[]; S.repo=null; S.branches=[]; S._wiki=null; }
    }
    parts=parts.slice(2);
  }
  const view = parts[0];
  const valid = new Set(['overview','repos','wiki','pipelines','library','boards','connections','artifacts','testplans','directory']);
  if(!valid.has(view)) return false;
  const nav = NAV.find(n=>n.view===view);
  if(nav && !reachable(nav.probe)) return false;
  S.view = view;
  S._deepLink = parts.slice(1);
  return true;
}

async function api(path){
  const r = await fetch(path);
  const d = await r.json().catch(()=>({error:"Bad response"}));
  if(!r.ok) throw Object.assign(new Error(d.error||"Request failed"), {kind:d.kind});
  return d;
}

/* ---------- landing ---------- */
function renderLanding(errMsg){
  app().innerHTML = `<div class="landing"><div class="card">
    <div class="brand"><span class="logo">${IC.logo}</span><h1>SpyGlass</h1></div>
    <div class="sub">Browse an Azure DevOps organization with a personal access token  - no Entra sign-in. SpyGlass maps what the token can reach, then lets you browse read-only.</div>
    <div class="field"><label>Personal access token</label><input id="tok" type="password" placeholder="paste token" autocomplete="off"></div>
    <div class="field"><label>Organization</label><input id="org" type="text" placeholder="contoso" autocomplete="off"></div>
    <button class="primary" id="go">Connect</button>
    ${errMsg?`<div class="err">${esc(errMsg)}</div>`:""}
    <div class="hint">Read-only. The token stays in memory on this machine and is never written to disk.</div>
  </div></div>`;
  const go = document.getElementById("go");
  const submit = async () => {
    go.disabled = true; go.textContent = "Connecting\u2026";
    try{
      const d = await api2("/api/probe", {token:document.getElementById("tok").value,
        org:document.getElementById("org").value, project:""});
      S.org=d.org; S.project=d.project_used; S.projects=d.projects; S.verdict=d.verdict;
      S.scheme=d.scheme; S.project_source=d.project_source;
      S.scope={}; d.surfaces.forEach(s=>S.scope[s.id]=s.status); S.surfaces=d.surfaces;
      if(d.verdict==="dead"){ renderLanding("No surface accepted this token. It is expired, revoked, or not for this org."); return; }
      if(!handleDeepLink()) S.view = "overview";
      renderShell();
    }catch(ex){ renderLanding(ex.message); }
  };
  go.onclick = submit;
  ["tok","org"].forEach(id=>document.getElementById(id).addEventListener("keydown",e=>{if(e.key==="Enter")submit();}));
}
async function api2(path, body){
  const r = await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const d = await r.json().catch(()=>({error:"Bad response"}));
  if(!r.ok) throw new Error(d.error||"Request failed");
  return d;
}

/* ---------- shell ---------- */
function renderShell(){
  const navHtml = NAV.map(n=>{
    const ok = reachable(n.probe);
    return `<li class="${S.view===n.view?"on":""} ${ok?"":"locked"}" data-view="${ok?n.view:""}" ${ok?"":`title="Token lacks ${esc((S.surfaces.find(s=>s.id===n.probe)||{}).scope||n.probe)}"`}>
      <span class="ic">${IC[n.ic]}</span>${esc(n.label)}${ok?"":`<span class="lock">${IC.lock}</span>`}</li>`;
  }).join("");
  app().innerHTML = `
    <div class="top"><span class="logo">${IC.logo}</span>
      <span class="org">Azure DevOps</span><span class="sep">|</span><span class="org">${esc(S.org)}</span>
      <span class="spacer"></span>
      <span class="filter-wrap"><svg class="filter-ic" viewBox="0 0 16 16" width="14" height="14"><circle cx="6.5" cy="6.5" r="5.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 10.5L14.5 14.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input type="text" id="filterInput" class="filter-input" placeholder="Filter… ( / )" value="${esc(S.filter||"")}"><button class="filter-x" id="filterClear" style="display:${S.filter?"inline":"none"}">&times;</button></span>
      <button class="tbtn" id="scopeBtn">Token scope</button>
      <button class="tbtn" id="signout">Disconnect</button></div>
    <div class="shell">
      <div class="rail">
        <div class="phdr">${S.projects.length>1?`<select id="projSel" class="pn">${S.projects.map(p=>`<option value="${esc(p.name)}" ${p.name===S.project?"selected":""}>${esc(p.name)}</option>`).join("")}</select>`:`<span class="pn">${esc(S.project||"(no project)")}</span>`}</div>
        <ul class="nav">${navHtml}</ul>
      </div>
      <div class="content" id="content"><div class="loading">Loading\u2026</div></div>
    </div>`;
  document.querySelectorAll(".nav li[data-view]").forEach(li=>{
    if(li.dataset.view) li.onclick=()=>{ S.filter=""; S.view=li.dataset.view; renderShell(); };
  });
  document.getElementById("signout").onclick = async ()=>{ await fetch("/api/clear",{method:"POST"}); location.reload(); };
  document.getElementById("scopeBtn").onclick = ()=>{ S.filter=""; S.view="overview"; renderShell(); };
  const projSel = document.getElementById("projSel");
  if(projSel) projSel.onchange = async e=>{
    S.filter=""; S.project=e.target.value; S.repos=[]; S.repo=null; S.branches=[]; S._wiki=null;
    try{
      const d = await api2("/api/reprobe",{project:S.project});
      S.surfaces = S.surfaces.filter(s=>s.tier==="org").concat(d.surfaces);
      S.scope={}; S.surfaces.forEach(s=>S.scope[s.id]=s.status);
    }catch(e){}
    renderShell();
  };
  const fi = document.getElementById("filterInput");
  if(fi){
    fi.oninput = ()=>{ S.filter=fi.value; document.getElementById("filterClear").style.display=S.filter?"inline":"none"; applyFilter(); };
    fi.addEventListener("keydown",e=>{ if(e.key==="Escape"){ S.filter=""; fi.value=""; fi.blur(); document.getElementById("filterClear").style.display="none"; applyFilter(); }});
  }
  document.getElementById("filterClear").onclick = ()=>{ S.filter=""; fi.value=""; fi.focus(); document.getElementById("filterClear").style.display="none"; applyFilter(); };
  renderView();
}

function content(html){ document.getElementById("content").innerHTML = html; if(S.filter) scheduleFilter(); }
function loading(){ document.getElementById("content").innerHTML = '<div class="loading">Loading\u2026</div>'; }
function apiError(ex){
  const m = ex.kind==="denied" ? "The token authenticates, but this scope is not granted."
          : ex.kind==="unauth" ? "The token was not accepted for this resource."
          : ex.message;
  content(`<div class="msgbox">${esc(m)}</div>`);
}

/* ---------- filter ---------- */
let _filterTimer = 0;
function scheduleFilter(){ clearTimeout(_filterTimer); _filterTimer = setTimeout(applyFilter, 0); }
function applyFilter(){
  const q = (S.filter||"").toLowerCase().trim();
  const el = document.getElementById("content");
  if(!el) return;
  if(S.view==="file"||S.view==="wikiPage") return;
  let targets;
  if(S.view==="overview") targets = el.querySelectorAll(".ov-card");
  else if(S.view==="wiki") targets = el.querySelectorAll(".wiki-tree .wp");
  else if(S.view==="library"||S.view==="testplans"||S.view==="artifacts") targets = el.querySelectorAll(".vg");
  else targets = el.querySelectorAll("table.grid tbody tr");
  let shown=0, total=targets.length;
  targets.forEach(t=>{
    const vis = !q || t.textContent.toLowerCase().includes(q);
    t.style.display = vis ? "" : "none";
    if(vis) shown++;
  });
  const old = el.querySelector(".filter-count");
  if(old) old.remove();
  if(q && total>0){
    const d = document.createElement("div");
    d.className="filter-count";
    d.textContent = shown+" of "+total+(shown===1?" match":" matches");
    const first = el.querySelector(".h,.toolbar,.crumbs,.ov,.tabs");
    if(first) first.parentNode.insertBefore(d, first.nextSibling);
    else el.prepend(d);
  }
}
document.addEventListener("keydown",e=>{
  const tag = (document.activeElement||{}).tagName||"";
  if(e.key==="/" && tag!=="INPUT" && tag!=="TEXTAREA" && tag!=="SELECT"){
    e.preventDefault();
    const fi = document.getElementById("filterInput");
    if(fi) fi.focus();
  }
});

/* ---------- views ---------- */
function renderView(){
  if(S.view==="overview") return viewOverview();
  if(S.view==="boards") return viewBoards();
  if(S.view==="repos") return viewRepos();
  if(S.view==="file") return viewFile();
  if(S.view==="wiki") return viewWiki();
  if(S.view==="wikiPage") return viewWikiPage();
  if(S.view==="pipelines") return viewPipelines();
  if(S.view==="testplans") return viewTestPlans();
  if(S.view==="artifacts") return viewArtifacts();
  if(S.view==="library") return viewLibrary();
  if(S.view==="connections") return viewConnections();
  if(S.view==="directory") return viewMembers();
  content(`<div class="empty">This section isn't implemented yet.</div>`);
}

function viewOverview(){
  const probeToView = {};
  NAV.forEach(n=>{ probeToView[n.probe]=n.view; });
  const rows = (S.surfaces||[]).map(s=>{
    const cls = s.status==="confirmed"?"ok":s.status==="empty"?"wn":s.status==="denied"?"dn":"na";
    const txt = {confirmed:"Accessible",empty:"Accessible (empty)",denied:"Denied",
      unauthorized:"No auth",not_found:"Not found",untested:"Untested"}[s.status]||s.status;
    const ok = ["confirmed","empty"].includes(s.status) && probeToView[s.id];
    return `<div class="ov-card${ok?" ov-link":""}" ${ok?`data-nav="${probeToView[s.id]}"`:""}>
      <div class="n">${esc(s.label)}</div><div class="sc">${esc(s.scope)}</div>
      <div class="ft"><span class="pill ${cls}">${txt}</span><span>${s.count!=null?s.count+" items":(s.http?"HTTP "+s.http:"")}</span></div></div>`;
  }).join("");
  content(`<div class="ov"><div class="h" style="padding-left:0">Token scope</div>
    <div class="lead">Capability probe for <b>${esc(S.org)}</b>${S.project?` &middot; <b>${esc(S.project)}</b>`:""} using ${esc(S.scheme||"token")} auth. Locked nav items indicate scopes not granted to this token.</div>
    <div class="ov-grid">${rows}</div></div>`);
  document.querySelectorAll(".ov-card[data-nav]").forEach(c=>c.onclick=()=>{ S.filter=""; S.view=c.dataset.nav; renderShell(); });
}

/* Repos */
async function viewRepos(){
  loading();
  try{
    if(!S.repos.length){ S.repos = await api(`/api/repos?project=${encodeURIComponent(S.project)}`); }
    if(!S.repos.length){ content(`<div class="empty">No repositories in this project.</div>`); return; }
    if(!S.repo || !S.repos.find(r=>r.id===S.repo.id)){ S.repo=S.repos[0]; S.branch=S.repo.defaultBranch||"main"; S.path="/"; S.branches=[]; }
    if(S._deepLink && S._deepLink.length){
      const rn=S._deepLink[0], m=S.repos.find(r=>r.name.toLowerCase()===rn.toLowerCase());
      if(m){ S.repo=m; S.branch=m.defaultBranch||"main"; S.branches=[]; }
      if(S._deepLink.length>1){ S.filePath='/'+S._deepLink.slice(1).join('/'); S._deepLink=null; S.view="file"; setTimeout(()=>renderShell(),0); return; }
      S._deepLink=null;
    }
    if(!S.branches.length){ try{ S.branches=await api(`/api/branches?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}`); }catch(e){ S.branches=[]; } }
    const repoOpts = S.repos.map(r=>`<option value="${r.id}" ${r.id===S.repo.id?"selected":""}>${esc(r.name)}</option>`).join("");
    const branchOpts = S.branches.map(b=>`<option value="${esc(b.name)}" ${b.name===S.branch?"selected":""}>${esc(b.name)}</option>`).join("");
    const TABS=[{id:"files",l:"Files"},{id:"branches",l:"Branches"},{id:"commits",l:"Commits"},{id:"pullrequests",l:"Pull Requests"}];
    const tabs = TABS.map(t=>`<div class="tab ${S.reposTab===t.id?"on":""}" data-tab="${t.id}">${t.l}</div>`).join("");
    content(`
      <div class="toolbar">
        <span class="drop">${IC.repos}<select id="repoSel">${repoOpts}</select></span>
        <span class="drop">${IC.branch}<select id="branchSel">${branchOpts||`<option>${esc(S.branch)}</option>`}</select></span>
        <span class="spacer"></span></div>
      <div class="tabs">${tabs}</div>
      <div id="repoBody"><div class="loading">Loading\u2026</div></div>`);
    document.getElementById("repoSel").onchange = e=>{ S.repo=S.repos.find(r=>r.id===e.target.value); S.branch=S.repo.defaultBranch||"main"; S.path="/"; S.branches=[]; viewRepos(); };
    document.getElementById("branchSel").onchange = e=>{ S.branch=e.target.value; S.path="/"; viewRepos(); };
    document.querySelectorAll(".tab[data-tab]").forEach(t=>t.onclick=()=>{ S.reposTab=t.dataset.tab; viewRepos(); });
    if(S.reposTab==="files") reposFiles();
    else if(S.reposTab==="branches") reposBranches();
    else if(S.reposTab==="pullrequests") reposPullRequests();
    else reposCommits();
  }catch(ex){ apiError(ex); }
}

async function reposFiles(){
  const body = document.getElementById("repoBody");
  try{
    const items = await api(`/api/tree?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}&path=${encodeURIComponent(S.path)}&branch=${encodeURIComponent(S.branch)}`);
    const segs = S.path.split("/").filter(Boolean);
    let crumb = `<a data-p="/">${esc(S.repo.name)}</a>`, acc="";
    segs.forEach(sg=>{ acc+="/"+sg; crumb+=`<span class="s">/</span><a data-p="${esc(acc)}">${esc(sg)}</a>`; });
    const rows = items.map(it=>`<tr>
        <td class="fn">${it.isFolder?IC.folder:IC.file}${it.isFolder?`<a data-folder="${esc(it.path)}">${esc(it.name)}</a>`:`<a data-file="${esc(it.path)}">${esc(it.name)}</a>`}</td>
      </tr>`).join("");
    const readme = items.find(it=>!it.isFolder && /^readme(\.md|\.txt)?$/i.test(it.name));
    body.innerHTML = `<div class="crumbs">${crumb}</div>
      <table class="grid"><thead><tr><td>Name</td></tr></thead><tbody>${rows||'<tr><td class="empty">Empty folder</td></tr>'}</tbody></table>
      <div id="readmeSlot"></div>`;
    body.querySelectorAll("[data-folder]").forEach(a=>a.onclick=()=>{ S.path=a.dataset.folder; reposFiles(); });
    body.querySelectorAll("[data-file]").forEach(a=>a.onclick=()=>{ S.filePath=a.dataset.file; S.view="file"; renderShell(); });
    body.querySelectorAll(".crumbs [data-p]").forEach(a=>a.onclick=()=>{ S.path=a.dataset.p; reposFiles(); });
    if(readme){
      try{
        const f = await api(`/api/file?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}&path=${encodeURIComponent(readme.path)}&branch=${encodeURIComponent(S.branch)}`);
        document.getElementById("readmeSlot").innerHTML = `<div class="readme"><div class="rh">${IC.file} ${esc(readme.name)}</div><div class="rb"><pre>${esc(f.content)}</pre></div></div>`;
      }catch(e){}
    }
  }catch(ex){ body.innerHTML=""; apiErrorInto(body, ex); }
}

async function reposBranches(){
  const body = document.getElementById("repoBody");
  try{
    const b = await api(`/api/branches?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}`);
    body.innerHTML = `<table class="grid"><thead><tr><td>Branch</td><td>Commit</td><td>Creator</td></tr></thead><tbody>${
      b.map(x=>`<tr><td class="fn">${IC.branch}<span>${esc(x.name)}</span></td><td class="msg" style="font-family:var(--mono);font-size:12.5px">${esc(x.objectId)}</td><td class="msg">${esc(x.creator)}</td></tr>`).join("")||'<tr><td class="empty">No branches</td></tr>'}</tbody></table>`;
  }catch(ex){ body.innerHTML=""; apiErrorInto(body, ex); }
}

async function reposCommits(){
  const body = document.getElementById("repoBody");
  try{
    const c = await api(`/api/commits?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}&branch=${encodeURIComponent(S.branch)}`);
    body.innerHTML = `<table class="grid"><thead><tr><td>Commit</td><td>Message</td><td style="text-align:right">When</td></tr></thead><tbody>${
      c.map(x=>`<tr><td><span class="cm" style="background:${avaColor(x.author)}">${esc(initials(x.author))}</span><span style="font-family:var(--mono);font-size:12.5px">${esc(x.commitId)}</span></td><td class="msg">${esc(x.comment)}</td><td class="when">${esc(rel(x.date))}</td></tr>`).join("")||'<tr><td class="empty">No commits</td></tr>'}</tbody></table>`;
  }catch(ex){ body.innerHTML=""; apiErrorInto(body, ex); }
}

async function viewFile(){
  loading();
  try{
    const f = await api(`/api/file?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}&path=${encodeURIComponent(S.filePath)}&branch=${encodeURIComponent(S.branch)}`);
    const name = S.filePath.split("/").pop();
    const bin = isBinary(f.content);
    content(`<div class="crumbs"><a id="back">${esc(S.repo.name)}</a><span class="s">/</span>${esc(S.filePath.replace(/^\//,""))}</div>
      <div class="h" style="padding-top:4px;display:flex;align-items:center;gap:12px">
        <span>${esc(name)} <span class="path">on ${esc(S.branch)} &middot; ${f.size} bytes</span></span>
      </div>
      <div id="fileContent">${bin?'<div class="msgbox">Binary file - content not shown.</div>':codeBlock(f.content)}</div>`);
    document.getElementById("back").onclick=()=>{ S.view="repos"; S.reposTab="files"; renderShell(); };
  }catch(ex){ apiError(ex); }
}

function isBinary(text){
  if(!text) return false;
  const s=text.slice(0,8192); let n=0;
  for(let i=0;i<s.length;i++){const c=s.charCodeAt(i);if(c===0||(c<32&&c!==9&&c!==10&&c!==13))n++;}
  return n/s.length>0.1;
}
function codeBlock(text){
  const lines = (text||"").replace(/\n$/,"").split("\n");
  const gutter = lines.map((_,i)=>i+1).join("\n");
  return `<div class="code"><div class="gutter">${esc(gutter)}</div><div class="src">${esc(text||"")}</div></div>`;
}

/* Wiki */
function miniMd(src){
  if(!src) return '<div class="empty">This page has no content.</div>';
  let h = esc(src);
  h = h.replace(/^### (.+)$/gm,'<h3>$1</h3>');
  h = h.replace(/^## (.+)$/gm,'<h2>$1</h2>');
  h = h.replace(/^# (.+)$/gm,'<h1>$1</h1>');
  h = h.replace(/^---$/gm,'<hr>');
  h = h.replace(/^&gt; (.+)$/gm,'<blockquote>$1</blockquote>');
  h = h.replace(/`([^`]+)`/g,'<code>$1</code>');
  h = h.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');
  h = h.replace(/\*([^*]+)\*/g,'<em>$1</em>');
  h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2" target="_blank">$1</a>');
  h = h.replace(/^[-*] (.+)$/gm,'<li>$1</li>');
  h = h.replace(/((?:<li>.*<\/li>\n?)+)/g,'<ul>$1</ul>');
  h = h.replace(/^\d+\. (.+)$/gm,'<li>$1</li>');
  const blocks = h.split(/```(\w*)\n?/);
  if(blocks.length>1){
    let out=''; for(let i=0;i<blocks.length;i++){
      if(i%2===0) out+=blocks[i]; else out+='<pre><code>'+blocks[i]+'</code></pre>';
    } h=out;
  }
  h = h.replace(/\n{2,}/g,'</p><p>');
  h = '<p>'+h+'</p>';
  h = h.replace(/<p>\s*(<h[123]>)/g,'$1').replace(/(<\/h[123]>)\s*<\/p>/g,'$1');
  h = h.replace(/<p>\s*(<hr>)\s*<\/p>/g,'$1');
  h = h.replace(/<p>\s*(<ul>)/g,'$1').replace(/(<\/ul>)\s*<\/p>/g,'$1');
  h = h.replace(/<p>\s*(<pre>)/g,'$1').replace(/(<\/pre>)\s*<\/p>/g,'$1');
  h = h.replace(/<p>\s*(<blockquote>)/g,'$1').replace(/(<\/blockquote>)\s*<\/p>/g,'$1');
  h = h.replace(/<p>\s*<\/p>/g,'');
  return h;
}

async function viewWiki(){
  loading();
  try{
    const ws = await api(`/api/wikis?project=${encodeURIComponent(S.project)}`);
    if(!ws.length){ content(`<div class="empty">No wikis in this project.</div>`); return; }
    if(!S._wiki || !ws.find(w=>w.id===S._wiki.id)) S._wiki=ws[0];
    if(S._deepLink && S._deepLink[0]){
      const target = S._deepLink[0];
      const pageParts = S._deepLink.slice(1);
      S._deepLink=null;
      const m = ws.find(w=>w.name.toLowerCase()===target.toLowerCase() || String(w.id)===target);
      if(m) S._wiki=m;
      if(pageParts.length){
        let pp = pageParts.join("/");
        if(pp.endsWith(".md")) pp=pp.slice(0,-3);
        S._wikiPath="/"+pp;
        S.view="wikiPage"; renderShell(); return;
      }
    }
    const pages = await api(`/api/wiki/pages?project=${encodeURIComponent(S.project)}&wiki=${encodeURIComponent(S._wiki.id)}`);
    const wikiOpts = ws.length>1 ? ws.map(w=>`<option value="${esc(w.id)}" ${w.id===S._wiki.id?"selected":""}>${esc(w.name)}</option>`).join("") : "";
    const typeLabel = S._wiki.type==="projectWiki" ? "Project wiki" : S._wiki.type==="codeWiki" ? "Code wiki" : (S._wiki.type||"Wiki");
    content(`<div class="h" style="padding-left:20px;display:flex;align-items:center;gap:12px">${IC.wiki}${
      ws.length>1?`<select id="wikiSel" style="font-size:16px;font-weight:600;background:transparent;border:none;color:var(--ink);cursor:pointer">${wikiOpts}</select>`
      :`<span>${esc(S._wiki.name)}</span>`}
      <span style="font-size:12px;color:var(--muted)">${esc(typeLabel)}</span></div>
      <div class="wiki-tree">${pages.map(p=>{
        const name = p.path==="/"?"Home":p.path.split("/").pop().replace(/-/g," ");
        const pad = (p.depth||0)*20;
        return `<div class="wp" data-wp="${esc(p.path)}" style="padding-left:${14+pad}px">${p.depth>0?IC.file:IC.wiki} <span>${esc(name)}</span></div>`;
      }).join("")}</div>`);
    document.querySelectorAll("[data-wp]").forEach(el=>el.onclick=()=>{
      S._wikiPath=el.dataset.wp; S.view="wikiPage"; renderShell();
    });
    if(ws.length>1){
      const sel=document.getElementById("wikiSel");
      if(sel) sel.onchange=e=>{ S._wiki=ws.find(w=>w.id===e.target.value)||ws[0]; S.view="wiki"; renderShell(); };
    }
  }catch(ex){ apiError(ex); }
}

async function viewWikiPage(){
  loading();
  try{
    const wikiId = S._wiki ? S._wiki.id : "";
    const wikiName = S._wiki ? S._wiki.name : "Wiki";
    const pagePath = S._wikiPath||"/";
    const pg = await api(`/api/wiki/page?project=${encodeURIComponent(S.project)}&wiki=${encodeURIComponent(wikiId)}&path=${encodeURIComponent(pagePath)}`);
    const name = pagePath==="/"?"Home":pagePath.split("/").pop().replace(/-/g," ");
    const crumbParts = pagePath.split("/").filter(Boolean);
    let crumbHtml = `<a id="wb">${esc(wikiName)}</a>`;
    for(let i=0;i<crumbParts.length;i++){
      const label = crumbParts[i].replace(/-/g," ");
      if(i<crumbParts.length-1){
        const partial = "/"+crumbParts.slice(0,i+1).join("/");
        crumbHtml += `<span class="s">/</span><a class="wbc" data-wp="${esc(partial)}">${esc(label)}</a>`;
      } else {
        crumbHtml += `<span class="s">/</span>${esc(label)}`;
      }
    }
    content(`<div class="crumbs">${crumbHtml}</div>
      <div class="h" style="padding-top:4px">${esc(name)}</div>
      <div class="wiki-body">${miniMd(pg.content)}</div>`);
    document.getElementById("wb").onclick=()=>{ S.view="wiki"; renderShell(); };
    document.querySelectorAll(".wbc").forEach(a=>a.onclick=()=>{
      S._wikiPath=a.dataset.wp; S.view="wikiPage"; renderShell();
    });
  }catch(ex){ apiError(ex); }
}

/* Pipelines */
async function viewPipelines(){
  loading();
  try{
    const ps = await api(`/api/pipelines?project=${encodeURIComponent(S.project)}`);
    if(!ps.length){ content(`<div class="empty">No pipelines in this project.</div>`); return; }
    content(`<div class="h" style="padding-left:20px">Pipelines</div>
      <table class="grid"><thead><tr><td>Name</td><td>Folder</td></tr></thead><tbody>${
        ps.map(p=>`<tr><td class="fn">${IC.pipelines}<a data-pid="${p.id}">${esc(p.name)}</a></td><td class="msg">${esc(p.folder||"\\")}</td></tr>`).join("")}</tbody></table>`);
    document.querySelectorAll("[data-pid]").forEach(a=>a.onclick=()=>pipelineDetail(a.dataset.pid));
    if(S._deepLink && S._deepLink[0]){ const pid=S._deepLink[0]; S._deepLink=null; pipelineDetail(pid); return; }
  }catch(ex){ apiError(ex); }
}

async function pipelineDetail(pid){
  loading();
  try{
    const [p, runs] = await Promise.all([
      api(`/api/pipeline?project=${encodeURIComponent(S.project)}&id=${pid}`),
      api(`/api/runs?project=${encodeURIComponent(S.project)}&pipeline=${pid}`).catch(()=>[])
    ]);
    const runColor = r => r.result==='succeeded'?'ok':r.result==='failed'?'dn':r.state==='inProgress'?'wn':'na';
    const runLabel = r => r.result||r.state||'queued';
    content(`<div class="crumbs"><a id="pb">Pipelines</a><span class="s">/</span>${esc(p.name)}</div>
      <div class="h" style="padding-top:4px;display:flex;align-items:center;gap:12px">
        <span>${esc(p.name)} <span class="path">${esc(p.type)}${p.path?" &middot; "+esc(p.path):""}</span></span>
        <span style="flex:1"></span>
      </div>
      ${runs.length?`<div class="h" style="font-size:16px;padding-top:8px">Recent Runs</div>
        <table class="grid"><thead><tr><td>Run</td><td>Result</td><td style="text-align:right">Started</td><td style="text-align:right">Finished</td></tr></thead><tbody>${
          runs.map(r=>`<tr><td>#${esc(r.id)}</td><td><span class="pill ${runColor(r)}">${esc(runLabel(r))}</span></td>
            <td class="when">${esc(rel(r.createdDate))}</td><td class="when">${esc(rel(r.finishedDate))}</td></tr>`).join("")}</tbody></table>`:''}
      ${p.yaml!=null ? codeBlock(p.yaml) : `<div class="msgbox">${p.type==="yaml"?"YAML defined in the repo but not readable with this token.":"Classic pipeline  - no YAML definition."}</div>`}`);
    document.getElementById("pb").onclick=()=>{ S.view="pipelines"; renderShell(); };
  }catch(ex){ apiError(ex); }
}

/* Library (variable groups) */
async function viewLibrary(){
  loading();
  try{
    const gs = await api(`/api/variablegroups?project=${encodeURIComponent(S.project)}`);
    if(!gs.length){ content(`<div class="empty">No variable groups in this project.</div>`); return; }
    let expandIdx = 0;
    if(S._deepLink && S._deepLink[0]){
      const target = S._deepLink[0]; S._deepLink = null;
      const idx = gs.findIndex(g => String(g.id)===target || g.name.toLowerCase()===target.toLowerCase());
      if(idx >= 0) expandIdx = idx;
    }
    content(`<div class="h" style="padding-left:20px">Library <span class="path">variable groups</span></div>` +
      gs.map((g,i)=>{
        const vars = g.variables.map(v=>`<tr><td class="k">${esc(v.name)}</td><td class="v">${v.isSecret?'<span class="secret">secret \u2014 not returned by the API</span>':esc(v.value||"")}</td></tr>`).join("");
        const typ = g.type==="AzureKeyVault" ? `Key Vault: ${esc(g.vault)}` : "Pipeline variables";
        return `<div class="vg"><div class="vh" data-g="${i}">${IC.library}<span class="nm">${esc(g.name)}</span>
          <span class="ty">${typ} &middot; ${g.variables.length} vars</span>
          </div>
          <table id="vg${i}" style="display:${i===expandIdx?"table":"none"}"><tbody>${vars||'<tr><td class="empty">No variables</td></tr>'}</tbody></table></div>`;
      }).join(""));
    document.querySelectorAll(".vh[data-g]").forEach(h=>h.onclick=()=>{
      const t=document.getElementById("vg"+h.dataset.g); t.style.display = t.style.display==="none"?"table":"none";
    });
    if(expandIdx > 0){ const el=document.getElementById("vg"+expandIdx); if(el) el.scrollIntoView({behavior:"smooth",block:"center"}); }
  }catch(ex){ apiError(ex); }
}

function apiErrorInto(el, ex){
  const m = ex.kind==="denied" ? "The token authenticates, but this scope is not granted."
          : ex.kind==="unauth" ? "The token was not accepted for this resource." : ex.message;
  el.innerHTML = `<div class="msgbox">${esc(m)}</div>`;
}

/* ---------- Boards (work items) ---------- */
const WI_COLOR = t => ({Bug:'#ff5c57',Task:'#e0a45c','User Story':'#4cd3e3',Feature:'#3fb950',Epic:'#8764b8','Issue':'#ff5c57'}[t]||'#5c6675');
async function viewBoards(){
  loading();
  try{
    const items = await api(`/api/workitems?project=${encodeURIComponent(S.project)}`);
    if(!items.length){ content(`<div class="empty">No work items found.</div>`); return; }
    content(`<div class="h" style="padding-left:20px;display:flex;align-items:center;gap:12px">Work Items</div>
      <table class="grid"><thead><tr><td>ID</td><td>Type</td><td>Title</td><td>State</td><td>Assigned To</td><td style="text-align:right">Changed</td></tr></thead><tbody>${
        items.map(i=>`<tr>
          <td><a data-wi="${i.id}">${i.id}</a></td>
          <td><span class="wi-type" style="background:${WI_COLOR(i.type)}">${esc(i.type)}</span></td>
          <td><a data-wi="${i.id}">${esc(i.title)}</a></td>
          <td><span class="pill ${/^(Closed|Done|Resolved)$/.test(i.state)?'ok':/^(Active|Committed|In Progress)$/.test(i.state)?'wn':'na'}">${esc(i.state)}</span></td>
          <td class="msg">${i.assignedTo?`<span class="cm" style="background:${avaColor(i.assignedTo)}">${esc(initials(i.assignedTo))}</span>${esc(i.assignedTo)}`:''}</td>
          <td class="when">${esc(rel(i.changedDate))}</td>
        </tr>`).join("")}</tbody></table>`);
    document.querySelectorAll("[data-wi]").forEach(a=>a.onclick=()=>viewWorkItem(a.dataset.wi));
    if(S._deepLink && S._deepLink[0]){ const wid=S._deepLink[0]; S._deepLink=null; viewWorkItem(wid); return; }
  }catch(ex){ apiError(ex); }
}

async function viewWorkItem(id){
  loading();
  try{
    const wi = await api(`/api/workitem?project=${encodeURIComponent(S.project)}&id=${id}`);
    const f = wi.fields||{};
    const type = f['System.WorkItemType']||'';
    const title = f['System.Title']||'';
    const desc = f['System.Description']||f['Microsoft.VSTS.TCM.ReproSteps']||'';
    const accept = f['Microsoft.VSTS.Common.AcceptanceCriteria']||'';
    const important = ['System.WorkItemType','System.State','System.Reason','System.AssignedTo',
      'System.AreaPath','System.IterationPath','System.Tags',
      'Microsoft.VSTS.Common.Priority','Microsoft.VSTS.Common.Severity',
      'Microsoft.VSTS.Scheduling.Effort','Microsoft.VSTS.Scheduling.StoryPoints',
      'System.CreatedBy','System.CreatedDate','System.ChangedBy','System.ChangedDate'];
    const skip = new Set(['System.Title','System.Description','Microsoft.VSTS.TCM.ReproSteps',
      'Microsoft.VSTS.Common.AcceptanceCriteria','System.CommentCount','System.Watermark',
      'System.Rev','System.AuthorizedDate','System.RevisedDate','System.Id']);
    const shown = important.filter(k=>f[k]!=null&&f[k]!=='');
    const rest = Object.keys(f).filter(k=>!skip.has(k)&&!important.includes(k)&&f[k]!=null&&f[k]!=='');
    const fLabel = k => k.replace(/^(System|Microsoft\.VSTS\.\w+)\./,'');
    const fRow = k => `<div class="dk">${esc(fLabel(k))}</div><div class="dv">${esc(String(f[k]))}</div>`;
    content(`<div class="crumbs"><a id="wiback">Work Items</a><span class="s">/</span>${esc(id)}</div>
      <div class="h" style="padding-top:4px;display:flex;align-items:center;gap:12px">
        <span><span class="wi-type" style="background:${WI_COLOR(type)}">${esc(type)}</span> #${esc(id)}  - ${esc(title)}</span>
        <span style="flex:1"></span>
      </div>
      ${desc?`<div class="wi-desc">${desc}</div>`:''}
      ${accept?`<div class="wi-desc"><b>Acceptance Criteria</b><br>${accept}</div>`:''}
      <div class="detail-grid">${shown.map(fRow).join("")}${rest.map(fRow).join("")}</div>
      ${(wi.relations||[]).length?`<div class="vg"><div class="vh"><span class="nm">Relations (${wi.relations.length})</span></div>
        <table><tbody>${wi.relations.map(r=>`<tr><td class="k">${esc(r.name||r.rel)}</td><td class="v" style="word-break:break-all">${esc(r.url)}</td></tr>`).join("")}</tbody></table></div>`:''}`);
    document.getElementById("wiback").onclick=()=>{ S.view="boards"; renderShell(); };
  }catch(ex){ apiError(ex); }
}

/* ---------- Pull Requests (repos tab) ---------- */
async function reposPullRequests(){
  const body = document.getElementById("repoBody");
  try{
    const prs = await api(`/api/pullrequests?project=${encodeURIComponent(S.project)}&repo=${S.repo.id}`);
    const statusColor = s => s==='active'?'wn':s==='completed'?'ok':s==='abandoned'?'dn':'na';
    const voteIcon = v => v===10?'✅':v===5?'✅':v===-5?'⏳':v===-10?'❌':'';
    body.innerHTML = (prs.length ? `<table class="grid"><thead><tr><td>ID</td><td>Title</td><td>Author</td><td>Source → Target</td><td>Reviewers</td><td>Status</td></tr></thead><tbody>${
      prs.map(pr=>`<tr>
        <td>!${pr.id}</td>
        <td>${esc(pr.title)}</td>
        <td class="msg"><span class="cm" style="background:${avaColor(pr.createdBy)}">${esc(initials(pr.createdBy))}</span>${esc(pr.createdBy)}</td>
        <td class="msg" style="font-family:var(--mono);font-size:12px">${esc(pr.sourceBranch)} → ${esc(pr.targetBranch)}</td>
        <td class="msg">${(pr.reviewers||[]).map(r=>`<span title="${esc(r.name)}: vote ${r.vote}">${voteIcon(r.vote)}${esc(initials(r.name))}</span>`).join(' ')||'-'}</td>
        <td><span class="pill ${statusColor(pr.status)}">${esc(pr.status)}</span></td>
      </tr>`).join("")}</tbody></table>`
      : '<div class="empty">No pull requests</div>');
  }catch(ex){ body.innerHTML=""; apiErrorInto(body, ex); }
}

/* ---------- Test Plans ---------- */
async function viewTestPlans(){
  loading();
  try{
    const plans = await api(`/api/testplans?project=${encodeURIComponent(S.project)}`);
    if(!plans.length){ content(`<div class="empty">No test plans in this project.</div>`); return; }
    content(`<div class="h" style="padding-left:20px">Test Plans</div>` +
      plans.map((p,i)=>`<div class="vg"><div class="vh" data-tp="${i}">${IC.testplans}
        <span class="nm">${esc(p.name)}</span>
        <span class="ty">${esc(p.state||'Active')} &middot; ${esc(p.owner||'Unassigned')}${p.startDate?' &middot; '+esc(p.startDate.slice(0,10)):''}</span></div>
        <div id="tp${i}" style="display:none" data-tpid="${p.id}"><div class="loading" style="padding:12px 16px">Click to load suites…</div></div></div>`).join(""));
    document.querySelectorAll(".vh[data-tp]").forEach(h=>h.onclick=()=>{
      const d=document.getElementById("tp"+h.dataset.tp);
      d.style.display=d.style.display==="none"?"block":"none";
      if(d.dataset.loaded) return;
      d.dataset.loaded="1";
      loadTestSuites(d.dataset.tpid, d);
    });
  }catch(ex){ apiError(ex); }
}

async function loadTestSuites(planId, container){
  container.innerHTML='<div class="loading" style="padding:12px 16px">Loading suites…</div>';
  try{
    const suites = await api(`/api/testsuites?project=${encodeURIComponent(S.project)}&plan=${planId}`);
    if(!suites.length){ container.innerHTML='<div class="empty">No test suites</div>'; return; }
    container.innerHTML = `<table class="grid"><thead><tr><td>Suite</td><td>Type</td><td>Test Cases</td><td></td></tr></thead><tbody>${
      suites.map(s=>`<tr>
        <td>${esc(s.name)}</td>
        <td><span class="pill na">${esc(s.suiteType)}</span></td>
        <td>${s.testCaseCount}</td>
        <td>${s.testCaseCount>0?`<a class="tc-link" data-plan="${planId}" data-suite="${s.id}">View cases</a>`:''}</td>
      </tr>`).join("")}</tbody></table><div class="tc-slot"></div>`;
    container.querySelectorAll(".tc-link").forEach(a=>a.onclick=()=>loadTestCases(planId, a.dataset.suite, container.querySelector(".tc-slot")));
  }catch(ex){ container.innerHTML=`<div class="msgbox" style="margin:12px 16px">${esc(ex.message)}</div>`; }
}

async function loadTestCases(planId, suiteId, slot){
  slot.innerHTML='<div class="loading" style="padding:12px 16px">Loading test cases…</div>';
  try{
    const cases = await api(`/api/testcases?project=${encodeURIComponent(S.project)}&plan=${planId}&suite=${suiteId}`);
    if(!cases.length){ slot.innerHTML='<div class="empty">No test cases in this suite</div>'; return; }
    slot.innerHTML = `<div style="margin:12px 16px;border:1px solid var(--line);border-radius:6px;overflow:hidden">
      <table class="grid"><thead><tr><td>ID</td><td>Test Case</td></tr></thead><tbody>${
        cases.map(c=>`<tr><td>${c.id||''}</td><td>${esc(c.name)}</td></tr>`).join("")}</tbody></table></div>`;
  }catch(ex){ slot.innerHTML=`<div class="msgbox" style="margin:12px 16px">${esc(ex.message)}</div>`; }
}

/* ---------- Artifacts (feeds & packages) ---------- */
async function viewArtifacts(){
  loading();
  try{
    const feeds = await api(`/api/feeds`);
    if(!feeds.length){ content(`<div class="empty">No artifact feeds found.</div>`); return; }
    let expandIdx = -1;
    if(S._deepLink && S._deepLink[0]){
      const target = S._deepLink[0]; S._deepLink = null;
      const idx = feeds.findIndex(f => f.id===target || f.name.toLowerCase()===target.toLowerCase());
      if(idx >= 0) expandIdx = idx;
    }
    content(`<div class="h" style="padding-left:20px">Artifacts <span class="path">feeds</span></div>` +
      feeds.map((f,i)=>`<div class="vg"><div class="vh" data-fd="${i}">${IC.artifacts}
        <span class="nm">${esc(f.name)}</span>
        <span class="ty">${f.project?esc(f.project)+' &middot; ':''}${f.upstreamEnabled?'Upstream enabled':'Local only'}</span></div>
        <div id="fd${i}" style="display:${i===expandIdx?"block":"none"}" data-fdid="${f.id}"><div class="loading" style="padding:12px 16px">Click to load packages…</div></div></div>`).join(""));
    document.querySelectorAll(".vh[data-fd]").forEach(h=>h.onclick=()=>{
      const d=document.getElementById("fd"+h.dataset.fd);
      d.style.display=d.style.display==="none"?"block":"none";
      if(d.dataset.loaded) return;
      d.dataset.loaded="1";
      loadPackages(d.dataset.fdid, d);
    });
    if(expandIdx >= 0){ const d=document.getElementById("fd"+expandIdx); if(d){d.dataset.loaded="1"; loadPackages(d.dataset.fdid,d); d.scrollIntoView({behavior:"smooth",block:"center"});} }
  }catch(ex){ apiError(ex); }
}

async function loadPackages(feedId, container){
  container.innerHTML='<div class="loading" style="padding:12px 16px">Loading packages…</div>';
  try{
    const pkgs = await api(`/api/packages?feed=${encodeURIComponent(feedId)}`);
    if(!pkgs.length){ container.innerHTML='<div class="empty" style="padding:12px 16px">No packages</div>'; return; }
    container.innerHTML = `<table class="grid"><thead><tr><td>Package</td><td>Type</td><td>Latest Version</td></tr></thead><tbody>${
      pkgs.map(p=>`<tr>
        <td>${esc(p.name)}</td>
        <td><span class="pill na">${esc(p.protocolType)}</span></td>
        <td style="font-family:var(--mono);font-size:12.5px">${esc(p.version||'-')}</td>
      </tr>`).join("")}</tbody></table>`;
  }catch(ex){ container.innerHTML=`<div class="msgbox" style="margin:12px 16px">${esc(ex.message)}</div>`; }
}

/* ---------- Service Connections ---------- */
async function viewConnections(){
  loading();
  try{
    const eps = await api(`/api/serviceendpoints?project=${encodeURIComponent(S.project)}`);
    if(!eps.length){ content(`<div class="empty">No service connections in this project.</div>`); return; }
    let highlightId = null;
    if(S._deepLink && S._deepLink[0]){
      const target = S._deepLink[0]; S._deepLink = null;
      const m = eps.find(e => e.id===target || e.name.toLowerCase()===target.toLowerCase());
      if(m) highlightId = m.id;
    }
    content(`<div class="h" style="padding-left:20px">Service Connections</div>
      <table class="grid"><thead><tr><td>Name</td><td>Type</td><td>URL</td><td>Auth Scheme</td><td>Status</td></tr></thead><tbody>${
        eps.map(e=>`<tr${e.id===highlightId?' class="hl" id="hl-conn"':''}>
          <td>${esc(e.name)}</td>
          <td><span class="pill na">${esc(e.type)}</span></td>
          <td class="msg" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.url||'-')}</td>
          <td class="msg">${esc(e.scheme||'-')}</td>
          <td><span class="pill ${e.isReady?'ok':'dn'}">${e.isReady?'Ready':'Not Ready'}</span></td>
        </tr>`).join("")}</tbody></table>`);
    if(highlightId){ const el=document.getElementById("hl-conn"); if(el) el.scrollIntoView({behavior:"smooth",block:"center"}); }
  }catch(ex){ apiError(ex); }
}

/* ---------- Organization Members ---------- */
async function viewMembers(){
  loading();
  try{
    const ms = await api(`/api/members`);
    if(!ms.length){ content(`<div class="empty">No users found or access denied.</div>`); return; }
    content(`<div class="h" style="padding-left:20px">Directory <span class="path">${ms.length} users</span></div>
      <table class="grid"><thead><tr><td>Name</td><td>Email</td><td>Origin</td></tr></thead><tbody>${
        ms.map(m=>`<tr>
          <td class="fn"><span class="cm" style="background:${avaColor(m.displayName)}">${esc(initials(m.displayName))}</span>${esc(m.displayName)}</td>
          <td class="msg">${esc(m.mailAddress||'-')}</td>
          <td><span class="pill na">${esc(m.origin||'-')}</span></td>
        </tr>`).join("")}</tbody></table>`);
  }catch(ex){ apiError(ex); }
}

function applyProbe(d){
  S.org=d.org; S.project=d.project_used; S.projects=d.projects||[];
  S.verdict=d.verdict; S.scheme=d.scheme; S.project_source=d.project_source;
  S.scope={}; (d.surfaces||[]).forEach(s=>S.scope[s.id]=s.status); S.surfaces=d.surfaces||[];
}
async function autoConnect(){
  const params = new URLSearchParams(window.location.search);
  const t=params.get("_t"), o=params.get("_o"), p=params.get("_p");
  if(t&&o){
    window.history.replaceState(null,"",window.location.pathname+window.location.hash);
    try{
      const d = await api2("/api/probe",{token:t,org:o,project:p||""});
      if(d.verdict!=="dead"){ applyProbe(d); return true; }
    }catch(e){}
  }
  try{
    const d = await api2("/api/preauth",{});
    if(d.preauth&&d.verdict&&d.verdict!=="dead"){ applyProbe(d); return true; }
  }catch(e){}
  return false;
}
(async()=>{
  if(await autoConnect()){
    if(!handleDeepLink()) S.view = "overview";
    renderShell();
  }else{
    renderLanding();
  }
})();
window.addEventListener('hashchange', function(){
  if(S.verdict && S.verdict !== 'dead'){
    if(handleDeepLink()){
      renderShell();
    }
  }
});
</script>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.environ.get("SPYGLASS_PORT", "5057"))
    print("SpyGlass on http://127.0.0.1:%d  (local only, token in memory, read-only)" % port)
    app.run(host="127.0.0.1", port=port, debug=False)

"""Azure DevOps variable loader — fetches pipeline variables for scanning.

Covers three variable surfaces:
  1. YAML / build pipeline definitions (build/definitions API)
  2. Variable groups (distributedtask/variablegroups API)
  3. Classic release pipeline definitions (vsrm release/definitions API)

All calls are read-only. Secret-marked variables are skipped (ADO returns
null for their values anyway).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AdoVariable:
    """A single variable extracted from an ADO pipeline or group."""

    name: str
    value: str
    project: str
    source_type: str  # "build_pipeline", "release_pipeline", "variable_group"
    source_name: str
    source_id: int = 0


@dataclass
class AdoScanResult:
    """All variables fetched from an ADO organization."""

    variables: list[AdoVariable] = field(default_factory=list)
    projects_scanned: int = 0
    pipelines_scanned: int = 0
    groups_scanned: int = 0
    release_definitions_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def to_var_dicts(self) -> list[dict[str, str]]:
        """Convert to the format expected by scan_variables()."""
        return [
            {
                "name": v.name,
                "value": v.value,
                "project": v.project,
                "resource": f"{v.project}/{v.source_name}",
                "source_pipeline": v.source_name if v.source_type != "variable_group" else "",
                "source_group": v.source_name if v.source_type == "variable_group" else "",
            }
            for v in self.variables
        ]


class AdoVariableLoader:
    """Fetches pipeline variables from Azure DevOps REST APIs (read-only)."""

    def __init__(self, org: str, pat: str, *, timeout: float = 30.0) -> None:
        self.org = org
        self._client = httpx.Client(
            base_url=f"https://dev.azure.com/{org}",
            auth=("", pat),
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        self._vsrm_client = httpx.Client(
            base_url=f"https://vsrm.dev.azure.com/{org}",
            auth=("", pat),
            timeout=timeout,
            headers={"Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()
        self._vsrm_client.close()

    def __enter__(self) -> AdoVariableLoader:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Project discovery
    # ------------------------------------------------------------------

    def list_projects(self) -> list[dict[str, Any]]:
        """List all projects in the organization."""
        try:
            resp = self._client.get(
                "/_apis/projects",
                params={"api-version": "7.1", "$top": "500"},
            )
            resp.raise_for_status()
            return resp.json().get("value", [])
        except httpx.HTTPError as exc:
            logger.warning("Failed to list projects: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Build / YAML pipeline definitions
    # ------------------------------------------------------------------

    def list_build_definitions(self, project: str) -> list[dict[str, Any]]:
        """List build definitions (YAML + classic build) in a project."""
        try:
            resp = self._client.get(
                f"/{project}/_apis/build/definitions",
                params={"api-version": "7.1", "$top": "500"},
            )
            resp.raise_for_status()
            return resp.json().get("value", [])
        except httpx.HTTPError as exc:
            logger.warning("Failed to list build definitions for %s: %s", project, exc)
            return []

    def get_build_definition(self, project: str, definition_id: int) -> dict[str, Any]:
        """Fetch a full build definition including variables."""
        resp = self._client.get(
            f"/{project}/_apis/build/definitions/{definition_id}",
            params={"api-version": "7.1"},
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_build_pipeline_variables(
        self, project: str, definition_id: int, definition_name: str = "",
    ) -> list[AdoVariable]:
        """Fetch all non-secret variables from a build pipeline definition."""
        try:
            defn = self.get_build_definition(project, definition_id)
        except httpx.HTTPError as exc:
            logger.debug("Could not fetch build definition %s/%s: %s", project, definition_id, exc)
            return []

        name = definition_name or defn.get("name", str(definition_id))
        variables = defn.get("variables", {})
        return self._extract_variables(variables, project, "build_pipeline", name, definition_id)

    # ------------------------------------------------------------------
    # Variable groups
    # ------------------------------------------------------------------

    def list_variable_groups(self, project: str) -> list[dict[str, Any]]:
        """List all variable groups in a project."""
        try:
            resp = self._client.get(
                f"/{project}/_apis/distributedtask/variablegroups",
                params={"api-version": "7.1"},
            )
            resp.raise_for_status()
            return resp.json().get("value", [])
        except httpx.HTTPError as exc:
            logger.warning("Failed to list variable groups for %s: %s", project, exc)
            return []

    def get_variable_group(self, project: str, group_id: int) -> dict[str, Any]:
        """Fetch a full variable group including variables."""
        resp = self._client.get(
            f"/{project}/_apis/distributedtask/variablegroups/{group_id}",
            params={"api-version": "7.1"},
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_variable_group_variables(
        self, project: str, group_id: int, group_name: str = "",
    ) -> list[AdoVariable]:
        """Fetch all non-secret variables from a variable group."""
        try:
            group = self.get_variable_group(project, group_id)
        except httpx.HTTPError as exc:
            logger.debug("Could not fetch variable group %s/%s: %s", project, group_id, exc)
            return []

        name = group_name or group.get("name", str(group_id))
        variables = group.get("variables", {})
        return self._extract_variables(variables, project, "variable_group", name, group_id)

    # ------------------------------------------------------------------
    # Classic release definitions
    # ------------------------------------------------------------------

    def list_release_definitions(self, project: str) -> list[dict[str, Any]]:
        """List classic release definitions in a project."""
        try:
            resp = self._vsrm_client.get(
                f"/{project}/_apis/release/definitions",
                params={"api-version": "7.1", "$top": "500", "$expand": "none"},
            )
            resp.raise_for_status()
            return resp.json().get("value", [])
        except httpx.HTTPError as exc:
            logger.warning("Failed to list release definitions for %s: %s", project, exc)
            return []

    def get_release_definition(self, project: str, definition_id: int) -> dict[str, Any]:
        """Fetch a full classic release definition including variables."""
        resp = self._vsrm_client.get(
            f"/{project}/_apis/release/definitions/{definition_id}",
            params={"api-version": "7.1"},
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_release_pipeline_variables(
        self, project: str, definition_id: int, definition_name: str = "",
    ) -> list[AdoVariable]:
        """Fetch all non-secret variables from a classic release definition.

        Classic release definitions have variables at two levels:
        1. Definition-level variables (shared across all stages)
        2. Per-environment variables (stage-specific)

        Both are extracted and returned.
        """
        try:
            defn = self.get_release_definition(project, definition_id)
        except httpx.HTTPError as exc:
            logger.debug("Could not fetch release definition %s/%s: %s", project, definition_id, exc)
            return []

        name = definition_name or defn.get("name", str(definition_id))
        results: list[AdoVariable] = []

        definition_vars = defn.get("variables", {})
        results.extend(
            self._extract_variables(definition_vars, project, "release_pipeline", name, definition_id)
        )

        for env in defn.get("environments", []):
            env_name = env.get("name", "")
            env_vars = env.get("variables", {})
            if env_vars:
                source = f"{name}/{env_name}" if env_name else name
                results.extend(
                    self._extract_variables(env_vars, project, "release_pipeline", source, definition_id)
                )

        return results

    # ------------------------------------------------------------------
    # Full org scan
    # ------------------------------------------------------------------

    def scan_org(
        self,
        *,
        projects: list[str] | None = None,
        include_builds: bool = True,
        include_groups: bool = True,
        include_releases: bool = True,
        max_definitions_per_project: int = 200,
    ) -> AdoScanResult:
        """Scan an entire ADO organization for pipeline variables.

        Iterates all projects (or a specified subset), fetching variables
        from build pipelines, variable groups, and classic release pipelines.
        """
        result = AdoScanResult()

        all_projects = self.list_projects()
        if projects:
            project_filter = {p.lower() for p in projects}
            all_projects = [p for p in all_projects if p["name"].lower() in project_filter]

        result.projects_scanned = len(all_projects)

        for project in all_projects:
            project_name = project["name"]
            logger.info("Scanning project: %s", project_name)

            if include_builds:
                self._scan_build_definitions(project_name, result, max_definitions_per_project)

            if include_groups:
                self._scan_variable_groups(project_name, result)

            if include_releases:
                self._scan_release_definitions(project_name, result, max_definitions_per_project)

        return result

    def _scan_build_definitions(
        self, project: str, result: AdoScanResult, max_defs: int,
    ) -> None:
        definitions = self.list_build_definitions(project)
        if len(definitions) > max_defs:
            logger.warning(
                "%s has %d build definitions — scanning first %d",
                project, len(definitions), max_defs,
            )
            definitions = definitions[:max_defs]

        for defn in definitions:
            defn_id = defn.get("id", 0)
            defn_name = defn.get("name", str(defn_id))
            variables = self.fetch_build_pipeline_variables(project, defn_id, defn_name)
            result.variables.extend(variables)
            result.pipelines_scanned += 1

    def _scan_variable_groups(self, project: str, result: AdoScanResult) -> None:
        groups = self.list_variable_groups(project)
        for group in groups:
            group_id = group.get("id", 0)
            group_name = group.get("name", str(group_id))
            variables = group.get("variables", {})
            extracted = self._extract_variables(
                variables, project, "variable_group", group_name, group_id,
            )
            result.variables.extend(extracted)
            result.groups_scanned += 1

    def _scan_release_definitions(
        self, project: str, result: AdoScanResult, max_defs: int,
    ) -> None:
        definitions = self.list_release_definitions(project)
        if len(definitions) > max_defs:
            logger.warning(
                "%s has %d release definitions — scanning first %d",
                project, len(definitions), max_defs,
            )
            definitions = definitions[:max_defs]

        for defn in definitions:
            defn_id = defn.get("id", 0)
            defn_name = defn.get("name", str(defn_id))
            variables = self.fetch_release_pipeline_variables(project, defn_id, defn_name)
            result.variables.extend(variables)
            result.release_definitions_scanned += 1

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_variables(
        variables: dict[str, Any],
        project: str,
        source_type: str,
        source_name: str,
        source_id: int,
    ) -> list[AdoVariable]:
        """Extract non-secret variables from an ADO variables dict."""
        results: list[AdoVariable] = []
        for var_name, var_props in variables.items():
            if var_props.get("isSecret", False):
                continue
            value = var_props.get("value")
            if value is None or str(value).strip() == "":
                continue
            results.append(AdoVariable(
                name=var_name,
                value=str(value),
                project=project,
                source_type=source_type,
                source_name=source_name,
                source_id=source_id,
            ))
        return results

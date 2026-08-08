"""Tests for the TUI URL builder (ado:// → web URL) and resolve_finding_url."""

from beachhead.tui.urls import (
    spyglass_credential_url,
    spyglass_finding_url,
    spyglass_resource_url,
    resolve_finding_url,
    resource_id_to_url,
)


class TestResourceIdToUrl:
    def test_vargroup(self):
        assert resource_id_to_url("ado://acme/proj/vargroup/7") == (
            "https://dev.azure.com/acme/proj/_library"
            "?itemType=VariableGroups&view=VariableGroupView&variableGroupId=7"
        )

    def test_pipeline(self):
        assert resource_id_to_url("ado://acme/proj/pipeline/42") == (
            "https://dev.azure.com/acme/proj/_build?definitionId=42"
        )

    def test_build(self):
        assert resource_id_to_url("ado://acme/proj/build/10") == (
            "https://dev.azure.com/acme/proj/_build?definitionId=10"
        )

    def test_build_log(self):
        assert resource_id_to_url("ado://acme/proj/build/10/log/3") == (
            "https://dev.azure.com/acme/proj/_build/results?buildId=10"
        )

    def test_release(self):
        assert resource_id_to_url("ado://acme/proj/release/5") == (
            "https://dev.azure.com/acme/proj/_release?definitionId=5"
        )

    def test_repo(self):
        url = resource_id_to_url("ado://acme/proj/repo/abc-123")
        assert url == "https://dev.azure.com/acme/proj/_git/abc-123"

    def test_endpoint(self):
        url = resource_id_to_url("ado://acme/proj/endpoint/ep-uuid")
        assert url == "https://dev.azure.com/acme/proj/_settings/adminservices?resourceId=ep-uuid"

    def test_work_item(self):
        assert resource_id_to_url("ado://acme/proj/wi/999") == (
            "https://dev.azure.com/acme/proj/_workitems/edit/999"
        )

    def test_project_feed(self):
        assert resource_id_to_url("ado://acme/proj/feed/my-feed") == (
            "https://dev.azure.com/acme/proj/_artifacts/feed/my-feed"
        )

    def test_org_feed(self):
        assert resource_id_to_url("ado://acme/feed/my-feed") == (
            "https://dev.azure.com/acme/_artifacts/feed/my-feed"
        )

    def test_wiki(self):
        assert resource_id_to_url("ado://acme/proj/wiki/My-Wiki") == (
            "https://dev.azure.com/acme/proj/_wiki/wikis/My-Wiki"
        )

    def test_pool(self):
        assert resource_id_to_url("ado://acme/pool/3") == (
            "https://dev.azure.com/acme/_settings/agentpools?poolId=3"
        )

    def test_pool_agent(self):
        assert resource_id_to_url("ado://acme/pool/3/agent/7") == (
            "https://dev.azure.com/acme/_settings/agentpools?poolId=3"
        )

    def test_extension(self):
        url = resource_id_to_url("ado://acme/extension/ms.vss-tfs-web")
        assert url == "https://dev.azure.com/acme/_settings/extensions"

    def test_hook(self):
        url = resource_id_to_url("ado://acme/hook/sub-123")
        assert url == "https://dev.azure.com/acme/_settings/serviceHooks"

    def test_empty_returns_empty(self):
        assert resource_id_to_url("") == ""

    def test_non_ado_returns_empty(self):
        assert resource_id_to_url("https://example.com") == ""

    def test_unrecognized_ado_returns_empty(self):
        assert resource_id_to_url("ado://acme/namespace/ns-123") == ""


class TestResolveFindingUrl:
    def test_prefers_explicit_ado_url(self):
        details = {"ado_url": "https://dev.azure.com/acme/proj/_git/repo?path=/file"}
        assert resolve_finding_url(details, "ado://acme/proj/repo/abc") == details["ado_url"]

    def test_falls_back_to_resource_id(self):
        url = resolve_finding_url({}, "ado://acme/proj/vargroup/7")
        assert "variableGroupId=7" in url

    def test_empty_details_empty_resource(self):
        assert resolve_finding_url({}, "") == ""

    def test_none_details(self):
        assert resolve_finding_url(None, "ado://acme/proj/vargroup/7") != ""


class TestSpyglassResourceUrl:
    def test_wiki_includes_project(self):
        url = spyglass_resource_url("ado://acme/MyProj/wiki/TeamWiki")
        assert "#/p/MyProj/wiki/TeamWiki" in url

    def test_repo_includes_project(self):
        url = spyglass_resource_url("ado://acme/MyProj/repo/my-repo", name="my-repo")
        assert "#/p/MyProj/repos/my-repo" in url

    def test_pipeline_includes_project(self):
        url = spyglass_resource_url("ado://acme/MyProj/pipeline/42")
        assert "#/p/MyProj/pipelines/42" in url

    def test_org_level_feed_no_project(self):
        url = spyglass_resource_url("ado://acme/feed/shared")
        assert "#/artifacts/shared" in url
        assert "/p/" not in url

    def test_empty_resource_id(self):
        assert spyglass_resource_url("") == ""


class TestSpyglassFindingUrl:
    def test_wiki_finding_includes_project(self):
        details = {"wiki_name": "TeamWiki", "project": "MyProj"}
        url = spyglass_finding_url(details)
        assert "#/p/MyProj/wiki/TeamWiki" in url

    def test_wiki_finding_with_page_path(self):
        details = {"wiki_name": "TeamWiki", "project": "MyProj", "page_path": "/Setup/Guide"}
        url = spyglass_finding_url(details)
        assert "#/p/MyProj/wiki/TeamWiki/Setup/Guide" in url

    def test_repo_finding_includes_project(self):
        details = {"repo_name": "backend", "project": "MyProj", "file_path": "/src/config.py"}
        url = spyglass_finding_url(details)
        assert "#/p/MyProj/repos/backend" in url

    def test_falls_back_to_resource_id_project(self):
        details = {"wiki_name": "TeamWiki"}
        url = spyglass_finding_url(details, resource_id="ado://acme/MyProj/wiki/TeamWiki")
        assert "#/p/MyProj/wiki/TeamWiki" in url

    def test_no_project_still_works(self):
        details = {"wiki_name": "TeamWiki"}
        url = spyglass_finding_url(details)
        assert "#/wiki/TeamWiki" in url
        assert "/p/" not in url


class TestSpyglassCredentialUrl:
    def test_wiki_credential_includes_project(self):
        details = {"wiki_name": "TeamWiki", "project": "MyProj"}
        url = spyglass_credential_url(details)
        assert "#/p/MyProj/wiki/TeamWiki" in url

    def test_repo_credential_includes_project(self):
        details = {"repo_name": "backend", "project": "MyProj"}
        url = spyglass_credential_url(details)
        assert "#/p/MyProj/repos/backend" in url

    def test_no_project_still_works(self):
        details = {"wiki_name": "TeamWiki"}
        url = spyglass_credential_url(details)
        assert "#/wiki/TeamWiki" in url
        assert "/p/" not in url

    def test_empty_details(self):
        assert spyglass_credential_url({}) == ""

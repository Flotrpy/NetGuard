import json

import httpx
import pytest

from netguard.core.security import encrypt_secret
from netguard.models import Repository
from netguard.services.providers import (
    COMMENT_MARKER,
    GitHubClient,
    GitLabClient,
    ProviderError,
    client_for,
    validate_external_id,
    validate_ref,
)


def http(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_identifier_and_ref_validation_blocks_path_injection():
    assert validate_external_id("github", "octo/repo-1.x") == "octo/repo-1.x"
    for bad in ["../etc/passwd", "a/b/c", "owner", "a b/c", "o/r?x=1", "o/r#f", "o/r/../x", "",
                "../x", "o/..", "./r", "o/."]:
        with pytest.raises(ProviderError):
            validate_external_id("github", bad)
    assert validate_external_id("gitlab", "12345") == "12345"
    assert validate_external_id("gitlab", "group/sub/proj") == "group/sub/proj"
    with pytest.raises(ProviderError):
        validate_external_id("gitlab", "group/../x?a=b")
    assert validate_ref("feature/x-1") == "feature/x-1"
    for bad in ["../main", "-rf", "a b", "x;rm", ""]:
        with pytest.raises(ProviderError):
            validate_ref(bad)


def test_github_get_repo_and_auth_header():
    seen = {}

    def handler(request):
        seen["auth"], seen["path"] = request.headers["authorization"], request.url.path
        return httpx.Response(200, json={"default_branch": "trunk", "html_url": "https://github.com/o/r", "private": True})

    info = GitHubClient("tok", "https://api.github.test", http(handler)).get_repo("o/r")
    assert info == {"default_branch": "trunk", "url": "https://github.com/o/r", "private": True}
    assert seen == {"auth": "Bearer tok", "path": "/repos/o/r"}


@pytest.mark.parametrize("status,msg", [(401, "rejected"), (403, "rejected"), (404, "not found"), (500, r"error \(500\)")])
def test_error_statuses_map_to_provider_errors(status, msg):
    c = GitHubClient("t", "https://x.test", http(lambda r: httpx.Response(status)))
    with pytest.raises(ProviderError, match=msg):
        c.get_repo("o/r")


def test_network_failure_is_a_provider_error():
    def down(request):
        raise httpx.ConnectError("no route")

    with pytest.raises(ProviderError, match="Could not reach"):
        GitHubClient("t", "https://x.test", http(down)).get_repo("o/r")


def test_archive_download_streams_and_enforces_size_limit(tmp_path):
    body = b"x" * 5000
    c = GitHubClient("t", "https://x.test", http(lambda r: httpx.Response(200, content=body)))
    dest = tmp_path / "a.tgz"
    c.download_archive("o/r", "main", dest, max_bytes=10_000)
    assert dest.read_bytes() == body
    with pytest.raises(ProviderError, match="size limit"):
        c.download_archive("o/r", "main", tmp_path / "b.tgz", max_bytes=1000)
    failing = GitHubClient("t", "https://x.test", http(lambda r: httpx.Response(404)))
    with pytest.raises(ProviderError, match="download failed"):
        failing.download_archive("o/r", "main", tmp_path / "c.tgz", max_bytes=10)


def test_github_status_and_comment_upsert():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.content))
        if request.method == "GET":
            return httpx.Response(200, json=[{"id": 7, "body": f"{COMMENT_MARKER}\nold"}])
        return httpx.Response(200, json={})

    c = GitHubClient("t", "https://x.test", http(handler))
    c.set_status("o/r", "abc1234", "failure", "2 findings", "https://ng.test/x")
    body = json.loads(calls[0][2])
    assert calls[0][:2] == ("POST", "/repos/o/r/statuses/abc1234")
    assert body == {"state": "failure", "description": "2 findings", "context": "NetGuard",
                    "target_url": "https://ng.test/x"}
    c.upsert_pr_comment("o/r", 5, f"{COMMENT_MARKER}\nnew")
    assert calls[-1][:2] == ("PATCH", "/repos/o/r/issues/comments/7")  # updates, not duplicates
    with pytest.raises(ProviderError, match="Invalid commit sha"):
        c.set_status("o/r", "../../x", "success", "d")


def test_github_creates_comment_when_none_exists():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(200, json=[] if request.method == "GET" else {})

    GitHubClient("t", "https://x.test", http(handler)).upsert_pr_comment("o/r", 3, "b")
    assert calls[-1] == ("POST", "/repos/o/r/issues/3/comments")


def test_gitlab_uses_private_token_and_encoded_project_path():
    seen = []

    def handler(request):
        seen.append((request.method, request.url.raw_path.decode(), request.headers.get("private-token")))
        return httpx.Response(200, json={"default_branch": None, "web_url": "u", "visibility": "public"} if request.method == "GET" else {})

    c = GitLabClient("glpat", "https://gl.test/api/v4", http(handler))
    assert c.get_repo("grp/sub/proj")["default_branch"] == "main"
    assert seen[0] == ("GET", "/api/v4/projects/grp%2Fsub%2Fproj", "glpat")
    c.set_status("42", "deadbeef", "failure", "bad")
    assert seen[1][1].startswith("/api/v4/projects/42/statuses/deadbeef?")
    assert "state=failed" in seen[1][1]


def test_client_for_decrypts_token_only_from_configured_urls():
    repo = Repository(project_id="p", provider="github", name="r", external_id="o/r",
                      token_encrypted=encrypt_secret("ghp_secret_value"))
    client = client_for(repo)
    assert isinstance(client, GitHubClient) and client.token == "ghp_secret_value"
    assert client.base_url == "https://api.github.com"  # from settings, not from the repo record
    gl = Repository(project_id="p", provider="gitlab", name="r", external_id="1",
                    token_encrypted=encrypt_secret("t"))
    assert isinstance(client_for(gl), GitLabClient)
    with pytest.raises(ProviderError):
        client_for(Repository(project_id="p", provider="upload", name="r"))
    with pytest.raises(ProviderError):
        client_for(Repository(project_id="p", provider="github", name="r", token_encrypted=""))

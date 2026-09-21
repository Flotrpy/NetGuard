"""GitHub and GitLab API clients (repository access, PR/MR comments, commit statuses).

Security notes:
* API base URLs come from server settings, never from user input (no SSRF via the integration).
* Repository identifiers are validated against a strict pattern before use in a URL.
* Source is fetched as an archive tarball (no ``git`` process, no hooks, no submodules) and is
  handed to the same hardened extraction pipeline as manual uploads.
* Tokens are decrypted only in memory, only when needed, and never logged.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from netguard.config import get_settings
from netguard.core.security import decrypt_secret
from netguard.models import Repository

COMMENT_MARKER = "<!-- netguard-security-check -->"
_GH_ID = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_GL_ID = re.compile(r"^(?:\d{1,12}|[A-Za-z0-9_.-]{1,100}(?:/[A-Za-z0-9_.-]{1,100}){1,8})$")
_REF = re.compile(r"^[A-Za-z0-9_./\-]{1,200}$")
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")


class ProviderError(Exception):
    """A provider call failed (bad credentials, not found, network, invalid input)."""


def validate_external_id(provider: str, external_id: str) -> str:
    pattern = _GH_ID if provider == "github" else _GL_ID
    if not pattern.match(external_id) or any(
        seg in (".", "..") or set(seg) == {"."} for seg in external_id.split("/")
    ):
        raise ProviderError(f"Invalid {provider} repository identifier")
    return external_id


def validate_ref(ref: str) -> str:
    if not _REF.match(ref) or ".." in ref or ref.startswith("-"):
        raise ProviderError("Invalid git ref")
    return ref


def _new_http() -> httpx.Client:  # separate function so tests can inject a mock transport
    return httpx.Client(timeout=30.0, follow_redirects=True, headers={"User-Agent": "NetGuard"})


class _Base:
    provider = ""

    def __init__(self, token: str, base_url: str, client: httpx.Client | None = None) -> None:
        self.token = token
        self.base_url = base_url.rstrip("/")
        self._client = client or _new_http()

    def _headers(self) -> dict[str, str]:  # pragma: no cover - overridden
        raise NotImplementedError

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            resp = self._client.request(
                method, f"{self.base_url}{path}", headers=self._headers(), **kw
            )
        except httpx.HTTPError as exc:
            raise ProviderError(f"Could not reach {self.provider}") from exc
        if resp.status_code in (401, 403):
            raise ProviderError(f"{self.provider} rejected the access token or it lacks permission")
        if resp.status_code == 404:
            raise ProviderError(f"{self.provider} repository or resource not found")
        if resp.status_code >= 400:
            raise ProviderError(f"{self.provider} returned an error ({resp.status_code})")
        return resp

    def _download(self, path: str, dest: Path, max_bytes: int, params: dict | None = None) -> None:
        try:
            with self._client.stream(
                "GET", f"{self.base_url}{path}", headers=self._headers(), params=params
            ) as resp:
                if resp.status_code >= 400:
                    raise ProviderError(
                        f"{self.provider} archive download failed ({resp.status_code})"
                    )
                size = 0
                with open(dest, "wb") as out:
                    for chunk in resp.iter_bytes(64 * 1024):
                        size += len(chunk)
                        if size > max_bytes:
                            raise ProviderError("Repository archive exceeds the size limit")
                        out.write(chunk)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Could not reach {self.provider}") from exc


class GitHubClient(_Base):
    provider = "GitHub"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get_repo(self, full_name: str) -> dict[str, Any]:
        data = self._request("GET", f"/repos/{validate_external_id('github', full_name)}").json()
        return {"default_branch": data.get("default_branch", "main"),
                "url": data.get("html_url", ""), "private": bool(data.get("private"))}

    def download_archive(self, full_name: str, ref: str, dest: Path, max_bytes: int) -> None:
        repo = validate_external_id("github", full_name)
        self._download(f"/repos/{repo}/tarball/{quote(validate_ref(ref))}", dest, max_bytes)

    def set_status(self, full_name: str, sha: str, state: str, description: str,
                   target_url: str = "") -> None:
        if not _SHA.match(sha):
            raise ProviderError("Invalid commit sha")
        body = {"state": state, "description": description[:140], "context": "NetGuard"}
        if target_url:
            body["target_url"] = target_url
        self._request("POST", f"/repos/{validate_external_id('github', full_name)}/statuses/{sha}",
                      json=body)

    def upsert_pr_comment(self, full_name: str, number: int, body: str) -> None:
        base = f"/repos/{validate_external_id('github', full_name)}/issues"
        existing = self._request("GET", f"{base}/{int(number)}/comments",
                                 params={"per_page": 100}).json()
        mine = next((c for c in existing if COMMENT_MARKER in (c.get("body") or "")), None)
        if mine:
            self._request("PATCH", f"{base}/comments/{mine['id']}", json={"body": body})
        else:
            self._request("POST", f"{base}/{int(number)}/comments", json={"body": body})


class GitLabClient(_Base):
    provider = "GitLab"

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.token}

    @staticmethod
    def _pid(project: str) -> str:
        return quote(validate_external_id("gitlab", project), safe="")

    def get_repo(self, project: str) -> dict[str, Any]:
        data = self._request("GET", f"/projects/{self._pid(project)}").json()
        return {"default_branch": data.get("default_branch") or "main",
                "url": data.get("web_url", ""), "private": data.get("visibility") != "public"}

    def download_archive(self, project: str, ref: str, dest: Path, max_bytes: int) -> None:
        self._download(f"/projects/{self._pid(project)}/repository/archive.tar.gz", dest,
                       max_bytes, params={"sha": validate_ref(ref)})

    def set_status(self, project: str, sha: str, state: str, description: str,
                   target_url: str = "") -> None:
        if not _SHA.match(sha):
            raise ProviderError("Invalid commit sha")
        gl_state = {"success": "success", "failure": "failed", "error": "failed",
                    "pending": "pending"}[state]
        params = {"state": gl_state, "name": "NetGuard", "description": description[:140]}
        if target_url:
            params["target_url"] = target_url
        self._request("POST", f"/projects/{self._pid(project)}/statuses/{sha}", params=params)

    def upsert_pr_comment(self, project: str, number: int, body: str) -> None:
        base = f"/projects/{self._pid(project)}/merge_requests/{int(number)}/notes"
        existing = self._request("GET", base, params={"per_page": 100}).json()
        mine = next((n for n in existing if COMMENT_MARKER in (n.get("body") or "")), None)
        if mine:
            self._request("PUT", f"{base}/{mine['id']}", json={"body": body})
        else:
            self._request("POST", base, json={"body": body})


def client_for(repo: Repository, http: httpx.Client | None = None) -> GitHubClient | GitLabClient:
    """Build the right client for a connected repository (token decrypted in memory only)."""
    s = get_settings()
    token = decrypt_secret(repo.token_encrypted)
    if not token:
        raise ProviderError("This repository has no stored access token")
    if repo.provider == "github":
        return GitHubClient(token, s.github_api_url, http)
    if repo.provider == "gitlab":
        return GitLabClient(token, s.gitlab_api_url, http)
    raise ProviderError("Repository is not connected to a provider")

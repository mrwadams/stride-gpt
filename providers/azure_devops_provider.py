from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse
import base64
import requests

from .base import RepoProvider, RepoRef, CODE_FILE_EXTENSIONS


class AzureDevOpsProvider(RepoProvider):
    def __init__(self, pat: str | None):
        if not pat:
            raise ValueError("Azure DevOps PAT is required")
        self.pat = pat

    def parse_url(self, url: str) -> RepoRef:
        parsed = urlparse(url)
        host = parsed.hostname or "dev.azure.com"
        parts = [p for p in parsed.path.split("/") if p]

        # Patterns:
        # 1) dev.azure.com/{org}/{project}/_git/{repo}
        # 2) {org}.visualstudio.com/{project}/_git/{repo}
        # 3) custom host: {collection}/{project}/_git/{repo}
        repo = None
        project = None
        owner = None  # org/collection

        if host.endswith("visualstudio.com"):
            # org from subdomain prefix
            owner = host.split(".")[0]
            if len(parts) >= 3 and parts[1] == "_git":
                project = parts[0]
                repo = parts[2]
            elif len(parts) >= 4 and parts[2] == "_git":
                project = parts[1]
                repo = parts[3]
            org_url = f"{parsed.scheme}://{host}"
        elif host == "dev.azure.com":
            if len(parts) < 4 or parts[2] != "_git":
                raise ValueError("Invalid Azure DevOps URL; expected dev.azure.com/{org}/{project}/_git/{repo}")
            owner, project, repo = parts[0], parts[1], parts[3]
            org_url = f"{parsed.scheme}://{host}/{owner}"
        else:
            # Custom server: {collection}/{project}/_git/{repo}
            # Some servers include /tfs/{collection}/... — keep first segment as owner/collection.
            # Find the index of '_git'
            try:
                git_idx = parts.index("_git")
            except ValueError:
                raise ValueError("Invalid Azure DevOps Server URL; missing /_git/ segment")
            if git_idx < 2:
                raise ValueError("Invalid Azure DevOps Server URL; expected {collection}/{project}/_git/{repo}")
            owner = parts[git_idx - 2]
            project = parts[git_idx - 1]
            repo = parts[git_idx + 1]
            org_url = f"{parsed.scheme}://{host}"

        return RepoRef(provider="azure-devops", host=host, owner=owner, project=project, repo=repo, organization_url=org_url)

    def _auth(self):
        # PAT via basic auth; username can be anything (often empty)
        return ("", self.pat)

    def _repo_api_base(self, ref: RepoRef) -> str:
        # {org_url}/{project}/_apis/git/repositories/{repo}
        return f"{ref.organization_url}/{ref.project}/_apis/git/repositories/{ref.repo}"

    def get_default_branch(self, ref: RepoRef) -> str:
        url = f"{self._repo_api_base(ref)}?api-version=7.1-preview.1"
        r = requests.get(url, auth=self._auth(), headers={"Accept": "application/json"})
        r.raise_for_status()
        data = r.json()
        default_ref = data.get("defaultBranch") or "refs/heads/main"
        return default_ref.replace("refs/heads/", "")

    def get_readme_text(self, ref: RepoRef, branch: str) -> str:
        for name in ("/README.md", "/readme.md"):
            url = (
                f"{self._repo_api_base(ref)}/items?path={name}"
                f"&versionDescriptor.version={branch}&versionDescriptor.versionType=branch"
                f"&includeContent=true&api-version=7.1-preview.1"
            )
            r = requests.get(url, auth=self._auth(), headers={"Accept": "application/json"})
            if r.status_code == 200:
                # Prefer JSON; fall back to raw text if server returns text/plain
                ctype = r.headers.get("Content-Type", "").lower()
                if "application/json" in ctype:
                    try:
                        data = r.json()
                        content = data.get("content")
                        if content is not None:
                            return content
                    except ValueError:
                        pass
                else:
                    # Raw content in response body
                    return r.text
        return ""

    def iter_code_files(self, ref: RepoRef, branch: str) -> Iterable[str]:
        # List all items recursively and filter by extension
        url = (
            f"{self._repo_api_base(ref)}/items?scopePath=/&recursionLevel=Full"
            f"&versionDescriptor.version={branch}&versionDescriptor.versionType=branch"
            "&includeContentMetadata=true&api-version=7.1-preview.1"
        )
        r = requests.get(url, auth=self._auth(), headers={"Accept": "application/json"})
        r.raise_for_status()
        data = r.json()
        for item in data.get("value", []):
            if item.get("isFolder"):
                continue
            path = item.get("path") or ""
            # Azure returns paths starting with '/'
            if any(path.endswith(ext) for ext in CODE_FILE_EXTENSIONS):
                # normalize path without leading slash for display consistency
                yield path[1:] if path.startswith("/") else path

    def get_file_content(self, ref: RepoRef, path: str, branch: str) -> str:
        # Ensure path begins with '/'
        norm_path = path if path.startswith("/") else f"/{path}"
        url = (
            f"{self._repo_api_base(ref)}/items?path={norm_path}"
            f"&versionDescriptor.version={branch}&versionDescriptor.versionType=branch"
            f"&includeContent=true&api-version=7.1-preview.1"
        )
        r = requests.get(url, auth=self._auth(), headers={"Accept": "application/json"})
        r.raise_for_status()
        ctype = r.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            try:
                data = r.json()
            except ValueError:
                data = None
            if isinstance(data, dict):
                content = data.get("content")
                if content is None:
                    return ""
                try:
                    content.encode("utf-8")
                    return content
                except Exception:
                    try:
                        return base64.b64decode(content).decode()
                    except Exception:
                        return ""
        # Fallback raw text body
        return r.text

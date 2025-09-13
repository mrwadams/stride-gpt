from __future__ import annotations

import base64
from urllib.parse import urlparse
from typing import Iterable

from github import Github

from .base import RepoProvider, RepoRef, CODE_FILE_EXTENSIONS


class GitHubProvider(RepoProvider):
    def __init__(self, token: str | None):
        self.token = token or ""

    def parse_url(self, url: str) -> RepoRef:
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 2:
            raise ValueError("Invalid GitHub URL; expected /owner/repo")
        owner, repo = parts[0], parts[1]
        api_base = f"{parsed.scheme}://{parsed.hostname}/api/v3" if parsed.hostname and parsed.hostname != "github.com" else None
        return RepoRef(provider="github", host=parsed.hostname or "github.com", owner=owner, project=None, repo=repo, api_base=api_base)

    def _client(self, ref: RepoRef) -> Github:
        if ref.api_base:
            return Github(self.token, base_url=ref.api_base)
        return Github(self.token)

    def _repo(self, ref: RepoRef):
        gh = self._client(ref)
        return gh.get_repo(f"{ref.owner}/{ref.repo}")

    def get_default_branch(self, ref: RepoRef) -> str:
        return self._repo(ref).default_branch

    def get_readme_text(self, ref: RepoRef, branch: str) -> str:
        repo = self._repo(ref)
        for name in ("README.md", "readme.md"):
            try:
                item = repo.get_contents(name, ref=branch)
                return base64.b64decode(item.content).decode()
            except Exception:
                continue
        return ""

    def iter_code_files(self, ref: RepoRef, branch: str) -> Iterable[str]:
        repo = self._repo(ref)
        tree = repo.get_git_tree(branch, recursive=True)
        for node in tree.tree:
            if getattr(node, "type", None) == "blob" and any(node.path.endswith(ext) for ext in CODE_FILE_EXTENSIONS):
                yield node.path

    def get_file_content(self, ref: RepoRef, path: str, branch: str) -> str:
        repo = self._repo(ref)
        content = repo.get_contents(path, ref=branch)
        return base64.b64decode(content.content).decode()

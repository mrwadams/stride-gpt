from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol, Tuple


@dataclass
class RepoRef:
    """Normalized repository reference across providers."""
    provider: str  # "github" | "azure-devops"
    host: str
    owner: str | None
    project: str | None
    repo: str
    api_base: str | None = None          # for GitHub (GHE)
    organization_url: str | None = None  # for Azure DevOps


class RepoProvider(Protocol):
    """Provider interface for repository content listing and retrieval."""

    def parse_url(self, url: str) -> RepoRef:
        ...

    def get_default_branch(self, ref: RepoRef) -> str:
        ...

    def get_readme_text(self, ref: RepoRef, branch: str) -> str:
        ...

    def iter_code_files(self, ref: RepoRef, branch: str) -> Iterable[str]:
        ...

    def get_file_content(self, ref: RepoRef, path: str, branch: str) -> str:
        ...


CODE_FILE_EXTENSIONS: Tuple[str, ...] = (
    ".py", ".js", ".ts", ".html", ".css", ".java", ".go", ".rb", ".c", ".cpp", ".h", ".cs", ".php"
)

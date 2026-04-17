from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(slots=True)
class GitResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


@dataclass(slots=True)
class GitHubRepoRef:
    owner: str
    repo_name: str
    repo_url: str


def run_git(repo_root: Path, *args: str) -> GitResult:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    return GitResult(
        command=["git", *args],
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def current_branch(repo_root: Path) -> str:
    result = run_git(repo_root, "branch", "--show-current")
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Unable to resolve current branch.")
    return result.stdout


def current_commit(repo_root: Path) -> str:
    result = run_git(repo_root, "rev-parse", "HEAD")
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Unable to resolve current commit.")
    return result.stdout


def is_git_repository(repo_root: Path) -> bool:
    if not repo_root.exists() or not repo_root.is_dir():
        return False
    result = run_git(repo_root, "rev-parse", "--is-inside-work-tree")
    return result.returncode == 0 and result.stdout.lower() == "true"


def origin_url(repo_root: Path) -> str:
    result = run_git(repo_root, "remote", "get-url", "origin")
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Unable to resolve git origin.")
    return result.stdout


def ensure_clean_message(result: GitResult) -> None:
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Git command failed.")


def normalize_public_github_url(raw_url: str) -> GitHubRepoRef:
    candidate = raw_url.strip()
    if not candidate:
        raise RuntimeError("Repository URL is required.")
    if candidate.startswith("git@") or candidate.startswith("ssh://"):
        raise RuntimeError("Only public GitHub HTTPS URLs are supported.")
    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise RuntimeError("Only public GitHub HTTPS URLs are supported.")

    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [part for part in path.split("/") if part]
    if len(parts) != 2 or any(not part for part in parts):
        raise RuntimeError("GitHub repository URL must be in github.com/<owner>/<repo> form.")

    owner, repo_name = parts
    return GitHubRepoRef(
        owner=owner,
        repo_name=repo_name,
        repo_url=f"https://github.com/{owner}/{repo_name}",
    )


def clone_repository(parent_root: Path, repo_url: str, target_path: Path) -> GitResult:
    target_parent = target_path.parent
    target_parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run(
        ["git", "clone", repo_url, str(target_path)],
        cwd=parent_root,
        text=True,
        capture_output=True,
        check=False,
    )
    return GitResult(
        command=["git", "clone", repo_url, str(target_path)],
        returncode=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def pull_current_branch(repo_root: Path) -> GitResult:
    result = run_git(repo_root, "pull")
    ensure_clean_message(result)
    return result


def ensure_repo_checkout(workspace_root: Path, repo_url: str, target_path: Path) -> str:
    if target_path.exists():
        if not target_path.is_dir():
            raise RuntimeError(f"Destination exists and is not a directory: {target_path}")
        if not is_git_repository(target_path):
            raise RuntimeError(f"Destination exists but is not a git repository: {target_path}")
        existing_origin = origin_url(target_path)
        if existing_origin.rstrip("/") != repo_url and existing_origin.rstrip("/") != f"{repo_url}.git":
            raise RuntimeError(
                f"Destination repository origin does not match requested URL: {target_path}"
            )
        result = pull_current_branch(target_path)
        if result.returncode != 0:
            raise RuntimeError(
                f"Unable to update cloned repository {repo_url}: {result.stderr or result.stdout}"
            )
        return "updated"

    result = clone_repository(workspace_root, repo_url, target_path)
    if result.returncode != 0:
        raise RuntimeError(
            f"Unable to clone public GitHub repository {repo_url}: {result.stderr or result.stdout}"
        )
    return "cloned"


def push_current_branch(repo_root: Path) -> GitResult:
    result = run_git(repo_root, "push")
    ensure_clean_message(result)
    return result

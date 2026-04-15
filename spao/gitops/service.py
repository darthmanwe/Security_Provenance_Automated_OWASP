from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class GitResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


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


def ensure_clean_message(result: GitResult) -> None:
    if result.returncode != 0:
        raise RuntimeError(result.stderr or "Git command failed.")


def push_current_branch(repo_root: Path) -> GitResult:
    result = run_git(repo_root, "push")
    ensure_clean_message(result)
    return result

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from spao.cli import main
from spao.gitops.service import GitHubRepoRef, GitResult, ensure_repo_checkout, normalize_public_github_url


class GitHubUrlNormalizationTests(unittest.TestCase):
    def test_normalize_public_github_url_accepts_supported_forms(self) -> None:
        ref = normalize_public_github_url("github.com/openai/spao-demo")
        self.assertEqual(ref.repo_url, "https://github.com/openai/spao-demo")
        self.assertEqual(ref.owner, "openai")
        self.assertEqual(ref.repo_name, "spao-demo")

        ref = normalize_public_github_url("https://github.com/openai/spao-demo.git")
        self.assertEqual(ref.repo_url, "https://github.com/openai/spao-demo")

    def test_normalize_public_github_url_rejects_unsupported_forms(self) -> None:
        for candidate in (
            "",
            "git@github.com:openai/spao-demo.git",
            "ssh://git@github.com/openai/spao-demo.git",
            "https://gitlab.com/openai/spao-demo",
            "https://github.com/openai",
            "https://github.com/openai/spao-demo/issues",
            "http://github.com/openai/spao-demo",
        ):
            with self.assertRaises(RuntimeError):
                normalize_public_github_url(candidate)


class RepoCheckoutServiceTests(unittest.TestCase):
    def test_ensure_repo_checkout_clones_then_updates_existing_repo(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            target = workspace / "imports" / "source"
            with patch(
                "spao.gitops.service.clone_repository",
                return_value=GitResult(
                    command=["git", "clone"],
                    returncode=0,
                    stdout="cloned",
                    stderr="",
                ),
            ) as clone_repository:
                action = ensure_repo_checkout(workspace, "https://github.com/openai/source", target)

            self.assertEqual(action, "cloned")
            clone_repository.assert_called_once_with(workspace, "https://github.com/openai/source", target)

            target.mkdir(parents=True)
            with patch("spao.gitops.service.is_git_repository", return_value=True):
                with patch("spao.gitops.service.origin_url", return_value="https://github.com/openai/source"):
                    with patch(
                        "spao.gitops.service.pull_current_branch",
                        return_value=GitResult(
                            command=["git", "pull"],
                            returncode=0,
                            stdout="updated",
                            stderr="",
                        ),
                    ) as pull_current_branch:
                        action = ensure_repo_checkout(workspace, "https://github.com/openai/source", target)

            self.assertEqual(action, "updated")
            pull_current_branch.assert_called_once_with(target)

    def test_ensure_repo_checkout_rejects_non_git_destination(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            destination = workspace / "imports" / "demo"
            destination.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "not a git repository"):
                ensure_repo_checkout(workspace, "https://github.com/openai/demo", destination)

    def test_ensure_repo_checkout_rejects_origin_mismatch(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            target = workspace / "imports" / "demo"
            target.mkdir(parents=True)

            with patch("spao.gitops.service.is_git_repository", return_value=True):
                with patch("spao.gitops.service.origin_url", return_value="https://github.com/openai/source-a"):
                    with self.assertRaisesRegex(RuntimeError, "origin does not match"):
                        ensure_repo_checkout(workspace, "https://github.com/openai/source-b", target)


class RepoPullCliTests(unittest.TestCase):
    def test_repo_pull_creates_managed_import_and_config(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            stdout = io.StringIO()
            with patch("spao.cli.Path.cwd", return_value=workspace):
                with patch(
                    "spao.cli.normalize_public_github_url",
                    return_value=GitHubRepoRef(
                        owner="openai",
                        repo_name="demo",
                        repo_url="https://github.com/openai/demo",
                    ),
                ):
                    with patch("spao.cli.ensure_repo_checkout", return_value="cloned") as ensure_checkout:
                        with patch("spao.cli.current_branch", return_value="main"):
                            with patch("spao.cli.current_commit", return_value="abc123"):
                                with redirect_stdout(stdout):
                                    exit_code = main(["repo", "pull", "https://github.com/openai/demo"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            target_repo = workspace / "imports" / "demo"
            self.assertEqual(payload["action"], "cloned")
            self.assertEqual(payload["repo_path"], str(target_repo))
            self.assertEqual(payload["repo_url"], "https://github.com/openai/demo")
            self.assertEqual(payload["branch"], "main")
            self.assertEqual(payload["commit"], "abc123")
            self.assertTrue(payload["initialized"])
            self.assertTrue((target_repo / ".spao" / "config.json").exists())
            ensure_checkout.assert_called_once_with(workspace, "https://github.com/openai/demo", target_repo)

    def test_repo_pull_rerun_preserves_existing_config(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            target_repo = workspace / "imports" / "demo"
            config_dir = target_repo / ".spao"
            config_dir.mkdir(parents=True)
            config_path = config_dir / "config.json"
            original = '{\n  "project_name": "custom-demo"\n}\n'
            config_path.write_text(original, encoding="utf-8")

            stdout = io.StringIO()
            with patch("spao.cli.Path.cwd", return_value=workspace):
                with patch(
                    "spao.cli.normalize_public_github_url",
                    return_value=GitHubRepoRef(
                        owner="openai",
                        repo_name="demo",
                        repo_url="https://github.com/openai/demo",
                    ),
                ):
                    with patch("spao.cli.ensure_repo_checkout", return_value="updated"):
                        with patch("spao.cli.current_branch", return_value="main"):
                            with patch("spao.cli.current_commit", return_value="def456"):
                                with redirect_stdout(stdout):
                                    exit_code = main(["repo", "pull", "https://github.com/openai/demo"])

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["action"], "updated")
            self.assertFalse(payload["initialized"])
            self.assertEqual(config_path.read_text(encoding="utf-8"), original)

    def test_repo_pull_rejects_invalid_url_before_git(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            stdout = io.StringIO()
            with patch("spao.cli.Path.cwd", return_value=workspace):
                with patch("spao.cli.ensure_repo_checkout") as ensure_checkout:
                    with redirect_stdout(stdout):
                        exit_code = main(["repo", "pull", "git@github.com:openai/demo.git"])

            self.assertEqual(exit_code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertIn("Only public GitHub HTTPS URLs are supported.", payload["error"])
            ensure_checkout.assert_not_called()

    def test_repo_pull_rejects_destination_outside_workspace(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            outside = workspace.parent / "elsewhere"
            stdout = io.StringIO()
            with patch("spao.cli.Path.cwd", return_value=workspace):
                with patch(
                    "spao.cli.normalize_public_github_url",
                    return_value=GitHubRepoRef(
                        owner="openai",
                        repo_name="demo",
                        repo_url="https://github.com/openai/demo",
                    ),
                ):
                    with patch("spao.cli.ensure_repo_checkout") as ensure_checkout:
                        with redirect_stdout(stdout):
                            exit_code = main(
                                [
                                    "repo",
                                    "pull",
                                    "https://github.com/openai/demo",
                                    "--dest",
                                    str(outside),
                                ]
                            )

            self.assertEqual(exit_code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertIn("Destination path must stay inside the current workspace.", payload["error"])
            ensure_checkout.assert_not_called()

    def test_repo_pull_supports_explicit_destination_inside_workspace(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            destination = Path("imports") / "custom-demo"
            stdout = io.StringIO()
            with patch("spao.cli.Path.cwd", return_value=workspace):
                with patch(
                    "spao.cli.normalize_public_github_url",
                    return_value=GitHubRepoRef(
                        owner="openai",
                        repo_name="demo",
                        repo_url="https://github.com/openai/demo",
                    ),
                ):
                    with patch("spao.cli.ensure_repo_checkout", return_value="cloned") as ensure_checkout:
                        with patch("spao.cli.current_branch", return_value="main"):
                            with patch("spao.cli.current_commit", return_value="abc123"):
                                with redirect_stdout(stdout):
                                    exit_code = main(
                                        [
                                            "repo",
                                            "pull",
                                            "https://github.com/openai/demo",
                                            "--dest",
                                            str(destination),
                                        ]
                                    )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["repo_path"], str((workspace / destination).resolve()))
            ensure_checkout.assert_called_once()

    def test_repo_pull_subprocess_rejects_non_github_host(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
            result = subprocess.run(
                [sys.executable, "-m", "spao", "repo", "pull", "https://gitlab.com/openai/demo"],
                cwd=workspace,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )

            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertIn("Only public GitHub HTTPS URLs are supported.", payload["error"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


CONFIG_DIR_NAME = ".spao"
CONFIG_FILE_NAME = "config.json"


@dataclass(slots=True)
class SpaoConfig:
    project_name: str
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password_env: str = "NEO4J_PASSWORD"
    default_branch_prefix: str = "codex"
    supported_languages: list[str] = field(
        default_factory=lambda: ["python", "javascript", "typescript"]
    )
    scanners: list[str] = field(
        default_factory=lambda: ["semgrep", "ruff", "bandit", "eslint"]
    )


def config_dir(root: Path) -> Path:
    return root / CONFIG_DIR_NAME


def config_path(root: Path) -> Path:
    return config_dir(root) / CONFIG_FILE_NAME


def load_config(root: Path) -> SpaoConfig:
    data = json.loads(config_path(root).read_text(encoding="utf-8"))
    return SpaoConfig(**data)


def save_config(root: Path, config: SpaoConfig) -> Path:
    directory = config_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    target = config_path(root)
    target.write_text(json.dumps(asdict(config), indent=2) + "\n", encoding="utf-8")
    return target

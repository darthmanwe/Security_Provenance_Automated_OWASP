from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from spao.graph.schema import EDGE_TYPES, NODE_LABELS
from spao.indexer.parsers import ParsedFile, parser_for_language
from spao.models import GraphDocument, GraphEdge, GraphNode


SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
}

EXCLUDED_PARTS = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    "__pycache__",
}


@dataclass(slots=True)
class IndexedFile:
    path: str
    language: str
    content: str


def _stable_id(prefix: str, *parts: object) -> str:
    raw = "::".join([prefix, *[str(part) for part in parts]])
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def discover_git_tracked_files(root: Path) -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Unable to enumerate git-tracked files.")

    files: list[Path] = []
    for relative in completed.stdout.splitlines():
        path = root / relative
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        files.append(path)
    return files


def _file_node(relative_path: str, language: str, content: str) -> GraphNode:
    return GraphNode(
        node_id=_stable_id("file", relative_path),
        label=NODE_LABELS["file"],
        properties={
            "path": relative_path,
            "language": language,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        },
    )


def build_graph(root: Path) -> GraphDocument:
    repo_node = GraphNode(
        node_id=_stable_id("repo", root.name),
        label=NODE_LABELS["repo"],
        properties={"name": root.name, "root_path": str(root)},
    )
    snapshot_node = GraphNode(
        node_id=_stable_id("snapshot", root.name, "latest"),
        label=NODE_LABELS["snapshot"],
        properties={"name": "latest"},
    )

    nodes = [repo_node, snapshot_node]
    edges = [
        GraphEdge(
            edge_id=_stable_id("edge", repo_node.node_id, snapshot_node.node_id, EDGE_TYPES["contains"]),
            edge_type=EDGE_TYPES["contains"],
            source=repo_node.node_id,
            target=snapshot_node.node_id,
        )
    ]

    file_count = 0
    line_count = 0
    symbol_count = 0
    statement_count = 0

    for path in discover_git_tracked_files(root):
        content = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(root).as_posix()
        language = SUPPORTED_EXTENSIONS[path.suffix.lower()]
        parsed_file = _parse_file(path, language, content)
        file_node = _file_node(relative_path, language, content)
        nodes.append(file_node)
        file_count += 1
        edges.append(
            GraphEdge(
                edge_id=_stable_id("edge", snapshot_node.node_id, file_node.node_id, EDGE_TYPES["contains"]),
                edge_type=EDGE_TYPES["contains"],
                source=snapshot_node.node_id,
                target=file_node.node_id,
            )
        )

        previous_line_node_id: str | None = None
        for line_number, line in enumerate(content.splitlines(), start=1):
            line_node = GraphNode(
                node_id=_stable_id("line", relative_path, line_number),
                label=NODE_LABELS["line_span"],
                properties={
                    "file_path": relative_path,
                    "line_start": line_number,
                    "line_end": line_number,
                    "text": line,
                    "sha256": hashlib.sha256(line.encode("utf-8")).hexdigest(),
                },
            )
            nodes.append(line_node)
            line_count += 1
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("edge", file_node.node_id, line_node.node_id, EDGE_TYPES["has_line"]),
                    edge_type=EDGE_TYPES["has_line"],
                    source=file_node.node_id,
                    target=line_node.node_id,
                )
            )
            if previous_line_node_id is not None:
                edges.append(
                    GraphEdge(
                        edge_id=_stable_id("edge", previous_line_node_id, line_node.node_id, EDGE_TYPES["next_line"]),
                        edge_type=EDGE_TYPES["next_line"],
                        source=previous_line_node_id,
                        target=line_node.node_id,
                    )
                )
            previous_line_node_id = line_node.node_id

        for symbol in parsed_file.symbols:
            symbol_node = GraphNode(
                node_id=_stable_id(
                    "symbol",
                    relative_path,
                    symbol.kind,
                    symbol.name,
                    symbol.line_start,
                    symbol.line_end,
                ),
                label=NODE_LABELS["symbol"],
                properties={
                    "file_path": relative_path,
                    "kind": symbol.kind,
                    "name": symbol.name,
                    "line_start": symbol.line_start,
                    "line_end": symbol.line_end,
                    "container_kind": symbol.container_kind,
                    "container_name": symbol.container_name,
                    "is_exported": symbol.is_exported,
                },
            )
            nodes.append(symbol_node)
            symbol_count += 1
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("edge", file_node.node_id, symbol_node.node_id, EDGE_TYPES["declares"]),
                    edge_type=EDGE_TYPES["declares"],
                    source=file_node.node_id,
                    target=symbol_node.node_id,
                )
            )

        for statement in parsed_file.statements:
            statement_node = GraphNode(
                node_id=_stable_id(
                    "statement",
                    relative_path,
                    statement.kind,
                    statement.line_start,
                    statement.line_end,
                ),
                label=NODE_LABELS["statement"],
                properties={
                    "file_path": relative_path,
                    "line_start": statement.line_start,
                    "line_end": statement.line_end,
                    "preview": statement.preview,
                    "kind": statement.kind,
                    "container_kind": statement.container_kind,
                    "container_name": statement.container_name,
                },
            )
            nodes.append(statement_node)
            statement_count += 1
            edges.append(
                GraphEdge(
                    edge_id=_stable_id("edge", file_node.node_id, statement_node.node_id, EDGE_TYPES["ast_parent"]),
                    edge_type=EDGE_TYPES["ast_parent"],
                    source=file_node.node_id,
                    target=statement_node.node_id,
                )
            )

    return GraphDocument(
        metadata={
            "repo_name": root.name,
            "indexed_files": file_count,
            "indexed_lines": line_count,
            "indexed_symbols": symbol_count,
            "indexed_statements": statement_count,
        },
        nodes=nodes,
        edges=edges,
    )


def _parse_file(path: Path, language: str, content: str) -> ParsedFile:
    parser = parser_for_language(language)
    return parser.parse(path, language, content)

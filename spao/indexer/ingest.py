from __future__ import annotations

import ast
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from spao.graph.schema import EDGE_TYPES, NODE_LABELS
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


def _statement_ranges(content: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped:
            ranges.append((line_number, line_number, stripped[:120]))
    return ranges


def _python_symbols(content: str) -> list[tuple[str, str, int, int]]:
    tree = ast.parse(content)
    symbols: list[tuple[str, str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end_line = getattr(node, "end_lineno", node.lineno)
            symbols.append(("function", node.name, node.lineno, end_line))
        elif isinstance(node, ast.ClassDef):
            end_line = getattr(node, "end_lineno", node.lineno)
            symbols.append(("class", node.name, node.lineno, end_line))
    return symbols


def _js_ts_symbols(content: str) -> list[tuple[str, str, int, int]]:
    symbols: list[tuple[str, str, int, int]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("function "):
            name = stripped.split("function ", 1)[1].split("(", 1)[0].strip()
            symbols.append(("function", name or f"function_{line_number}", line_number, line_number))
        elif stripped.startswith("class "):
            name = stripped.split("class ", 1)[1].split("{", 1)[0].strip()
            symbols.append(("class", name or f"class_{line_number}", line_number, line_number))
        elif "=>" in stripped and ("const " in stripped or "let " in stripped):
            name = stripped.split("=", 1)[0].replace("const ", "").replace("let ", "").strip()
            symbols.append(("function", name or f"lambda_{line_number}", line_number, line_number))
    return symbols


def _extract_symbols(language: str, content: str) -> list[tuple[str, str, int, int]]:
    if language == "python":
        return _python_symbols(content)
    return _js_ts_symbols(content)


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

        for symbol_kind, symbol_name, start_line, end_line in _extract_symbols(language, content):
            symbol_node = GraphNode(
                node_id=_stable_id("symbol", relative_path, symbol_kind, symbol_name, start_line, end_line),
                label=NODE_LABELS["symbol"],
                properties={
                    "file_path": relative_path,
                    "kind": symbol_kind,
                    "name": symbol_name,
                    "line_start": start_line,
                    "line_end": end_line,
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

        for start_line, end_line, preview in _statement_ranges(content):
            statement_node = GraphNode(
                node_id=_stable_id("statement", relative_path, start_line, end_line),
                label=NODE_LABELS["statement"],
                properties={
                    "file_path": relative_path,
                    "line_start": start_line,
                    "line_end": end_line,
                    "preview": preview,
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

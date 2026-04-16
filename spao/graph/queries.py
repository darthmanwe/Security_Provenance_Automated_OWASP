from __future__ import annotations

from spao.models import GraphDocument, GraphNode


def query_graph(
    document: GraphDocument,
    kind: str,
    path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
) -> dict[str, object]:
    if kind == "files":
        nodes = [
            node.to_dict()
            for node in document.nodes
            if node.label == "File" and (path is None or node.properties.get("path") == path)
        ]
        return {"kind": kind, "results": nodes}

    if kind == "symbols":
        _require_path(path, kind)
        nodes = [
            node.to_dict()
            for node in document.nodes
            if node.label == "Symbol"
            and node.properties.get("file_path") == path
            and _matches_line_range(node, line_start, line_end)
        ]
        return {"kind": kind, "results": nodes}

    if kind == "statements":
        _require_path(path, kind)
        nodes = [
            node.to_dict()
            for node in document.nodes
            if node.label == "Statement"
            and node.properties.get("file_path") == path
            and _matches_line_range(node, line_start, line_end)
        ]
        return {"kind": kind, "results": nodes}

    if kind == "neighbors":
        _require_path(path, kind)
        if line_start is None:
            raise RuntimeError("graph query --kind neighbors requires --line-start.")
        file_node = next(
            (
                node.to_dict()
                for node in document.nodes
                if node.label == "File" and node.properties.get("path") == path
            ),
            None,
        )
        symbols = [
            node.to_dict()
            for node in document.nodes
            if node.label == "Symbol"
            and node.properties.get("file_path") == path
            and _matches_line_range(node, line_start, line_end or line_start)
        ]
        window_start = max(1, line_start - 3)
        window_end = (line_end or line_start) + 3
        statements = [
            node.to_dict()
            for node in document.nodes
            if node.label == "Statement"
            and node.properties.get("file_path") == path
            and _matches_line_range(node, window_start, window_end)
        ]
        return {
            "kind": kind,
            "results": {
                "file": file_node,
                "symbols": symbols,
                "statements": statements,
            },
        }

    raise RuntimeError(f"Unsupported graph query kind: {kind}")


def _matches_line_range(node: GraphNode, line_start: int | None, line_end: int | None) -> bool:
    if line_start is None and line_end is None:
        return True
    start = int(node.properties.get("line_start", 0))
    end = int(node.properties.get("line_end", 0))
    requested_start = line_start if line_start is not None else line_end
    requested_end = line_end if line_end is not None else line_start
    assert requested_start is not None
    assert requested_end is not None
    return start <= requested_end and end >= requested_start


def _require_path(path: str | None, kind: str) -> None:
    if path is None:
        raise RuntimeError(f"graph query --kind {kind} requires --path.")

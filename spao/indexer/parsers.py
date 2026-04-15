from __future__ import annotations

import ast
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ParsedSymbol:
    kind: str
    name: str
    line_start: int
    line_end: int
    container_kind: str | None = None
    container_name: str | None = None
    is_exported: bool = False


@dataclass(slots=True)
class ParsedStatement:
    kind: str
    line_start: int
    line_end: int
    preview: str
    container_kind: str | None = None
    container_name: str | None = None


@dataclass(slots=True)
class ParsedFile:
    symbols: list[ParsedSymbol]
    statements: list[ParsedStatement]


class ParserAdapter:
    def parse(self, path: Path, language: str, content: str) -> ParsedFile:
        raise NotImplementedError


class PythonParserAdapter(ParserAdapter):
    def parse(self, path: Path, language: str, content: str) -> ParsedFile:
        tree = ast.parse(content)
        symbols: list[ParsedSymbol] = []
        statements: list[ParsedStatement] = []
        container_stack: list[tuple[str, str]] = []

        def visit(node: ast.AST) -> None:
            current_container = container_stack[-1] if container_stack else (None, None)

            if isinstance(node, ast.ClassDef):
                end_line = getattr(node, "end_lineno", node.lineno)
                symbols.append(
                    ParsedSymbol(
                        kind="class",
                        name=node.name,
                        line_start=node.lineno,
                        line_end=end_line,
                        container_kind=current_container[0],
                        container_name=current_container[1],
                    )
                )
                container_stack.append(("class", node.name))
                for child in node.body:
                    visit(child)
                container_stack.pop()
                return

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end_line = getattr(node, "end_lineno", node.lineno)
                symbols.append(
                    ParsedSymbol(
                        kind="function",
                        name=node.name,
                        line_start=node.lineno,
                        line_end=end_line,
                        container_kind=current_container[0],
                        container_name=current_container[1],
                    )
                )
                container_stack.append(("function", node.name))
                for child in node.body:
                    visit(child)
                container_stack.pop()
                return

            if isinstance(node, ast.stmt):
                end_line = getattr(node, "end_lineno", getattr(node, "lineno", 0))
                line_start = getattr(node, "lineno", 0)
                if line_start:
                    preview = ast.get_source_segment(content, node) or ast.dump(node, include_attributes=False)
                    preview = " ".join(preview.split())[:120]
                    statements.append(
                        ParsedStatement(
                            kind=type(node).__name__,
                            line_start=line_start,
                            line_end=end_line,
                            preview=preview,
                            container_kind=current_container[0],
                            container_name=current_container[1],
                        )
                    )

            for child in ast.iter_child_nodes(node):
                visit(child)

        visit(tree)
        return ParsedFile(symbols=symbols, statements=statements)


class JsTsParserAdapter(ParserAdapter):
    def __init__(self) -> None:
        self.helper_path = Path(__file__).with_name("js_ts_parser.js")

    def parse(self, path: Path, language: str, content: str) -> ParsedFile:
        completed = subprocess.run(
            ["node", str(self.helper_path), str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"Failed to parse {path.name} with the JS/TS parser: {completed.stderr.strip() or completed.stdout.strip()}"
            )

        payload = json.loads(completed.stdout)
        return ParsedFile(
            symbols=[ParsedSymbol(**item) for item in payload.get("symbols", [])],
            statements=[ParsedStatement(**item) for item in payload.get("statements", [])],
        )


def parser_for_language(language: str) -> ParserAdapter:
    if language == "python":
        return PythonParserAdapter()
    if language in {"javascript", "typescript"}:
        return JsTsParserAdapter()
    raise RuntimeError(f"Unsupported language for parsing: {language}")

"""AST parsing layer using tree-sitter via tree-sitter-language-pack."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from tree_sitter_language_pack import get_parser

if TYPE_CHECKING:
    from tree_sitter import Node, Parser, Tree


LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
}

# Directories and path components to always skip during file collection
SKIP_DIRS: frozenset[str] = frozenset({
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".git",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
})


@dataclass
class ParsedFile:
    """A file that has been parsed into a tree-sitter AST."""

    path: Path
    language: str
    source: bytes
    tree: "Tree"
    lines: list[str] = field(default_factory=list)

    def get_node_text(self, node: "Node") -> str:
        """Extract source text for a given tree-sitter node."""
        # node.start_byte and node.end_byte are byte offsets into self.source
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def get_line(self, line_number: int) -> str:
        """Return the source line at 1-based line_number, or '' if out of range."""
        idx = line_number - 1
        if 0 <= idx < len(self.lines):
            return self.lines[idx]
        return ""

    def get_snippet(self, line_start: int, line_end: int, context: int = 0) -> str:
        """Return a multi-line snippet from line_start to line_end (1-based, inclusive)."""
        start = max(0, line_start - 1 - context)
        end = min(len(self.lines), line_end + context)
        return "\n".join(self.lines[start:end])


class ASTLayer:
    """Manages tree-sitter parsers and parses source files into ParsedFile objects."""

    def __init__(self) -> None:
        self._parsers: dict[str, "Parser"] = {}

    def _get_parser(self, language: str) -> "Parser":
        if language not in self._parsers:
            self._parsers[language] = get_parser(language)  # type: ignore[arg-type]
        return self._parsers[language]

    def parse_file(self, path: Path) -> ParsedFile | None:
        """Parse a single file. Returns None if the file extension is unsupported."""
        ext = path.suffix.lower()
        language = LANGUAGE_MAP.get(ext)
        if not language:
            return None
        try:
            source = path.read_bytes()
        except (OSError, PermissionError):
            return None
        parser = self._get_parser(language)
        tree = parser.parse(source)
        lines = source.decode("utf-8", errors="replace").splitlines()
        return ParsedFile(
            path=path,
            language=language,
            source=source,
            tree=tree,
            lines=lines,
        )

    def collect_files(
        self,
        target: Path,
        extensions: list[str] | None = None,
    ) -> list[Path]:
        """Recursively collect scannable source files under target, skipping common non-source dirs."""
        exts = set(extensions or list(LANGUAGE_MAP.keys()))
        if target.is_file():
            return [target] if target.suffix.lower() in exts else []
        results: list[Path] = []
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in exts:
                continue
            # Skip hidden dirs and known non-source dirs
            if any(
                part.startswith(".") or part in SKIP_DIRS
                for part in p.parts
            ):
                continue
            results.append(p)
        return sorted(results)

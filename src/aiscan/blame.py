"""`git blame` wrapper used by the metrics command.

Runs two distinct subprocess calls: `git blame --porcelain -L N,N -- <file>`
to attribute a single line to a commit SHA, and `git log -1 --format=...` to
pull the commit metadata. Both are cached on the Blamer instance so repeated
findings on the same line or from the same commit don't re-shell.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from aiscan.attribution import CommitInfo


_UNCOMMITTED_SHA = "0" * 40
_TRAILER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.+)$")


class BlameError(Exception):
    """Raised when the target is not inside a git working tree."""


class Blamer:
    def __init__(self, repo_root: Path, invocation_cwd: Path | None = None) -> None:
        self._root = repo_root
        # Scanner records Finding.file_path relative to whatever target the
        # CLI was handed — i.e. relative to the user's cwd at invocation.
        # We capture that cwd so blame_sha can promote those paths to
        # absolute before running git blame from the repo root.
        self._invocation_cwd = (invocation_cwd or Path.cwd()).resolve()
        self._blame_cache: dict[tuple[str, int], str | None] = {}
        self._commit_cache: dict[str, CommitInfo | None] = {}

    @classmethod
    def for_target(cls, target: Path) -> Blamer:
        """Locate the enclosing git repo root, or raise BlameError."""
        target_abs = target.resolve()
        start = target_abs if target_abs.is_dir() else target_abs.parent
        try:
            out = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=start,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise BlameError(
                f"{target} is not inside a git repository "
                f"(git rev-parse failed: {exc.stderr.strip()})"
            ) from exc
        except FileNotFoundError as exc:
            raise BlameError("git executable not found on PATH") from exc
        return cls(Path(out.stdout.strip()), invocation_cwd=Path.cwd())

    @property
    def repo_root(self) -> Path:
        return self._root

    def blame_sha(self, file_path: Path, line: int) -> str | None:
        """Return the SHA of the commit that last touched `file_path:line`.

        Returns None when the line is uncommitted (staged or unstaged), the
        file is untracked, or blame otherwise fails.
        """
        # Absolute paths pass through; relative ones are resolved against
        # the CLI's invocation cwd. Git blame accepts either, and the
        # absolute form is correct regardless of which directory the blame
        # subprocess runs in.
        if file_path.is_absolute():
            resolved = file_path
        else:
            resolved = (self._invocation_cwd / file_path).resolve()
        key = (str(resolved), line)
        if key in self._blame_cache:
            return self._blame_cache[key]

        try:
            out = subprocess.run(
                ["git", "blame", "--porcelain", "-L", f"{line},{line}", "--", str(resolved)],
                cwd=self._root,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            self._blame_cache[key] = None
            return None

        first = out.stdout.splitlines()[0] if out.stdout else ""
        if not first:
            self._blame_cache[key] = None
            return None
        sha = first.split()[0]
        if sha == _UNCOMMITTED_SHA:
            self._blame_cache[key] = None
            return None
        self._blame_cache[key] = sha
        return sha

    def commit_info(self, sha: str) -> CommitInfo | None:
        """Return parsed commit metadata for `sha`, or None on lookup failure."""
        if sha in self._commit_cache:
            return self._commit_cache[sha]

        # %H sha, %an author name, %ae author email, %B raw message body.
        # Separate with NUL bytes so message content can't break parsing.
        fmt = "%H%x00%an%x00%ae%x00%B"
        try:
            out = subprocess.run(
                ["git", "log", "-1", f"--format={fmt}", sha],
                cwd=self._root,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            self._commit_cache[sha] = None
            return None

        parts = out.stdout.split("\x00", 3)
        if len(parts) < 4:
            self._commit_cache[sha] = None
            return None
        commit = CommitInfo(
            sha=parts[0],
            author_name=parts[1],
            author_email=parts[2],
            message=parts[3],
            trailers=_parse_trailers(parts[3]),
        )
        self._commit_cache[sha] = commit
        return commit


def _parse_trailers(message: str) -> list[tuple[str, str]]:
    """Extract trailer-style (Key: Value) lines from the commit message.

    Trailers are the last paragraph of the message, and that paragraph must
    be preceded by a blank line (so a single-line subject like
    ``fix: something`` does not get misread as a trailer).
    """
    lines = message.rstrip().splitlines()
    trailers: list[tuple[str, str]] = []
    hit_blank = False
    for line in reversed(lines):
        if not line.strip():
            hit_blank = True
            break
        match = _TRAILER_LINE.match(line)
        if match:
            trailers.append((match.group(1), match.group(2).strip()))
        else:
            # Non-trailer line in the trailer block — stop scanning.
            break
    if not hit_blank:
        return []
    trailers.reverse()
    return trailers

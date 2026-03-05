from __future__ import annotations

import ast
import logging
from pathlib import Path

from .models import ParsedFile

logger = logging.getLogger(__name__)


def load(target_path: str) -> list[ParsedFile]:
    """Discover all .py files under *target_path* and parse them into ASTs."""
    root = Path(target_path)
    if root.is_file() and root.suffix == ".py":
        py_files = [root]
    elif root.is_dir():
        py_files = sorted(root.rglob("*.py"))
    else:
        logger.warning("Target path %s is neither a .py file nor a directory", target_path)
        return []

    parsed: list[ParsedFile] = []
    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("Could not read %s: %s", py_file, exc)
            continue

        # split("\n"), NOT splitlines() -- splitlines() strips the trailing
        # newline which shifts the last-line index relative to ast lineno.
        source_lines = source.split("\n")

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as exc:
            logger.warning("Syntax error in %s: %s", py_file, exc)
            continue

        parsed.append(ParsedFile(
            file_path=str(py_file),
            tree=tree,
            source_lines=source_lines,
        ))

    return parsed

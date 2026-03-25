"""
TEST FIXTURE: safe_skill/utils.py
Purpose: Helper utilities for the write-doc skill.
This file should produce ZERO findings when scanned by maton.
It performs only safe, local file operations using the standard library.
"""

from __future__ import annotations

import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_EXTENSIONS = frozenset({".py", ".md", ".txt", ".yaml", ".yml", ".toml"})

DEFAULT_OUTPUT_DIR = Path("docs")

MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB — skip files larger than this


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def slugify(text: str) -> str:
    """Convert *text* to a lowercase slug suitable for use as a filename.

    Example:
        >>> slugify("Hello World!")
        'hello-world'
    """
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = text.strip("-")
    return text


def collect_source_files(root: Path, topic_keywords: list[str]) -> list[Path]:
    """Return files under *root* whose names contain any of *topic_keywords*.

    Only files with supported extensions and within the size limit are returned.
    Files outside *root* are never accessed.

    Args:
        root: The base directory to search within (must be within the project).
        topic_keywords: List of lowercase keywords to match against file stems.

    Returns:
        Sorted list of matching ``Path`` objects.
    """
    root = root.resolve()
    matches: list[Path] = []

    for candidate in root.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        try:
            if candidate.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue

        stem = candidate.stem.lower()
        if any(kw in stem for kw in topic_keywords):
            matches.append(candidate)

    return sorted(matches)


def extract_docstring(source_lines: list[str]) -> str | None:
    """Return the first triple-quoted docstring found in *source_lines*, or None.

    Args:
        source_lines: Lines of a Python source file.

    Returns:
        The raw docstring text (without the triple quotes), or ``None`` if not found.
    """
    in_docstring = False
    delimiter = ""
    buffer: list[str] = []

    for line in source_lines:
        stripped = line.strip()
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                delimiter = stripped[:3]
                content = stripped[3:]
                if content.endswith(delimiter) and len(content) > len(delimiter):
                    # Single-line docstring
                    return content[: -len(delimiter)].strip()
                in_docstring = True
                if content:
                    buffer.append(content)
        else:
            if delimiter in line:
                idx = line.index(delimiter)
                buffer.append(line[:idx])
                return "\n".join(buffer).strip()
            buffer.append(line.rstrip())

    return None


def format_section(title: str, body: str, level: int = 2) -> str:
    """Wrap *body* in a Markdown heading section.

    Args:
        title: Section heading text.
        body: Section content (Markdown).
        level: Heading level (1–6). Defaults to 2.

    Returns:
        Formatted Markdown string.
    """
    heading_prefix = "#" * max(1, min(level, 6))
    return f"{heading_prefix} {title}\n\n{body.strip()}\n"

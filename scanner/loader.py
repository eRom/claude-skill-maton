"""File loader — recursively reads text files from a target directory."""

from __future__ import annotations

from pathlib import Path

# Extensions considered as scannable text files
ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {".md", ".json", ".yaml", ".yml", ".toml", ".txt", ".py", ".sh", ".bash", ".zsh"}
)

# Directory names to skip entirely
IGNORED_DIRS: frozenset[str] = frozenset({".git", "node_modules", "__pycache__"})


def load_files(path: str) -> list[tuple[str, list[str]]]:
    """Recursively load all scannable text files under *path*.

    Args:
        path: Root directory to scan (absolute or relative).

    Returns:
        A list of ``(relative_path, lines)`` tuples, where *relative_path* is
        relative to *path* and *lines* is the file content split into lines
        (newlines stripped).  Files that cannot be decoded are silently skipped.
    """
    root = Path(path).resolve()
    results: list[tuple[str, list[str]]] = []

    for file_path in _iter_files(root):
        rel = file_path.relative_to(root).as_posix()
        lines = _read_lines(file_path)
        if lines is not None:
            results.append((rel, lines))

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_files(root: Path):
    """Yield all files under *root* that pass the extension and dir filters."""
    for entry in root.rglob("*"):
        # Skip ignored directory subtrees
        if any(part in IGNORED_DIRS for part in entry.parts):
            continue
        if not entry.is_file():
            continue
        if entry.suffix.lower() in ALLOWED_EXTENSIONS:
            yield entry


def _read_lines(file_path: Path) -> list[str] | None:
    """Return the lines of *file_path* or None if the file cannot be decoded."""
    # Quick binary sniff: reject files that contain a null byte in the first 8 KB
    try:
        chunk = file_path.read_bytes()[:8192]
    except OSError:
        return None

    if b"\x00" in chunk:
        # Almost certainly a binary file
        return None

    # Try UTF-8 first, then latin-1 as a lossless fallback
    for encoding in ("utf-8", "latin-1"):
        try:
            text = file_path.read_text(encoding=encoding, errors="strict")
            return text.splitlines()
        except (UnicodeDecodeError, OSError):
            continue

    return None

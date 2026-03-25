"""Tests for scanner.loader."""

import tempfile
from pathlib import Path

import pytest

from scanner.loader import ALLOWED_EXTENSIONS, IGNORED_DIRS, load_files


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_tree(tmp_path: Path) -> Path:
    """Build a small directory tree for loader tests."""
    # Scannable files
    (tmp_path / "README.md").write_text("# Hello\nworld\n", encoding="utf-8")
    (tmp_path / "config.yaml").write_text("key: value\n", encoding="utf-8")
    (tmp_path / "script.py").write_text("print('hi')\n", encoding="utf-8")

    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "notes.txt").write_text("line1\nline2\n", encoding="utf-8")

    # File with an ignored extension — should be skipped
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")

    # Binary file with a .txt extension — should be skipped (null byte)
    (tmp_path / "binary.txt").write_bytes(b"hello\x00world")

    # Ignored directory
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    node_dir = tmp_path / "node_modules"
    node_dir.mkdir()
    (node_dir / "lib.js").write_text("// ignored\n", encoding="utf-8")

    pycache_dir = tmp_path / "__pycache__"
    pycache_dir.mkdir()
    (pycache_dir / "mod.pyc").write_bytes(b"\x00\x01\x02\x03")

    return tmp_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_returns_list_of_tuples(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    assert isinstance(results, list)
    for item in results:
        assert isinstance(item, tuple) and len(item) == 2
        rel, lines = item
        assert isinstance(rel, str)
        assert isinstance(lines, list)


def test_finds_expected_files(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}

    assert "README.md" in found_paths
    assert "config.yaml" in found_paths
    assert "script.py" in found_paths
    assert "subdir/notes.txt" in found_paths


def test_skips_binary_extension(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}
    assert "image.png" not in found_paths


def test_skips_binary_content_with_text_extension(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}
    assert "binary.txt" not in found_paths


def test_skips_git_dir(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}
    assert not any(p.startswith(".git/") for p in found_paths)


def test_skips_node_modules(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}
    assert not any(p.startswith("node_modules/") for p in found_paths)


def test_skips_pycache(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    found_paths = {r[0] for r in results}
    assert not any("__pycache__" in p for p in found_paths)


def test_lines_content(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    md = next(r for r in results if r[0] == "README.md")
    assert md[1] == ["# Hello", "world"]


def test_relative_paths_are_posix(tmp_tree: Path) -> None:
    results = load_files(str(tmp_tree))
    for rel, _ in results:
        assert "\\" not in rel


def test_empty_directory(tmp_path: Path) -> None:
    assert load_files(str(tmp_path)) == []


def test_allowed_extensions_constants() -> None:
    assert ".md" in ALLOWED_EXTENSIONS
    assert ".py" in ALLOWED_EXTENSIONS
    assert ".png" not in ALLOWED_EXTENSIONS


def test_ignored_dirs_constants() -> None:
    assert ".git" in IGNORED_DIRS
    assert "node_modules" in IGNORED_DIRS
    assert "__pycache__" in IGNORED_DIRS

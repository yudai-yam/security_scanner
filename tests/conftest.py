"""Shared fixtures for SecAudit tests."""

import textwrap
from pathlib import Path

import pytest


@pytest.fixture
def tmp_py_file(tmp_path: Path):
    """Create a temporary Python file with given content."""

    def _create(content: str, filename: str = "test_sample.py") -> Path:
        f = tmp_path / filename
        f.write_text(textwrap.dedent(content))
        return f

    return _create


@pytest.fixture
def tmp_dir_with_files(tmp_path: Path):
    """Create a temp directory with multiple files."""

    def _create(files: dict[str, str]) -> Path:
        for name, content in files.items():
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(textwrap.dedent(content))
        return tmp_path

    return _create

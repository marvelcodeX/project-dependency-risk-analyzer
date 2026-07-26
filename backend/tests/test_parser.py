"""Tests for the requirements.txt parser."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.parsers.requirements import parse_requirements_txt


def test_parse_pinned_version():
    content = "flask==2.0.1"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "flask"
    assert deps[0].version == "2.0.1"
    assert deps[0].pinned is True


def test_parse_range_version():
    content = "requests>=2.25.0,<3.0.0"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].version == "2.25.0"
    assert deps[0].pinned is False


def test_parse_no_version():
    content = "numpy"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "numpy"
    assert deps[0].version is None
    assert deps[0].pinned is False


def test_skip_comments_and_blanks():
    content = """
# This is a comment
flask==2.0.1

# Another comment
requests>=2.25.0
    """
    deps = parse_requirements_txt(content)
    assert len(deps) == 2


def test_skip_flags():
    content = """-r base.txt
-e git+https://github.com/some/repo
--index-url https://pypi.org/simple
flask==1.0
"""
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "flask"


def test_inline_comments():
    content = "flask==2.0.1  # web framework"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "flask"
    assert deps[0].version == "2.0.1"


def test_extras():
    content = "uvicorn[standard]==0.34.0"
    deps = parse_requirements_txt(content)
    assert len(deps) == 1
    assert deps[0].name == "uvicorn"
    assert deps[0].version == "0.34.0"


def test_full_requirements_file():
    content = """# Soteria-AI test requirements
flask==2.0.1
requests>=2.25.0,<3.0.0
numpy
django>=4.0
# dev dependencies
pytest==7.0.0
-r dev-requirements.txt
"""
    deps = parse_requirements_txt(content)
    assert len(deps) == 5
    names = [d.name for d in deps]
    assert "flask" in names
    assert "requests" in names
    assert "numpy" in names
    assert "django" in names
    assert "pytest" in names

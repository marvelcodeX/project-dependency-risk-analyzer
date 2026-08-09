"""Tests for AST-based reachability analysis."""

from app.services import reachability as reach


def test_analyze_imports_extracts_top_level_modules():
    src = {
        "app.py": (
            "import os\n"
            "import flask\n"
            "from requests import get\n"
            "from django.db import models\n"
            "from . import local_thing\n"  # relative — ignored
        )
    }
    mods = reach.analyze_imports(src)
    assert "flask" in mods
    assert "requests" in mods
    assert "django" in mods  # top-level of django.db
    assert "os" in mods
    assert "local_thing" not in mods  # relative import skipped


def test_analyze_imports_skips_unparseable():
    src = {"broken.py": "import (this is not valid python"}
    assert reach.analyze_imports(src) == set()


def test_classify_unknown_without_source():
    assert reach.classify("flask", set(), has_source=False) == reach.UNKNOWN


def test_classify_reachable_when_imported():
    mods = {"flask"}
    assert reach.classify("flask", mods, has_source=True) == reach.REACHABLE


def test_classify_uses_import_name_mapping():
    # PyYAML is imported as `yaml`.
    mods = {"yaml"}
    assert reach.classify("PyYAML", mods, has_source=True) == reach.REACHABLE


def test_classify_unreachable_for_known_package():
    # flask has a confident import-name mapping and isn't imported here.
    mods = {"numpy"}
    assert reach.classify("flask", mods, has_source=True) == reach.UNREACHABLE


def test_classify_potentially_reachable_for_unknown_package():
    # Package we don't have a confident mapping for → hedge instead of claiming
    # UNREACHABLE.
    mods = {"numpy"}
    assert (
        reach.classify("some-obscure-pkg", mods, has_source=True)
        == reach.POTENTIALLY_REACHABLE
    )

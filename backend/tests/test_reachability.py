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


# ---- JavaScript / TypeScript -------------------------------------------------

import pytest  # noqa: E402

from app.schemas.scan import Dependency  # noqa: E402


@pytest.mark.parametrize(
    ("spec", "pkg"),
    [
        ("lodash", "lodash"),
        ("lodash/fp", "lodash"),
        ("@babel/core", "@babel/core"),
        ("@babel/core/lib/x.js", "@babel/core"),
        ("React", "react"),
        ("./local", None),
        ("../up", None),
        ("/abs/path", None),
        ("node:fs", None),
        ("fs", None),
        ("path", None),
        ("@/components/Button", None),  # bundler alias
        ("~/utils", None),
        ("#internal", None),  # package.json "imports" alias
        ("https://esm.sh/react", None),
    ],
)
def test_js_package_name(spec, pkg):
    assert reach.js_package_name(spec) == pkg


def test_js_import_forms():
    src = {
        "app.ts": """
import React, { useState } from 'react'
import * as d3 from "d3"
import 'normalize.css'
import {
  a,
  b,
} from '@scope/multi-line'
export { x } from 'reexported'
export * from "star-export"
const _ = require('lodash/fp')
const lazy = await import('lazy-loaded')
import type { Foo } from 'types-only'
export type { Bar } from 'also-types-only'
import { helper } from './helper'
import fs from 'node:fs'
// import commented from 'commented-out'
/* require('block-commented') */
const url = "https://example.com/x"  // not an import
"""
    }
    assert reach.analyze_sources(src) == {
        "npm": {
            "react", "d3", "normalize.css", "@scope/multi-line", "reexported",
            "star-export", "lodash", "lazy-loaded",
        }
    }


def test_languages_are_tracked_separately():
    assert reach.analyze_sources({"a.py": "import flask"}) == {"PyPI": {"flask"}}
    assert reach.analyze_sources({"a.js": "require('x')"}) == {"npm": {"x"}}
    # .d.ts declarations and non-source files are ignored entirely.
    assert reach.analyze_sources({"t.d.ts": "import 'x'", "README.md": "import x"}) == {}
    # Pasted code without a name: Python if it parses, otherwise JavaScript.
    assert reach.analyze_sources({"pasted": "import flask"}) == {"PyPI": {"flask"}}
    assert reach.analyze_sources({"pasted": "import x from 'y'"}) == {"npm": {"y"}}


def test_npm_classification_is_certain():
    assert reach.classify("lodash", {"lodash"}, True, "npm") == reach.REACHABLE
    assert reach.classify("chalk", {"lodash"}, True, "npm") == reach.UNREACHABLE
    assert reach.classify("chalk", set(), False, "npm") == reach.UNKNOWN
    assert reach.classify("x", {"x"}, True, "Go") == reach.UNKNOWN


def _npm(name, direct, depends_on=(), version="1.0.0"):
    return Dependency(name=name, version=version, ecosystem="npm", direct=direct,
                      depends_on=list(depends_on))


def test_reachability_propagates_through_the_graph():
    deps = [
        _npm("express", True, ["body-parser@1.0.0"]),
        _npm("body-parser", False, ["qs@1.0.0"]),
        _npm("qs", False),
        _npm("eslint", True, ["chalk@1.0.0"]),
        _npm("chalk", False),
        _npm("shared", False),
    ]
    deps[0].depends_on.append("shared@1.0.0")
    deps[3].depends_on.append("shared@1.0.0")
    got = reach.classify_all(deps, {"npm": {"express"}})
    assert got == {
        "express@1.0.0": reach.REACHABLE,
        "body-parser@1.0.0": reach.POTENTIALLY_REACHABLE,  # via express
        "qs@1.0.0": reach.POTENTIALLY_REACHABLE,  # two hops
        "eslint@1.0.0": reach.UNREACHABLE,  # never imported
        "chalk@1.0.0": reach.UNREACHABLE,  # only under eslint
        "shared@1.0.0": reach.POTENTIALLY_REACHABLE,  # one path is enough
    }


def test_transitive_without_graph_is_never_unreachable():
    # go.mod-style: indirect modules, no edges.
    deps = [
        Dependency(name="a", version="1", ecosystem="npm", direct=True),
        Dependency(name="b", version="1", ecosystem="npm", direct=False),
    ]
    got = reach.classify_all(deps, {"npm": {"zzz"}})
    assert got == {"a@1": reach.UNREACHABLE, "b@1": reach.POTENTIALLY_REACHABLE}


def test_no_source_for_that_language_stays_unknown():
    deps = [_npm("express", True)]
    assert reach.classify_all(deps, {"PyPI": {"flask"}}) == {
        "express@1.0.0": reach.UNKNOWN
    }

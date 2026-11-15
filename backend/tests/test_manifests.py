"""Tests for the npm / Go / Maven parsers and format detection."""

import pytest

from app.parsers import ManifestError, detect_format, parse_manifest
from app.parsers.go_mod import parse_go_mod
from app.parsers.maven import parse_pom_xml
from app.parsers.npm import parse_package_json, parse_package_lock


def _by_name(deps):
    return {d.name: d for d in deps}


# ---- package.json ----------------------------------------------------------


def test_package_json_ranges_and_pins():
    content = """{
      "name": "app",
      "dependencies": {
        "lodash": "^4.17.20",
        "express": "4.18.2",
        "react": "~18.2.0",
        "left-pad": "1.x",
        "chalk": ">=2.0.0 <5",
        "debug": "*",
        "local": "file:../local",
        "fork": "github:user/repo",
        "aliased": "npm:minimist@^1.2.5"
      },
      "devDependencies": {"jest": "29.7.0", "lodash": "^1.0.0"}
    }"""
    deps = _by_name(parse_package_json(content))
    assert deps["lodash"].version == "4.17.20"  # dependencies wins over dev
    assert deps["lodash"].pinned is False
    assert deps["express"].version == "4.18.2" and deps["express"].pinned
    assert deps["react"].version == "18.2.0"
    assert deps["left-pad"].version == "1.0.0"
    assert deps["chalk"].version == "2.0.0"
    assert deps["debug"].version is None
    assert deps["local"].version is None
    assert deps["fork"].version is None
    assert deps["minimist"].version == "1.2.5"  # alias resolves to real pkg
    assert deps["jest"].pinned is True
    assert all(d.ecosystem == "npm" for d in deps.values())


def test_package_json_invalid_json():
    with pytest.raises(ManifestError):
        parse_package_json("{oops")


# ---- package-lock.json -----------------------------------------------------


def test_package_lock_v3_includes_transitive_and_dedupes():
    content = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@babel/core": {"version": "7.23.0"},
        "node_modules/a/node_modules/lodash": {"version": "3.10.1"},
        "node_modules/b/node_modules/lodash": {"version": "3.10.1"},
        "node_modules/linked": {"link": true, "resolved": "packages/linked"},
        "packages/workspace-a": {"version": "0.1.0"}
      }
    }"""
    deps = parse_package_lock(content)
    pairs = sorted((d.name, d.version) for d in deps)
    assert pairs == [
        ("@babel/core", "7.23.0"),
        ("lodash", "3.10.1"),
        ("lodash", "4.17.20"),
    ]
    assert all(d.pinned for d in deps)


def test_package_lock_v1_nested():
    content = """{
      "lockfileVersion": 1,
      "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
        "gitdep": {"version": "git+https://github.com/x/y.git#abc"}
      }
    }"""
    pairs = sorted((d.name, d.version) for d in parse_package_lock(content))
    assert pairs == [("a", "1.0.0"), ("b", "2.0.0")]


# ---- go.mod ----------------------------------------------------------------


GO_MOD = """module example.com/app

go 1.21

require github.com/gin-gonic/gin v1.9.0

require (
\tgolang.org/x/net v0.17.0 // indirect
\tgithub.com/old/mod v1.0.0
\tgithub.com/local/mod v0.1.0
)

replace github.com/old/mod => github.com/new/mod v1.2.0
replace github.com/local/mod => ../mod
"""


def test_go_mod_requires_and_replaces():
    deps = _by_name(parse_go_mod(GO_MOD))
    assert deps["github.com/gin-gonic/gin"].version == "1.9.0"  # "v" stripped
    assert deps["golang.org/x/net"].version == "0.17.0"
    assert deps["github.com/new/mod"].version == "1.2.0"
    assert "github.com/old/mod" not in deps
    assert deps["github.com/local/mod"].version is None
    assert deps["github.com/gin-gonic/gin"].ecosystem == "Go"
    assert deps["github.com/gin-gonic/gin"].pinned is True


# ---- pom.xml ---------------------------------------------------------------


POM = """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
  </parent>
  <artifactId>app</artifactId>
  <properties>
    <jackson.version>2.13.0</jackson.version>
    <log4j.version>${log4j.base}</log4j.version>
    <log4j.base>2.14.1</log4j.base>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>${project.groupId}</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>[4.12,5.0)</version>
    </dependency>
    <dependency>
      <groupId>org.x</groupId>
      <artifactId>unresolved</artifactId>
      <version>${missing.prop}</version>
    </dependency>
  </dependencies>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.yaml</groupId>
        <artifactId>snakeyaml</artifactId>
        <version>1.30</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>"""


def test_pom_resolves_properties_and_ranges():
    deps = _by_name(parse_pom_xml(POM))
    assert deps["com.fasterxml.jackson.core:jackson-databind"].version == "2.13.0"
    assert deps["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert deps["com.example:sibling"].version == "2.0.0"  # from <parent>
    assert deps["org.springframework:spring-core"].version is None
    assert deps["junit:junit"].version == "4.12"
    assert deps["junit:junit"].pinned is False
    assert deps["org.x:unresolved"].version is None
    assert deps["org.yaml:snakeyaml"].version == "1.30"
    assert all(d.ecosystem == "Maven" for d in deps.values())


def test_pom_rejects_entity_expansion():
    evil = """<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>
<project><dependencies/></project>"""
    with pytest.raises(ManifestError):
        parse_pom_xml(evil)


def test_pom_invalid_xml():
    with pytest.raises(ManifestError):
        parse_pom_xml("<project><dependencies>")


# ---- detection -------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "content", "expected"),
    [
        ("requirements.txt", "flask", "requirements.txt"),
        ("requirements-dev.txt", "flask", "requirements.txt"),
        ("sub/dir/package.json", "{}", "package.json"),
        ("npm-shrinkwrap.json", "{}", "package-lock.json"),
        ("pasted", '{"lockfileVersion": 3}', "package-lock.json"),
        ("pasted", '{"dependencies": {}}', "package.json"),
        ("pasted", "module x\n", "go.mod"),
        ("pasted", "<project></project>", "pom.xml"),
        ("pasted", "flask==1.0", "requirements.txt"),
        ("", "flask==1.0", "requirements.txt"),
    ],
)
def test_detect_format(filename, content, expected):
    assert detect_format(filename, content) == expected


def test_detect_format_unsupported():
    with pytest.raises(ManifestError):
        detect_format("Gemfile.lock", "GEM\n")


def test_parse_manifest_dispatches():
    deps = parse_manifest("module x\nrequire a.com/b v1.0.0\n", "go.mod")
    assert deps[0].ecosystem == "Go"


# ---- dependency graph ------------------------------------------------------


def test_package_lock_v3_graph_direct_depth_and_edges():
    content = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app", "dependencies": {"express": "^4"},
             "devDependencies": {"debug": "^4"}},
        "node_modules/express": {"version": "4.18.2",
             "dependencies": {"body-parser": "1.20.1", "debug": "2.6.9"}},
        "node_modules/express/node_modules/debug": {"version": "2.6.9",
             "dependencies": {"ms": "2.0.0"}},
        "node_modules/body-parser": {"version": "1.20.1",
             "dependencies": {"debug": "2.6.9", "ms": "2.0.0"}},
        "node_modules/body-parser/node_modules/debug": {"version": "2.6.9",
             "dependencies": {"ms": "2.0.0"}},
        "node_modules/debug": {"version": "4.3.4", "dependencies": {"ms": "2.1.2"}},
        "node_modules/ms": {"version": "2.1.2"},
        "node_modules/express/node_modules/ms": {"version": "2.0.0"},
        "node_modules/body-parser/node_modules/ms": {"version": "2.0.0"}
      }
    }"""
    deps = {d.key: d for d in parse_package_lock(content)}

    assert deps["express@4.18.2"].direct is True and deps["express@4.18.2"].depth == 0
    assert deps["debug@4.3.4"].direct is True  # devDependency of the root
    assert deps["body-parser@1.20.1"].direct is False
    assert deps["body-parser@1.20.1"].depth == 1
    # Nested copies resolve to their nearest node_modules, merged per version.
    assert deps["debug@2.6.9"].depth == 1
    assert deps["ms@2.0.0"].depth == 2
    assert deps["ms@2.1.2"].depth == 1  # under the hoisted debug@4
    assert deps["express@4.18.2"].depends_on == ["body-parser@1.20.1", "debug@2.6.9"]
    assert deps["debug@4.3.4"].depends_on == ["ms@2.1.2"]


def test_package_lock_workspaces_count_as_roots():
    content = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "mono", "workspaces": ["packages/*"]},
        "packages/web": {"name": "web", "dependencies": {"react": "^18"}},
        "node_modules/web": {"link": true, "resolved": "packages/web"},
        "node_modules/react": {"version": "18.2.0", "dependencies": {"loose-envify": "^1"}},
        "node_modules/loose-envify": {"version": "1.4.0"}
      }
    }"""
    deps = {d.key: d for d in parse_package_lock(content)}
    assert set(deps) == {"react@18.2.0", "loose-envify@1.4.0"}
    assert deps["react@18.2.0"].direct is True
    assert deps["loose-envify@1.4.0"].depth == 1


def test_package_lock_v1_has_edges_but_unknown_directness():
    content = """{
      "lockfileVersion": 1,
      "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "^2"}},
        "b": {"version": "2.0.0"}
      }
    }"""
    deps = {d.key: d for d in parse_package_lock(content)}
    assert deps["a@1.0.0"].depends_on == ["b@2.0.0"]
    assert deps["a@1.0.0"].direct is None and deps["a@1.0.0"].depth is None


def test_go_mod_marks_indirect_modules():
    deps = _by_name(parse_go_mod(GO_MOD))
    assert deps["github.com/gin-gonic/gin"].direct is True
    assert deps["golang.org/x/net"].direct is False  # "// indirect"
    assert deps["golang.org/x/net"].depth is None


def test_pom_dependency_management_is_not_direct():
    deps = _by_name(parse_pom_xml(POM))
    assert deps["junit:junit"].direct is True
    assert deps["org.yaml:snakeyaml"].direct is False


def test_package_json_deps_are_direct():
    deps = parse_package_json('{"dependencies": {"lodash": "^4.17.20"}}')
    assert deps[0].direct is True and deps[0].depth == 0

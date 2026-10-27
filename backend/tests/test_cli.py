"""Tests for the CI command-line scanner (OSV/KEV mocked)."""

import json
from pathlib import Path

import pytest

import app.services.scanner as scanner_mod
from app import cli
from app.schemas.scan import Vulnerability
from app.services.osv_client import OsvError


async def _fake_many(deps):
    out = []
    for d in deps:
        if d.name == "flask":
            out.append([
                Vulnerability(
                    id="GHSA-flask", summary="Flask flaw", severity="HIGH",
                    cvss_score=7.5, fixed_version="2.3.2", aliases=["CVE-2023-30861"],
                )
            ])
        elif d.name == "lodash":
            out.append([Vulnerability(id="GHSA-lodash", summary="Proto", severity="LOW",
                                      cvss_score=2.0, fixed_version="4.17.21")])
        else:
            out.append([])
    return out


async def _fake_kev():
    return set()


@pytest.fixture(autouse=True)
def _mock_network(monkeypatch):
    monkeypatch.setattr(scanner_mod, "query_osv_many", _fake_many)
    monkeypatch.setattr(scanner_mod, "get_kev_cve_ids", _fake_kev)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)


@pytest.fixture
def repo(tmp_path, monkeypatch) -> Path:
    """A small multi-ecosystem repo; cwd is set to it like in CI."""
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "requirements.txt").write_text("flask==2.0.1\nnumpy==1.26.0\n")
    (tmp_path / "backend" / "app.py").write_text("import flask\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text('{"dependencies": {"lodash": "^4.0.0"}}')
    (tmp_path / "web" / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}'
    )
    # Must be ignored: dependencies' own manifests.
    nm = tmp_path / "web" / "node_modules" / "x"
    nm.mkdir(parents=True)
    (nm / "package.json").write_text('{"dependencies": {"evil": "1.0.0"}}')
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "requirements.txt").write_text("evil==1.0\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_discovery_skips_vendored_and_prefers_lockfile(repo):
    found = [p.as_posix() for p in cli.discover_manifests([Path(".")])]
    assert found == ["backend/requirements.txt", "web/package-lock.json"]


def test_explicit_missing_path_is_an_error(repo, capsys):
    assert cli.main(["scan", "nope.txt"]) == cli.EXIT_ERROR
    assert "No such file" in capsys.readouterr().err


def test_no_manifests_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan"]) == cli.EXIT_ERROR
    assert "No supported manifests" in capsys.readouterr().err


def test_report_only_by_default(repo, capsys):
    assert cli.main(["scan"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "scanned 2 manifest(s)" in out
    assert "GHSA-flask" in out and "GHSA-lodash" in out
    assert "report only" in out


@pytest.mark.parametrize(
    ("fail_on", "code"),
    [("critical", cli.EXIT_OK), ("high", cli.EXIT_FAIL), ("low", cli.EXIT_FAIL)],
)
def test_fail_on_threshold(repo, fail_on, code):
    # flask: CVSS 7.5 → 30 + 10 (unknown reach) + 0 + 3 = 43 → HIGH
    assert cli.main(["scan", "-q", "--fail-on", fail_on]) == code


def test_reachability_from_source(repo, capsys):
    cli.main(["scan", "backend", "--source", "backend", "-o", "json=-", "-q"])
    data = json.loads(capsys.readouterr().out)
    vuln = data[0]["results"][0]["vulnerabilities"][0]
    assert vuln["reachability"] == "REACHABLE"


def test_writes_reports_and_sarif_has_per_manifest_locations(repo):
    code = cli.main([
        "scan", "-q",
        "-o", "sarif=out/soteria.sarif",
        "-o", "markdown=out/summary.md",
        "-o", "cyclonedx=out/bom.cdx.json",
        "-o", "html=out/report.html",
    ])
    assert code == cli.EXIT_OK
    sarif = json.loads((repo / "out" / "soteria.sarif").read_text())
    assert len(sarif["runs"]) == 1
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif["runs"][0]["results"]
    }
    assert uris == {"backend/requirements.txt", "web/package-lock.json"}
    md = (repo / "out" / "summary.md").read_text()
    assert "backend/requirements.txt, web/package-lock.json" in md
    bom = json.loads((repo / "out" / "bom.cdx.json").read_text())
    assert {c["name"] for c in bom["components"]} == {"flask", "numpy", "lodash"}
    assert "scan #" not in (repo / "out" / "report.html").read_text()


def test_stdout_report_moves_summary_to_stderr(repo, capsys):
    cli.main(["scan", "-o", "markdown=-"])
    captured = capsys.readouterr()
    assert captured.out.startswith("# Soteria-AI dependency report")
    assert "scanned 2 manifest(s)" in captured.err


def test_github_outputs(repo, monkeypatch):
    out_file = repo / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    cli.main(["scan", "-q", "--fail-on", "high"])
    outputs = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
    assert outputs == {
        "risk-score": "43", "risk-level": "HIGH", "findings": "2", "failed": "true",
    }


def test_osv_outage_exits_2(repo, monkeypatch, capsys):
    async def _down(deps):
        raise OsvError("connection refused")

    monkeypatch.setattr(scanner_mod, "query_osv_many", _down)
    assert cli.main(["scan"]) == cli.EXIT_ERROR
    assert "unavailable" in capsys.readouterr().err


def test_bad_manifest_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text("{broken")
    assert cli.main(["scan"]) == cli.EXIT_ERROR
    assert "package.json" in capsys.readouterr().err


def test_bad_output_spec_is_a_usage_error(repo):
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", "-o", "pdf=x.pdf"])
    assert exc.value.code == 2


def test_unexpected_crash_exits_2_not_1(repo, monkeypatch, capsys):
    def _boom(*a, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(cli, "render", _boom)
    assert cli.main(["scan", "-q", "-o", "json=out.json"]) == cli.EXIT_ERROR
    assert "kaboom" in capsys.readouterr().err

"""Command-line scanner for CI pipelines.

    python -m app.cli scan [PATH ...] [--source DIR] [-o FORMAT=FILE ...]
                           [--fail-on LEVEL]

PATHs may be manifests or directories (searched recursively for supported
manifests). Reports are written with ``-o``, e.g. ``-o sarif=soteria.sarif``
or ``-o markdown=-`` for stdout. Nothing is stored in the database.

Exit codes: 0 = OK, 1 = a finding met ``--fail-on``, 2 = scan error.

When run under GitHub Actions (``$GITHUB_OUTPUT`` set), the risk score,
level, finding count and pass/fail result are also exported as step outputs.
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from app import __version__
from app.parsers import ManifestError
from app.reports import ReportFormat, render_report
from app.reports.common import findings
from app.reports.sarif import render_sarif
from app.schemas.scan import ScanResponse
from app.services.osv_client import OsvError
from app.services.risk import risk_level
from app.services.scanner import scan_manifest

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2

LEVELS = ("critical", "high", "medium", "low", "none")
_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Directories never worth descending into (dependencies, envs, build output).
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "site-packages", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", "dist", "build", "target", "vendor", ".next", ".idea",
}

_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_SOURCE_BYTES = 50 * 1024 * 1024


class CliError(Exception):
    """A user-facing error; printed without a traceback."""


# ---- discovery -------------------------------------------------------------


def _is_manifest(path: Path) -> bool:
    name = path.name.lower()
    if name in ("package-lock.json", "npm-shrinkwrap.json", "go.mod", "pom.xml"):
        return True
    if name.endswith(".txt") and (
        name.startswith("requirements") or path.parent.name == "requirements"
    ):
        return True
    return name == "package.json"


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def discover_manifests(paths: list[Path]) -> list[Path]:
    """Expand directories into the manifests they contain.

    ``package.json`` is skipped when a lockfile sits next to it: the lockfile
    has exact versions and the full transitive tree.
    """
    found: list[Path] = []
    for p in paths:
        if p.is_file():
            found.append(p)
        elif p.is_dir():
            found.extend(f for f in _walk(p) if _is_manifest(f))
        else:
            raise CliError(f"No such file or directory: {p}")

    locked_dirs = {
        f.parent.resolve()
        for f in found
        if f.name in ("package-lock.json", "npm-shrinkwrap.json")
    }
    out, seen = [], set()
    for f in found:
        key = f.resolve()
        if key in seen:
            continue
        seen.add(key)
        if f.name == "package.json" and f.parent.resolve() in locked_dirs:
            continue
        out.append(f)
    return out


def collect_sources(dirs: list[Path]) -> dict[str, str]:
    """Read Python files under ``dirs`` for import-reachability analysis."""
    sources: dict[str, str] = {}
    total = 0
    for d in dirs:
        if not d.is_dir():
            raise CliError(f"--source must be a directory: {d}")
        for f in _walk(d):
            if f.suffix != ".py":
                continue
            try:
                size = f.stat().st_size
                if size > _MAX_FILE_BYTES or total + size > _MAX_SOURCE_BYTES:
                    continue
                sources[_display(f)] = f.read_text(encoding="utf-8", errors="replace")
                total += size
            except OSError:
                continue
    return sources


def _display(path: Path) -> str:
    """Repo-relative POSIX path when possible (what SARIF locations expect)."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


# ---- scanning & output -----------------------------------------------------


async def scan_all(manifests: list[Path], sources: dict[str, str]) -> list[ScanResponse]:
    scans = []
    now = datetime.now(timezone.utc)
    for m in manifests:
        if m.stat().st_size > _MAX_FILE_BYTES:
            raise CliError(f"{m} is larger than 5 MB")
        try:
            content = m.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            raise CliError(f"{m} is not valid UTF-8 text")
        name = _display(m)
        try:
            scan = await scan_manifest(content, name, sources)
        except ManifestError as exc:
            raise CliError(f"{name}: {exc}")
        scan.created_at = now
        scans.append(scan)
    return scans


def combine(scans: list[ScanResponse]) -> ScanResponse:
    """Merge several manifest scans into one result for whole-project reports."""
    if len(scans) == 1:
        return scans[0]
    worst = max((s.risk_score for s in scans), default=0)
    return ScanResponse(
        filename=", ".join(s.filename for s in scans),
        created_at=scans[0].created_at if scans else None,
        total_dependencies=sum(s.total_dependencies for s in scans),
        vulnerable_dependencies=sum(s.vulnerable_dependencies for s in scans),
        risk_score=worst,
        risk_level=risk_level(worst),
        results=[r for s in scans for r in s.results],
    )


def render(fmt: ReportFormat, scans: list[ScanResponse]) -> str:
    if fmt is ReportFormat.sarif:
        return json.dumps(render_sarif(scans), indent=2)  # keeps per-file locations
    if fmt is ReportFormat.json:
        return json.dumps(
            [s.model_dump(mode="json") for s in scans], indent=2
        )
    return render_report(combine(scans), fmt).body


def parse_output(spec: str) -> tuple[ReportFormat, str]:
    fmt, sep, dest = spec.partition("=")
    if not sep or not dest:
        raise argparse.ArgumentTypeError(
            f"expected FORMAT=FILE (e.g. sarif=out.sarif), got {spec!r}"
        )
    try:
        return ReportFormat(fmt.strip().lower()), dest
    except ValueError:
        choices = ", ".join(f.value for f in ReportFormat)
        raise argparse.ArgumentTypeError(f"unknown format {fmt!r} (choose: {choices})")


def summary_text(scans: list[ScanResponse], fail_on: str, failed: bool) -> str:
    merged = combine(scans)
    items = findings(merged)
    lines = [
        f"Soteria-AI {__version__} — scanned {len(scans)} manifest(s): "
        + (", ".join(s.filename for s in scans) or "none"),
        f"Dependencies: {merged.total_dependencies} · vulnerable: "
        f"{merged.vulnerable_dependencies} · findings: {len(items)} · "
        f"risk: {merged.risk_score}/100 ({merged.risk_level})",
    ]
    if items:
        lines.append("")
        lines.append(f"{'RISK':>4}  {'LEVEL':<8}  {'PACKAGE':<40}  {'ADVISORY':<22}  FIX")
        for f in items[:25]:
            v = f.vuln
            kev = "  [KEV]" if v.in_cisa_kev else ""
            lines.append(
                f"{v.risk_score:>4}  {v.risk_level:<8}  {f.package_label[:40]:<40}  "
                f"{v.id[:22]:<22}  {v.fixed_version or '-'}{kev}"
            )
        if len(items) > 25:
            lines.append(f"... and {len(items) - 25} more (use -o to export all)")
    lines.append("")
    if fail_on == "none":
        lines.append("Result: report only (--fail-on none)")
    else:
        lines.append(
            f"Result: {'FAIL' if failed else 'PASS'} "
            f"(--fail-on {fail_on}: fails on {fail_on.upper()} risk or worse)"
        )
    return "\n".join(lines)


def threshold_exceeded(scans: list[ScanResponse], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    limit = _RANK[fail_on.upper()]
    return any(
        _RANK.get(v.risk_level, 0) >= limit
        for s in scans
        for r in s.results
        for v in r.vulnerabilities
    )


def write_github_outputs(scans: list[ScanResponse], failed: bool) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    merged = combine(scans)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"risk-score={merged.risk_score}\n")
        fh.write(f"risk-level={merged.risk_level}\n")
        fh.write(f"findings={len(findings(merged))}\n")
        fh.write(f"failed={'true' if failed else 'false'}\n")


# ---- entry point -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soteria", description="Scan dependency manifests for known vulnerabilities."
    )
    parser.add_argument("--version", action="version", version=f"soteria {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan manifests and write reports")
    scan.add_argument(
        "paths", nargs="*", type=Path, default=[Path(".")],
        help="manifest files or directories to search (default: .)",
    )
    scan.add_argument(
        "--source", action="append", type=Path, default=[], metavar="DIR",
        help="Python source directory for reachability analysis (repeatable)",
    )
    scan.add_argument(
        "-o", "--output", action="append", type=parse_output, default=[],
        metavar="FORMAT=FILE",
        help="write a report: json, sarif, cyclonedx, markdown or html; "
        "FILE '-' means stdout (repeatable)",
    )
    scan.add_argument(
        "--fail-on", choices=LEVELS, default="none",
        help="exit 1 if any finding's risk level is at or above this (default: none)",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="no summary output")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        # Never let a crash look like exit 1 ("threshold met") to CI.
        import traceback

        traceback.print_exc()
        print("soteria: error: unexpected failure (see traceback)", file=sys.stderr)
        return EXIT_ERROR


def _main(argv: list[str] | None) -> int:
    args = build_parser().parse_args(argv)
    to_stdout = any(dest == "-" for _, dest in args.output)
    log = sys.stderr if to_stdout else sys.stdout

    try:
        manifests = discover_manifests(args.paths)
        if not manifests:
            raise CliError(
                "No supported manifests found (requirements*.txt, package.json, "
                "package-lock.json, go.mod, pom.xml)"
            )
        sources = collect_sources(args.source)
        scans = asyncio.run(scan_all(manifests, sources))
    except CliError as exc:
        print(f"soteria: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OsvError as exc:
        print(f"soteria: error: vulnerability database unavailable: {exc}", file=sys.stderr)
        return EXIT_ERROR

    failed = threshold_exceeded(scans, args.fail_on)

    for fmt, dest in args.output:
        body = render(fmt, scans)
        if dest == "-":
            sys.stdout.write(body if body.endswith("\n") else body + "\n")
        else:
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_text(body, encoding="utf-8")

    write_github_outputs(scans, failed)
    if not args.quiet:
        print(summary_text(scans, args.fail_on, failed), file=log)
    return EXIT_FAIL if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

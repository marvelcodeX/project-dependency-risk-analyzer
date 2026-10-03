"""Parser for Maven ``pom.xml`` files.

Reads ``<dependencies>`` and ``<dependencyManagement>``, resolving
``${property}`` placeholders from ``<properties>`` and the project/parent
coordinates. Versions inherited from a parent POM or BOM that isn't in this
file can't be resolved and are left as ``None``.

Parsing uses ``defusedxml``: the input is untrusted, and stock XML parsers
are open to entity-expansion attacks.
"""

import re
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.parsers.errors import ManifestError
from app.schemas.scan import Dependency

ECOSYSTEM = "Maven"

_PROP_RE = re.compile(r"\$\{([^}]+)\}")


def _local(tag: str) -> str:
    """Strip the ``{namespace}`` prefix from an element tag."""
    return tag.rsplit("}", 1)[-1]


def _child(el: Element | None, name: str) -> Element | None:
    if el is None:
        return None
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el: Element | None, name: str) -> str | None:
    c = _child(el, name)
    return c.text.strip() if c is not None and c.text else None


def _resolve(value: str | None, props: dict[str, str]) -> str | None:
    """Substitute ``${...}`` placeholders; ``None`` if any stay unresolved."""
    if value is None:
        return None
    for _ in range(5):  # properties may reference other properties
        if "${" not in value:
            return value
        value = _PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return None if "${" in value else value


def _version_from_spec(spec: str) -> tuple[str | None, bool]:
    """Return ``(version, pinned)``. Ranges like ``[1.0,2.0)`` use the floor."""
    spec = spec.strip()
    if not spec:
        return None, False
    if spec[0] in "[(":
        # Range: "[1.2.3]" is an exact pin; otherwise take the lower bound.
        inner = spec.strip("[]()")
        lower = inner.split(",", 1)[0].strip()
        exact = spec.startswith("[") and spec.endswith("]") and "," not in inner
        return (lower or None), exact
    return spec, True  # Maven "soft" requirement — the version actually used


def parse_pom_xml(content: str) -> list[Dependency]:
    """Parse dependencies from a ``pom.xml``."""
    try:
        root = ET.fromstring(content)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ManifestError(f"Invalid pom.xml: {exc}") from exc
    if _local(root.tag) != "project":
        raise ManifestError("Expected a <project> root element")

    parent = _child(root, "parent")
    props: dict[str, str] = {}
    for key, el, name in (
        ("project.groupId", root, "groupId"),
        ("project.version", root, "version"),
        ("project.parent.groupId", parent, "groupId"),
        ("project.parent.version", parent, "version"),
    ):
        val = _text(el, name)
        if val:
            props[key] = val
    # A child POM inherits groupId/version from its parent when omitted.
    props.setdefault("project.groupId", props.get("project.parent.groupId", ""))
    props.setdefault("project.version", props.get("project.parent.version", ""))
    for alias in ("groupId", "version"):  # deprecated ${pom.x} / ${x} forms
        props[f"pom.{alias}"] = props[f"project.{alias}"]
    properties = _child(root, "properties")
    if properties is not None:
        for p in properties:
            if p.text:
                props[_local(p.tag)] = p.text.strip()

    dep_lists = [_child(root, "dependencies")]
    dep_lists.append(_child(_child(root, "dependencyManagement"), "dependencies"))

    deps: list[Dependency] = []
    seen: set[str] = set()
    for dep_list in dep_lists:
        if dep_list is None:
            continue
        for d in dep_list:
            if _local(d.tag) != "dependency":
                continue
            group = _resolve(_text(d, "groupId"), props)
            artifact = _resolve(_text(d, "artifactId"), props)
            if not group or not artifact:
                continue
            name = f"{group}:{artifact}"
            if name in seen:
                continue
            seen.add(name)
            raw = _text(d, "version") or ""
            resolved = _resolve(raw, props) if raw else None
            version, pinned = _version_from_spec(resolved) if resolved else (None, False)
            deps.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=ECOSYSTEM,
                    pinned=pinned,
                    raw_spec=raw,
                )
            )
    return deps

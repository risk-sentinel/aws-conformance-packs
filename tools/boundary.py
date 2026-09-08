"""Resolve a boundary's CDEF list to the set of AWS services it actually runs.

#20's premise: the domain split is a TAXONOMY split forced by the 130-rule cap;
a boundary split answers a different question -- does this rule apply to what we
actually deployed. They compose. Domain catalogs define the rule universe; the
boundary selects the subset with resources to evaluate.

WHY A CDEF CANNOT ALWAYS BE RESOLVED, AND WHY THAT IS AN ERROR
--------------------------------------------------------------
awslabs' service CDEFs carry a `service-id` prop and resolve exactly.

Custom boundary CDEFs -- the ones an organization writes per component, like
sparc-iac's `component-definition-alb.json` -- carry a `type: service` and a
human title, and NO props at all. Matching those by title is guesswork of
exactly the kind that resolved `AWS::RDS::DBCluster` to DocDB.

So an unresolvable CDEF is a hard ERROR naming the file, not a silent skip.
Skipping it would shrink the boundary, which shrinks the pack, which removes
rules nobody decided to remove -- and the smaller pack would look like a
deliberate scoping decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


class BoundaryError(Exception):
    """A boundary that cannot be resolved without guessing."""


@dataclass(frozen=True)
class Boundary:
    services: frozenset[str]          # service ids present in the boundary
    sources: dict[str, str]           # service id -> where it came from

    @property
    def declared(self) -> bool:
        return bool(self.services)


def _components(doc: dict) -> list[dict]:
    cd = doc.get("component-definition", doc)
    return [c for c in (cd.get("components") or []) if c.get("type") == "service"]


def from_cdef_dir(path: Path, known: set[str]) -> tuple[set[str], list[str]]:
    """Read service ids out of a directory of OSCAL component definitions."""
    if not path.is_dir():
        raise BoundaryError(f"{path} is not a directory")
    found: set[str] = set()
    unresolved: list[str] = []
    files = sorted(list(path.glob("*.json")) + list(path.glob("*.oscal.json")))
    if not files:
        raise BoundaryError(
            f"{path} contains no component definitions. An empty boundary would "
            f"exclude every rule, which is not a safe reading of 'not configured'.")
    for f in sorted(set(files)):
        try:
            doc = json.loads(f.read_text())
        except json.JSONDecodeError as exc:
            raise BoundaryError(f"{f.name} is not valid JSON: {exc}") from exc
        for c in _components(doc):
            props = {p["name"]: p["value"] for p in (c.get("props") or [])
                     if p.get("name") != "label"}
            sid = props.get("service-id")
            if sid and sid in known:
                found.add(sid)
                continue
            # Try the title only as an EXACT match against a known service id.
            # Anything looser is the guesswork that produced RDS -> DocDB.
            title = c.get("title", "")
            if title in known:
                found.add(title)
                continue
            unresolved.append(f"{f.name}: {title or '(untitled)'}")
    return found, unresolved


def resolve(cfg: dict, known: set[str], root: Path = Path(".")) -> Boundary:
    """Build the boundary from inputs.yml.

    No boundary declared means NO FILTERING, not an empty boundary. Reading
    "unconfigured" as "nothing is in scope" would silently drop every rule.
    """
    b = (cfg.get("boundary") or {})
    explicit = {str(s) for s in (b.get("services") or [])}
    bad = explicit - known
    if bad:
        raise BoundaryError(
            f"boundary.services names {sorted(bad)}, which the service availability "
            f"index does not contain. Use the `service-id` values in "
            f"vendor/aws-services/aws-service-availability.json.")

    sources = {s: "inputs.yml boundary.services" for s in explicit}
    services = set(explicit)

    if d := b.get("cdef_dir"):
        found, unresolved = from_cdef_dir(root / d, known)
        if unresolved:
            raise BoundaryError(
                "these component definitions declare a service but carry no "
                "`service-id` prop that resolves, so the boundary cannot be built "
                "without guessing:\n  " + "\n  ".join(unresolved) +
                "\n\nList them explicitly under `boundary.services` instead. Skipping "
                "them would shrink the boundary, and a smaller pack would look like a "
                "deliberate scoping decision rather than an unresolved input.")
        for s in found:
            sources.setdefault(s, f"CDEF in {d}")
        services |= found

    return Boundary(services=frozenset(services), sources=sources)

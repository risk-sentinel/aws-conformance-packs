"""Read the vendored FedRAMP Consolidated Rules snapshot.

The snapshot is the KSI vocabulary this repository validates against, and the
source of the KSI to NIST 800-53 crosswalk. FedRAMP maintains that crosswalk --
each indicator carries its own `controls[]` -- so this repository consumes it
and does not own its accuracy.

Why a pinned snapshot rather than a live fetch: FedRAMP 20x keeps changing until
the High baseline locks around 2027-02. Generating against a live fetch would let
a pack's crosswalk change silently between two runs of the same command, and
produce evidence that cannot say what it was assessed against.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

SNAPSHOT = Path(__file__).resolve().parents[1] / "vendor/fedramp/fedramp-consolidated-rules.json"


@dataclass(frozen=True)
class Indicator:
    id: str
    family: str
    name: str
    statement: str
    controls: tuple[str, ...]   # NIST 800-53 ids, as FedRAMP publishes them


@dataclass(frozen=True)
class Snapshot:
    version: str
    last_updated: str
    indicators: dict[str, Indicator]

    @property
    def families(self) -> set[str]:
        return {i.family for i in self.indicators.values()}

    def controls_for(self, ksi_id: str) -> tuple[str, ...]:
        return self.indicators[ksi_id].controls


@lru_cache(maxsize=1)
def load(path: Path | None = None) -> Snapshot:
    p = path or SNAPSHOT
    if not p.exists():
        raise FileNotFoundError(
            f"{p} is missing. It is vendored deliberately -- see "
            f"vendor/fedramp/PROVENANCE.md. Without it, nothing validates that a "
            f"KSI referenced by a rule is an indicator that actually exists."
        )
    doc = json.loads(p.read_text())
    inds: dict[str, Indicator] = {}
    for family, block in (doc.get("KSI") or {}).items():
        if not isinstance(block, dict) or "indicators" not in block:
            continue
        for kid, ind in block["indicators"].items():
            inds[kid] = Indicator(
                id=kid, family=family,
                name=ind.get("name", ""), statement=ind.get("statement", ""),
                controls=tuple(ind.get("controls", []) or []),
            )
    info = doc.get("info", {})
    return Snapshot(version=info.get("version", "unknown"),
                    last_updated=info.get("last_updated", "unknown"),
                    indicators=inds)


def suggest(unknown_id: str, snap: Snapshot) -> list[str]:
    """Best-effort successors for a stale id, to make a build failure actionable.

    The numbered-to-mnemonic re-key is not 1:1 -- `KSI-IAM-02` fans out across
    several mnemonics -- so this deliberately returns the whole family rather
    than pretending to a single answer a human has not made yet.
    """
    parts = unknown_id.split("-")
    if len(parts) < 2:
        return []
    fam = parts[1]
    # Families FedRAMP renamed. Not a guess: derived by comparing the vendored
    # snapshot's families against the ones this estate previously used.
    renamed = {"EDU": "CED", "CM": "CMT", "IR": "INR", "POL": "PIY", "REC": "RPL",
               "TPR": None, "AUTH": None}
    fam = renamed.get(fam, fam)
    if fam is None:
        return []
    return sorted(i.id for i in snap.indicators.values() if i.family == fam)

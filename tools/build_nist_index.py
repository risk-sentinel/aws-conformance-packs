#!/usr/bin/env python3
"""Derive a compact NIST SP 800-53 Rev 5 parameter index from OSCAL baselines.

    python3 tools/build_nist_index.py --catalogs <dir> --out vendor/nist

The raw resolved baselines are ~10.6 MB of OSCAL. Vendoring them into a
repository whose selling point is portability is a bad trade, and reviewing a
diff against them in a PR is not something anyone will actually do.

So this derives a small, reviewable index carrying only what the ODP catalog
needs to join against: every control, its parameters, their canonical and
alt-identifier ids, their labels and guidelines, and which baselines the control
resolves in. That last field is load-bearing -- ac-2.3 is absent from Low, and an
ODP bound to a control outside the target baseline must not render.

The index is DERIVED, never hand-edited. Rebuild it rather than patch it; a
hand-edit is how a param id that joins to nothing gets in.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

BASELINES = ("low", "moderate", "high")


def _controls(doc: dict) -> dict:
    cat = doc.get("catalog", doc)
    out: dict[str, dict] = {}

    def walk(group: dict) -> None:
        for c in group.get("controls", []) or []:
            out[c["id"]] = c
            walk(c)
        for g in group.get("groups", []) or []:
            walk(g)

    walk(cat)
    return out


def build(catalog_dir: Path) -> dict:
    per_baseline: dict[str, dict] = {}
    for b in BASELINES:
        matches = list(catalog_dir.glob(f"*rev5_{b.upper()}-baseline-resolved-profile_catalog.json"))
        if not matches:
            raise SystemExit(f"no resolved {b} baseline catalog found in {catalog_dir}")
        per_baseline[b] = _controls(json.loads(matches[0].read_text()))

    index: dict[str, dict] = {}
    for b, ctrls in per_baseline.items():
        for cid, c in ctrls.items():
            entry = index.setdefault(cid, {
                "title": c.get("title", ""), "baselines": [], "params": {},
            })
            if b not in entry["baselines"]:
                entry["baselines"].append(b)
            for p in c.get("params", []) or []:
                alt = next((x["value"] for x in p.get("props", []) or []
                            if x.get("name") == "alt-identifier"), None)
                # `_odp` is the Rev 5 canonical form. A `_prm_` id with no `_odp`
                # sibling is a legacy alias that survived into the catalogue; keep
                # it, but flag it so the ODP catalog does not key on it by mistake.
                entry["params"][p["id"]] = {
                    "label": p.get("label", ""),
                    "alt_id": alt,
                    "canonical": "_odp" in p["id"],
                    "guidelines": " ".join(
                        g.get("prose", "") for g in (p.get("guidelines") or [])
                    ).strip(),
                    "select": bool(p.get("select")),
                }
    for entry in index.values():
        entry["baselines"].sort(key=lambda x: BASELINES.index(x))
    return index


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--catalogs", type=Path, required=True,
                    help="directory holding the three rev5 resolved baseline catalogs")
    ap.add_argument("--out", type=Path, default=Path("vendor/nist"))
    ap.add_argument("--source", default="NIST SP 800-53 Rev 5 OSCAL resolved baselines")
    args = ap.parse_args()
    args.catalogs = safe_paths.consumer_dir(args.catalogs, "--catalogs")

    args.out = safe_paths.out_dir(args.out, "--out")
    index = build(args.catalogs)
    args.out.mkdir(parents=True, exist_ok=True)
    payload = {
        "_meta": {
            "source": args.source,
            "derived_by": "tools/build_nist_index.py",
            "derived_on": date.today().isoformat(),
            "controls": len(index),
            "parameters": sum(len(c["params"]) for c in index.values()),
        },
        "controls": dict(sorted(index.items())),
    }
    path = args.out / "nist-800-53r5-params.json"
    path.write_text(json.dumps(payload, indent=1, sort_keys=False) + "\n")
    m = payload["_meta"]
    print(f"wrote {path} — {m['controls']} controls, {m['parameters']} parameters, "
          f"{path.stat().st_size // 1024} KB")
    for b in BASELINES:
        n = sum(1 for c in index.values() if b in c["baselines"])
        print(f"  {b:9s} {n} controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

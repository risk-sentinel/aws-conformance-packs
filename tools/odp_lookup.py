#!/usr/bin/env python3
"""Emit catalog-ready ODP stubs for a set of controls, from the vendored index.

    python3 tools/odp_lookup.py ac-2.3 ia-5 sc-12
    python3 tools/odp_lookup.py --ksi KSI-CNA-RNT          # controls FedRAMP maps
    python3 tools/odp_lookup.py --domain rules/iam.yaml    # controls a catalog uses

Writes stubs to stdout for pasting into odp/catalog.yaml. It deliberately does
NOT write the catalog itself: `type`, `constraint` and `default` are judgement
calls about a specific AWS rule parameter, and a tool that guessed them would be
manufacturing exactly the unreviewed assertion the catalog exists to prevent.

What it removes is the transcription step -- 767 parameters copied by hand is
where a wrong param id gets in, and a wrong id joins to nothing while looking
entirely correct.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.control_ids import normalize_control_id  # noqa: E402
from tools import safe_paths  # noqa: E402

INDEX = Path(__file__).resolve().parents[1] / "vendor/nist/nist-800-53r5-params.json"


def load_index() -> dict:
    if not INDEX.exists():
        raise SystemExit(f"{INDEX} is missing; run tools/build_nist_index.py")
    return json.loads(INDEX.read_text())


def stub(control: str, entry: dict, pid: str, p: dict) -> str:
    label = (p.get("label") or "").replace('"', "'")
    guide = " ".join((p.get("guidelines") or "").split())
    kind = "SELECTION" if p.get("select") else "parameter"
    lines = [
        f"  # {control} — {entry['title']}",
        f"  # {kind}: {guide}" if guide else f"  # {kind}",
        f"  CHANGEME_{pid.replace('.', '_').replace('-', '_')}:",
        f"    description: >-",
        f"      TODO — what this knob is, in one sentence.",
        f"    control: {control}",
        f"    oscal_param_id: {pid}",
        f"    oscal_alt_id: {p.get('alt_id') or 'TODO-no-alt-identifier-published'}",
        f'    oscal_label: {label or "TODO"}',
        f"    baselines: [{', '.join(entry['baselines'])}]",
        f"    type: TODO            # integer | string | boolean | enum",
        f"    constraint: {{ }}       # TODO — a bad value must fail the build",
        f"    default: TODO         # must satisfy the constraint above",
    ]
    if not p.get("canonical"):
        lines.insert(2, "  # WARNING: legacy `_prm_` id with no `_odp` sibling; "
                        "prefer the canonical form if one exists.")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("controls", nargs="*")
    ap.add_argument("--ksi", action="append", default=[],
                    help="pull in the controls FedRAMP maps to this indicator")
    ap.add_argument("--domain", type=Path,
                    help="pull in every control a rule catalog already references")
    ap.add_argument("--baseline", choices=("low", "moderate", "high"))
    args = ap.parse_args()

    idx = load_index()
    wanted: set[str] = {normalize_control_id(c) for c in args.controls}

    for k in args.ksi:
        from tools import fedramp
        snap = fedramp.load()
        ind = snap.indicators.get(k)
        if ind is None:
            raise SystemExit(f"{k} is not in the vendored FedRAMP snapshot ({snap.version})")
        wanted |= {normalize_control_id(c) for c in ind.controls}

    if args.domain:
        import yaml
        doc = yaml.safe_load(
            safe_paths.consumer_file(args.domain, "--domain").read_text()) or {}
        for rule in (doc.get("rules") or {}).values():
            wanted |= {normalize_control_id(c)
                       for c in rule.get("controls", {}).get("nist_800_53_r5", [])}

    if not wanted:
        ap.error("give at least one control, --ksi, or --domain")

    missing, no_params, emitted = [], [], 0
    print("odps:")
    for cid in sorted(wanted):
        entry = idx["controls"].get(cid)
        if entry is None:
            missing.append(cid)
            continue
        if args.baseline and args.baseline not in entry["baselines"]:
            print(f"\n  # SKIPPED {cid} — not in the {args.baseline} baseline "
                  f"(resolves in: {', '.join(entry['baselines'])})")
            continue
        if not entry["params"]:
            no_params.append(cid)
            continue
        for pid, p in sorted(entry["params"].items()):
            print()
            print(stub(cid, entry, pid, p))
            emitted += 1

    print(f"\n# {emitted} stub(s) from {len(wanted)} control(s)", file=sys.stderr)
    if no_params:
        print(f"# no ODPs (nothing to parameterize): {', '.join(no_params)}", file=sys.stderr)
    if missing:
        # Not a warning to skim past. A control absent from every baseline cannot
        # be claimed as coverage -- si-13 is exactly this case, named in issue #7.
        print(f"# NOT IN ANY BASELINE — cannot be claimed as coverage: "
              f"{', '.join(missing)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

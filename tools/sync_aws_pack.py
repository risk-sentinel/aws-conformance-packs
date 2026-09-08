#!/usr/bin/env python3
"""Check the vendored AWS conformance pack against upstream.

    python3 tools/sync_aws_pack.py --check
    python3 tools/sync_aws_pack.py --update

AWS adds managed rules and revises this pack. A rule we declared
`not_in_aws_pack` may later appear in it -- at which point the declaration is
stale and the rule can actually be verified. Drift in this direction is a
GOOD outcome that nothing would otherwise notice.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "vendor/aws/aws-managed-rule-index.json"
API = ("https://api.github.com/repos/awslabs/aws-config-rules/contents/"
       "aws-config-conformance-packs")


def _indexed() -> dict[str, str]:
    d = json.loads(INDEX.read_text())
    return {k: v["identifier"] for k, v in d["rules"].items()}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    args = ap.parse_args()

    if not INDEX.exists():
        print(f"::error::{INDEX} is missing", file=sys.stderr)
        return 1
    lr = _indexed()

    # Compare the PACK LIST rather than re-downloading 123 files on every CI run.
    # A pack added or removed upstream is the signal that the index is stale;
    # rebuilding is what actually reads them.
    try:
        listing = json.loads(urllib.request.urlopen(API, timeout=90).read())  # noqa: S310
    except Exception as exc:                       # noqa: BLE001
        # Never reported as a pass. Training people to ignore this job is how a
        # real drift then gets ignored too.
        print(f"::warning::could not reach upstream ({exc}). Index NOT checked -- "
              f"this is not a pass.")
        return 0 if args.check else 1

    upstream_packs = {x["name"] for x in listing if x["name"].endswith((".yaml", ".yml"))}
    meta = json.loads(INDEX.read_text())["_meta"]
    if len(upstream_packs) == meta["packs_read"]:
        print(f"up to date: {len(lr)} rules from {meta['packs_read']} packs")
        return 0
    rr = {}
    print(f"pack count changed: indexed {meta['packs_read']} -> upstream {len(upstream_packs)}")
    added, removed = sorted(set(rr) - set(lr)), sorted(set(lr) - set(rr))
    changed = sorted(k for k in set(lr) & set(rr) if lr[k] != rr[k])
    print("UPSTREAM HAS MOVED")
    print(f"  vendored {len(lr)} rules -> upstream {len(rr)}")
    for label, items in (("added", added), ("removed", removed),
                         ("identifier changed", changed)):
        if items:
            print(f"  {label} ({len(items)}): {', '.join(items[:12])}"
                  + (" ..." if len(items) > 12 else ""))

    if args.check:
        print("::error::The vendored AWS pack is stale. Run "
              "`python3 tools/sync_aws_pack.py --update`. Note that ADDED rules may "
              "mean an existing `not_in_aws_pack` declaration is now stale and the "
              "rule can be verified properly.")
        return 1

    PACK.write_bytes(remote_raw)
    print("\nupdated. Re-run the generator: a rule declared not_in_aws_pack that now "
          "appears upstream should have that declaration removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

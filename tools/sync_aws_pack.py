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
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "vendor/aws/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml"
RAW_URL = ("https://raw.githubusercontent.com/awslabs/aws-config-rules/master/"
           "aws-config-conformance-packs/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml")


def _rules(text: str) -> dict[str, str]:
    doc = yaml.safe_load(text)
    return {
        r["Properties"]["ConfigRuleName"]:
            (r["Properties"].get("Source") or {}).get("SourceIdentifier", "")
        for r in (doc.get("Resources") or {}).values()
        if r.get("Type") == "AWS::Config::ConfigRule"
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    args = ap.parse_args()

    if not PACK.exists():
        print(f"::error::{PACK} is missing", file=sys.stderr)
        return 1
    local_raw = PACK.read_bytes()

    try:
        remote_raw = urllib.request.urlopen(RAW_URL, timeout=90).read()  # noqa: S310
    except Exception as exc:                       # noqa: BLE001
        # Never reported as a pass. Training people to ignore this job is how a
        # real drift then gets ignored too.
        print(f"::warning::could not reach upstream ({exc}). Pack NOT checked -- "
              f"this is not a pass.")
        return 0 if args.check else 1

    if hashlib.sha256(local_raw).hexdigest() == hashlib.sha256(remote_raw).hexdigest():
        print(f"up to date: {len(_rules(local_raw.decode()))} rules")
        return 0

    lr, rr = _rules(local_raw.decode()), _rules(remote_raw.decode())
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

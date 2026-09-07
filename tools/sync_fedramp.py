#!/usr/bin/env python3
"""Check the vendored FedRAMP snapshot against upstream, or refresh it.

    python3 tools/sync_fedramp.py --check     # exit 1 if upstream has moved
    python3 tools/sync_fedramp.py --update    # replace the snapshot + provenance

`--check` is what runs on a schedule in CI. The point is that FedRAMP 20x drift
surfaces as a failing job rather than as a question from an assessor.

That is the failure this whole tool exists to prevent, and it has already
happened once: the KSI ids in this estate were transcribed by hand from a
rendered documentation page, so when FedRAMP re-keyed every indicator from
numbered to mnemonic form, nothing noticed. Values copied from HTML cannot
detect drift, because nothing compares them to anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "vendor/fedramp/fedramp-consolidated-rules.json"
PROVENANCE = ROOT / "vendor/fedramp/PROVENANCE.md"
RAW_URL = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json"
REPO_API = "https://api.github.com/repos/FedRAMP/rules/commits/main"


def _indicators(doc: dict) -> dict[str, str]:
    out = {}
    for family, block in (doc.get("KSI") or {}).items():
        if isinstance(block, dict) and "indicators" in block:
            for kid, ind in block["indicators"].items():
                out[kid] = f"{family}|{ind.get('name','')}|{len(ind.get('controls',[]) or [])}"
    return out


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:   # noqa: S310 - fixed https URL
        return r.read()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    args = ap.parse_args()

    if not SNAPSHOT.exists():
        print(f"::error::{SNAPSHOT} is missing", file=sys.stderr)
        return 1

    local_raw = SNAPSHOT.read_bytes()
    local = json.loads(local_raw)

    try:
        remote_raw = _fetch(RAW_URL)
    except Exception as exc:                      # noqa: BLE001
        # A network failure is NOT drift. Reporting it as drift would train people
        # to ignore this job, which is how a real drift then gets ignored too.
        print(f"::warning::could not reach upstream ({exc}). "
              f"Snapshot NOT checked -- this is not a pass.")
        return 0 if args.check else 1

    if hashlib.sha256(remote_raw).hexdigest() == hashlib.sha256(local_raw).hexdigest():
        print(f"up to date: version {local['info']['version']} "
              f"({len(_indicators(local))} indicators)")
        return 0

    remote = json.loads(remote_raw)
    li, ri = _indicators(local), _indicators(remote)
    added = sorted(set(ri) - set(li))
    removed = sorted(set(li) - set(ri))
    changed = sorted(k for k in set(li) & set(ri) if li[k] != ri[k])

    print("UPSTREAM HAS MOVED")
    print(f"  vendored : {local['info']['version']}  ({local['info']['last_updated']})")
    print(f"  upstream : {remote['info']['version']}  ({remote['info']['last_updated']})")
    for label, items in (("added", added), ("removed", removed), ("changed", changed)):
        if items:
            print(f"  {label} ({len(items)}): {', '.join(items[:12])}"
                  + (" ..." if len(items) > 12 else ""))

    if args.check:
        print("::error::The vendored FedRAMP snapshot is stale. Run "
              "`python3 tools/sync_fedramp.py --update`, then review the diff -- a "
              "removed or renamed indicator means rule catalogs reference a KSI that "
              "no longer exists, and the re-key is NOT 1:1.")
        return 1

    SNAPSHOT.write_bytes(remote_raw)
    try:
        sha = json.loads(_fetch(REPO_API).decode())["sha"]
    except Exception:                              # noqa: BLE001
        sha = "unknown"
    text = PROVENANCE.read_text()
    for old, new in (
        (local["info"]["version"], remote["info"]["version"]),
        (local["info"]["last_updated"], remote["info"]["last_updated"]),
        (hashlib.sha256(local_raw).hexdigest(), hashlib.sha256(remote_raw).hexdigest()),
    ):
        text = text.replace(old, new)
    import re
    text = re.sub(r"\| Upstream commit \| `[0-9a-f]+` \|", f"| Upstream commit | `{sha}` |", text)
    text = re.sub(r"\| Retrieved \| \d{4}-\d{2}-\d{2} \|",
                  f"| Retrieved | {date.today().isoformat()} |", text)
    PROVENANCE.write_text(text)
    print(f"\nupdated snapshot and provenance. REVIEW THE DIFF: a removed or renamed "
          f"indicator breaks rule catalogs, and the mapping is not 1:1.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

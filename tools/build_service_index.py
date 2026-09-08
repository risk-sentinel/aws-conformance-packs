#!/usr/bin/env python3
"""Derive a service availability index from awslabs' OSCAL content for AWS services.

    python3 tools/build_service_index.py

awslabs publishes an OSCAL Component Definition per AWS service (231 of them).
Each carries the facts this repository has been ASSERTING by hand:

    availability            GLOBAL | REGIONAL | ZONAL | SUBZONAL
    links[rel=provided-by]  the Regions the service is actually available in
    service-id / arnNamespace / iamServicePrefix

`region_scope: global` in rules/iam.yaml was hand-written. AWS publishes that
IAM is GLOBAL, so it can be derived instead of asserted -- and the same data
says Bedrock exists in 15 Regions while S3 exists in 34, which is a distinction
no pack currently makes.

WHY THE RESOURCE-TYPE JOIN IS NOT DERIVED FROM THE STRING. The obvious approach
is to split `AWS::S3::Bucket` and look up `s3`. It produces WRONG ANSWERS:
`AWS::RDS::DBCluster` matches DocDB, because DocumentDB shares the `rds` ARN
namespace. A silently wrong service means a silently wrong Region scope, so the
mapping lives explicitly in vendor/aws-services/resource-type-map.yaml and a lint
fails when a resource type has no entry.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import safe_paths  # noqa: E402
OUT = ROOT / "vendor/aws-services/aws-service-availability.json"
API = ("https://api.github.com/repos/awslabs/oscal-content-for-aws-services/"
       "contents/component-definitions")
RAW = ("https://raw.githubusercontent.com/awslabs/oscal-content-for-aws-services/"
       "main/component-definitions/")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "aws-conformance-packs"})
    with urllib.request.urlopen(req, timeout=90) as r:   # noqa: S310 - fixed https
        return r.read()


def build() -> dict:
    regions = json.loads(_get(RAW + "aws_regions.oscal.json"))
    region_ids = []
    for c in regions["component-definition"]["components"]:
        p = {x["name"]: x["value"] for x in (c.get("props") or [])}
        if rid := p.get("region-id"):
            region_ids.append(rid)
    region_by_title = {c["title"]: {x["name"]: x["value"]
                                    for x in (c.get("props") or [])}.get("region-id")
                       for c in regions["component-definition"]["components"]}

    listing = json.loads(_get(API))
    files = sorted((x["name"] for x in listing if x["name"].endswith(".oscal.json")))
    services: dict[str, dict] = {}
    failed: list[str] = []

    for i, name in enumerate(files, 1):
        if name.startswith("aws_regions"):
            continue
        try:
            doc = json.loads(_get(RAW + name))
        except Exception as exc:                          # noqa: BLE001
            failed.append(f"{name}: {exc}")
            continue
        for c in doc["component-definition"].get("components", []):
            if c.get("type") != "service":
                continue
            p = {x["name"]: x["value"] for x in (c.get("props") or []) if x["name"] != "label"}
            sid = p.get("service-id") or c.get("title")
            # Region titles, mapped to ids. A title we cannot resolve is dropped
            # loudly rather than guessed -- a wrong Region is worse than a short
            # list, because it would let a pack deploy where nothing exists.
            regs, unresolved = [], []
            for l in (c.get("links") or []):
                if l.get("rel") != "provided-by":
                    continue
                rid = region_by_title.get(l.get("text"))
                (regs if rid else unresolved).append(rid or l.get("text"))
            entry = {
                "service_id": sid, "title": c.get("title"),
                "availability": p.get("availability"),
                "arn_namespace": p.get("arnNamespace"),
                "iam_prefix": p.get("iamServicePrefix"),
                "regions": sorted(set(regs)),
                "file": name,
            }
            if unresolved:
                entry["unresolved_region_titles"] = sorted(set(unresolved))
            services[sid] = entry
        if i % 60 == 0:
            print(f"  ...{i}/{len(files)} files, {len(services)} services", file=sys.stderr)

    if failed:
        raise SystemExit(f"::error::{len(failed)} file(s) unreadable; refusing to write a "
                         f"partial index:\n  " + "\n  ".join(failed[:8]))
    return {
        "_meta": {
            "source": "https://github.com/awslabs/oscal-content-for-aws-services",
            "derived_by": "tools/build_service_index.py",
            "derived_on": date.today().isoformat(),
            "services": len(services),
            "regions": len(region_ids),
            "note": ("availability is a SCOPE CLASS (GLOBAL/REGIONAL/ZONAL/SUBZONAL); "
                     "`regions` is the actual availability list AWS publishes per "
                     "service. They answer different questions."),
        },
        "regions": sorted(region_ids),
        "services": dict(sorted(services.items())),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    args.out = safe_paths.out_dir(args.out, "--out")
    payload = build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=1) + "\n")
    m = payload["_meta"]
    print(f"wrote {args.out} — {m['services']} services, {m['regions']} regions, "
          f"{args.out.stat().st_size // 1024} KB")
    print(f"sha256 {hashlib.sha256(args.out.read_bytes()).hexdigest()}")
    glob = [s for s in payload["services"].values() if s["availability"] == "GLOBAL"]
    print(f"GLOBAL services: {[s['service_id'] for s in glob]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

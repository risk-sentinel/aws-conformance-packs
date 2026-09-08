#!/usr/bin/env python3
"""Derive a managed-rule verification index from AWS's published conformance packs.

    python3 tools/build_aws_index.py

AWS publishes ~120 conformance packs. Our rules were previously checked against
ONE of them (NIST 800-53 Rev 5), which left 24 real managed rules unverifiable
purely because that pack does not happen to carry them.

That matters because a wrong SourceIdentifier does NOT fail at deploy time. It
reports INSUFFICIENT_DATA forever, which every dashboard renders as "not
failing" -- the failure mode this repository exists to catch.

Vendors a DERIVED INDEX, not 120 raw packs. The packs total several megabytes
and nobody diffs that in review; the index carries rule name, identifier,
parameter names and the pack each was seen in, which is small, greppable, and
rebuilt by a tool that names its source.

IMPORTANT ON WHAT "VERIFIED" MEANS HERE. This confirms an identifier and
parameter NAMES exist as AWS publishes them. It says nothing about whether the
rule evaluates what our crosswalk claims. That is what live evaluation is for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import safe_paths  # noqa: E402
OUT = ROOT / "vendor/aws/aws-managed-rule-index.json"
API = ("https://api.github.com/repos/awslabs/aws-config-rules/contents/"
       "aws-config-conformance-packs")


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics.

    Several packs use `!Not [!Equals [!Ref X, ""]]` in Conditions. safe_load
    refuses those tags outright, which took out a whole pack and would have
    silently narrowed verification coverage if the run had been allowed to
    continue. We only need Resources, so the tags are read as opaque values.
    """


def _opaque(loader, tag_suffix, node):                      # noqa: ANN001
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CfnLoader.add_multi_constructor("!", _opaque)


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "aws-conformance-packs"})
    with urllib.request.urlopen(req, timeout=90) as r:      # noqa: S310 - fixed https
        return r.read()


def build() -> dict:
    listing = json.loads(_get(API).decode())
    packs = sorted((x for x in listing if x["name"].endswith((".yaml", ".yml"))),
                   key=lambda x: x["name"])
    rules: dict[str, dict] = {}
    failed: list[str] = []

    for i, entry in enumerate(packs, 1):
        try:
            raw = _get(entry["download_url"]).decode()
            doc = yaml.load(raw, Loader=_CfnLoader) or {}
        except Exception as exc:                            # noqa: BLE001
            failed.append(f"{entry['name']}: {exc}")
            continue
        for res in (doc.get("Resources") or {}).values():
            if res.get("Type") != "AWS::Config::ConfigRule":
                continue
            props = res["Properties"]
            name = props.get("ConfigRuleName")
            ident = (props.get("Source") or {}).get("SourceIdentifier")
            # A SourceIdentifier that is not a plain string is an intrinsic
            # (!Ref, Fn::If) or a CUSTOM_POLICY rule. Neither is a managed-rule
            # identifier we can verify anything against, so it is skipped rather
            # than coerced into a string that would look authoritative.
            if not isinstance(name, str) or not isinstance(ident, str) or not ident:
                continue
            r = rules.setdefault(name, {"identifier": ident, "identifiers": {},
                                        "parameters": [], "packs": []})
            # Count every identifier seen rather than letting first- or last-wins
            # decide silently. AWS's own packs disagree in at least one case, and
            # a silent pick could accept a wrong identifier as verified.
            r["identifiers"][ident] = r["identifiers"].get(ident, 0) + 1
            # Union of parameters seen anywhere: a pack that sets none does not
            # mean the rule accepts none, so absence is never treated as proof.
            params = props.get("InputParameters")
            for p in (params if isinstance(params, dict) else {}):
                if p not in r["parameters"]:
                    r["parameters"].append(p)
            if entry["name"] not in r["packs"]:
                r["packs"].append(entry["name"])
        if i % 20 == 0:
            print(f"  ...{i}/{len(packs)} packs, {len(rules)} rules", file=sys.stderr)

    if failed:
        # A partial index would silently narrow verification coverage and look
        # like a clean run. Refuse it.
        raise SystemExit(f"::error::{len(failed)} pack(s) could not be read; refusing to "
                         f"write a partial index:\n  " + "\n  ".join(failed[:10]))

    conflicts = {}
    for name, r in rules.items():
        r["parameters"].sort()
        r["packs"].sort()
        seen = r.pop("identifiers")
        # The identifier the most packs agree on wins; any disagreement is
        # recorded on the entry so it is visible to a reviewer rather than
        # resolved out of sight.
        r["identifier"] = max(seen, key=lambda k: (seen[k], k))
        if len(seen) > 1:
            r["conflicting_identifiers"] = {k: v for k, v in sorted(seen.items())}
            conflicts[name] = r["conflicting_identifiers"]
    for name, c in conflicts.items():
        print(f"::warning::{name}: AWS packs disagree on the identifier {c}; "
              f"using the majority. Verification accepts ANY of them.", file=sys.stderr)
    return {
        "_meta": {
            "source": "https://github.com/awslabs/aws-config-rules",
            "path": "aws-config-conformance-packs/",
            "derived_by": "tools/build_aws_index.py",
            "derived_on": date.today().isoformat(),
            "packs_read": len(packs),
            "rules": len(rules),
            "note": ("Confirms an identifier and parameter NAMES exist as AWS publishes "
                     "them. Says nothing about whether a rule evaluates what a crosswalk "
                     "claims -- that is what live evaluation is for."),
        },
        "rules": dict(sorted(rules.items())),
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
    digest = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print(f"wrote {args.out} — {m['rules']} rules from {m['packs_read']} packs, "
          f"{args.out.stat().st_size // 1024} KB")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate inputs.yml before anything is deployed.

    python3 tools/validate_inputs.py --inputs inputs.yml

Every refusal here is a condition under which the deploy would appear to succeed
and produce evidence nobody should trust. A malformed inputs.yml caught halfway
through a deploy leaves some packs in and some out, with no record of which.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ("low", "moderate", "high")
MODES = ("single-account", "organization")
ACCOUNT_RE = re.compile(r"^\d{12}$")
OU_RE = re.compile(r"^ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}$")
REGION_RE = re.compile(r"^[a-z]{2}(-gov)?(-[a-z]+)+-\d$")


def known_packs() -> set[str]:
    return {yaml.safe_load(f.read_text())["domain"]
            for f in (ROOT / "rules").glob("*.yaml")}


def validate(cfg: dict, root: Path = ROOT) -> list[str]:
    e: list[str] = []
    packs = cfg.get("packs") or []
    known = known_packs()

    if not packs:
        e.append("`packs` is empty. Nothing would deploy — which is a silent no-op, not "
                 "a safe default.")
    for p in packs:
        if p not in known:
            e.append(f"`packs` names {p!r}, which is not a built pack. Known: {sorted(known)}")

    if not cfg.get("accounts"):
        e.append("`accounts` is empty. There is no safe default for where your evidence "
                 "comes from.")
    mode = cfg.get("mode")
    if mode not in MODES:
        e.append(f"`mode` is {mode!r}; expected one of {list(MODES)}")
    for a in cfg.get("accounts") or []:
        ok = OU_RE.match(str(a)) if mode == "organization" else ACCOUNT_RE.match(str(a))
        if not ok:
            e.append(f"`accounts` entry {a!r} is not a valid "
                     f"{'organizational unit id' if mode == 'organization' else '12-digit account id'} "
                     f"for mode {mode!r}. A malformed id does not error at deploy — the "
                     f"call simply targets nothing.")

    regions = cfg.get("regions") or []
    if not regions:
        e.append("`regions` is empty. A Region you omit is not reported as a gap; it is "
                 "absent, which reads as nothing to fix.")
    for r in regions:
        if not REGION_RE.match(str(r)):
            e.append(f"`regions` entry {r!r} is not a Region identifier. A wrong Region "
                     f"reads an empty account and reports a CLEAN result.")

    gr = cfg.get("global_resource_region") or ""
    if "IAM" in packs:
        if not gr:
            e.append("`global_resource_region` is required when the IAM pack is selected. "
                     "IAM is global and recorded in exactly ONE Region; deployed anywhere "
                     "else the pack evaluates nothing and reports INSUFFICIENT_DATA.")
        elif gr not in regions:
            e.append(f"`global_resource_region` is {gr!r}, which is not in `regions`. The "
                     f"IAM pack would be deployed nowhere that records IAM.")
    if gr and not REGION_RE.match(str(gr)):
        e.append(f"`global_resource_region` {gr!r} is not a Region identifier.")

    d = cfg.get("delivery") or {}
    ev = d.get("evidence_bucket") or ""
    if not ev:
        e.append("`delivery.evidence_bucket` is empty. It is where your evidence lands, "
                 "so it has no safe default.")
    elif mode == "organization" and not ev.startswith("awsconfigconforms"):
        # Verified against the PutOrganizationConformancePack API reference,
        # 2026-09-08: "If used, it must be prefixed with `awsconfigconforms`."
        # The single-account API has no such requirement, so this is exactly the
        # kind of difference that only shows up at deploy time.
        e.append(f"`delivery.evidence_bucket` is {ev!r}. In organization mode AWS "
                 f"requires the delivery bucket name to be prefixed with "
                 f"`awsconfigconforms`; the single-account API does not, so this "
                 f"only fails when you switch modes.")

    # ExcludedAccounts: max 1000 items, fixed length 12, pattern \d{12}.
    excl = cfg.get("excluded_accounts") or []
    if len(excl) > 1000:
        e.append(f"`excluded_accounts` has {len(excl)} entries; AWS accepts at most 1000.")
    for a in excl:
        if not ACCOUNT_RE.match(str(a)):
            e.append(f"`excluded_accounts` entry {a!r} is not a 12-digit account id. AWS "
                     f"rejects the call, so the pack deploys to nobody rather than to "
                     f"everyone-but-that-account.")
    if excl and mode != "organization":
        e.append("`excluded_accounts` is set but `mode` is not `organization`. It is "
                 "ignored in single-account mode, so the accounts you meant to exclude "
                 "would be deployed to.")

    ov = cfg.get("overlay")
    if not ov:
        e.append("`overlay` is empty.")
    else:
        p = root / ov
        if not p.exists():
            e.append(f"`overlay` points at {ov}, which does not exist.")
        else:
            doc = yaml.safe_load(p.read_text()) or {}
            lvl = doc.get("baseline_level")
            base = cfg.get("baseline")
            if base not in BASELINES:
                e.append(f"`baseline` is {base!r}; expected one of {list(BASELINES)}")
            elif lvl != base:
                # Silent mismatch: the overlay's values apply, but rules bound to
                # controls outside `baseline` are excluded. The pack renders and
                # is smaller than the operator expects, with no signal.
                e.append(f"`baseline` is {base!r} but {ov} declares "
                         f"`baseline_level: {lvl!r}`. Rules bound to controls outside "
                         f"{base!r} would be excluded and the pack would render smaller "
                         f"than intended, with nothing saying so.")

    safety = cfg.get("safety") or {}
    if safety.get("require_recorder_preflight") is False:
        e.append("`safety.require_recorder_preflight` is false. Turning it off does not "
                 "make the packs work — it makes them deploy and report "
                 "INSUFFICIENT_DATA, which reads as 'not failing'. If this is a "
                 "deliberate risk acceptance it needs an owner's approval recorded, per "
                 "docs/dev/issue_rules.md.")
    return e


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inputs", type=Path, default=Path("inputs.yml"))
    args = ap.parse_args()
    if not args.inputs.exists():
        print(f"::error::{args.inputs} does not exist. Copy inputs.template.yml and fill "
              f"it in — nothing in it has a default, deliberately.", file=sys.stderr)
        return 1
    cfg = yaml.safe_load(args.inputs.read_text()) or {}
    problems = validate(cfg)
    if problems:
        print(f"::error::{args.inputs} is not deployable:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"{args.inputs} is valid: {len(cfg['packs'])} pack(s), "
          f"{len(cfg['regions'])} Region(s), mode {cfg['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

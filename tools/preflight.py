#!/usr/bin/env python3
"""Recorder preflight — refuses to deploy packs that could not evaluate anything.

    python3 tools/preflight.py --inputs inputs.yml

THIS CANNOT BE A CONFIG RULE, and that is the whole reason it exists as a CLI.
A rule about the AWS Config recorder, evaluated by AWS Config, is circular: if
recording is off, the rule that would report that fact does not run. So the
assertion has to be made from outside, before anything is deployed.

WHAT IT GUARDS AGAINST. A Config rule scoped to a resource type the recorder is
not capturing never evaluates. It does not fail -- it reports INSUFFICIENT_DATA,
which most dashboards render as "not failing". A pack deployed onto an
unconfigured recorder therefore produces a green board and no evidence, which is
the failure mode the programme epic calls the silent killer.

It REFUSES rather than warns. A warning at deploy time is read once and then
scrolled past; the pack stays deployed either way.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import safe_paths  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class PreflightError(Exception):
    """A condition under which deploying would produce evidence nobody should trust."""


def _aws(args: list[str], region: str, profile: str | None) -> dict:
    cmd = ["aws", *args, "--region", region, "--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise PreflightError(f"`{' '.join(args)}` failed in {region}: {r.stderr.strip()}")
    return json.loads(r.stdout or "{}")


def required_resource_types(packs: list[str], boundary: set[str] | None = None,
                            svc=None) -> dict[str, set[str]]:
    """Resource types each selected pack declares it needs recorded.

    BOUNDARY-AWARE, and it has to be. Found by running this against a real
    account: the preflight asserted every resource type the catalogs mention,
    while the generator had already excluded the rules that use them because the
    boundary does not run those services. The two disagreed, and the preflight
    was the stricter one — so it refused a deployment that would have been
    entirely correct.

    A preflight that refuses valid work is not a safe default. It is a guard
    people learn to bypass.
    """
    want: dict[str, set[str]] = {}
    for f in sorted((ROOT / "rules").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        if doc["domain"] not in packs:
            continue
        types = set(doc.get("required_resource_types") or [])
        for rule in doc["rules"].values():
            types |= set(rule.get("resource_types") or [])
        if boundary is not None and svc is not None:
            types = {
                rt for rt in types
                if svc.for_resource_type(rt) is None
                or svc.for_resource_type(rt).service_id in boundary
            }
        # Account-level pseudo-type: not a recorded resource, so never asserted.
        types.discard("AWS::::Account")
        want[doc["domain"]] = types
    return want


def rules_using(types: set[str]) -> dict[str, list[str]]:
    """Which rules reference each resource type — so a refusal names the cost.

    A boundary is service-level; a recorder exclusion is resource-TYPE level, so
    a service can be partially recorded. Telling an operator that
    `AWS::EC2::Instance` is excluded is true and not actionable; telling them
    which rules go inert is.
    """
    out: dict[str, list[str]] = {}
    for f in sorted((ROOT / "rules").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
        for name, rule in doc["rules"].items():
            for rt in (rule.get("resource_types") or []):
                if rt in types:
                    out.setdefault(rt, []).append(f"{doc['domain']}/{name}")
    return out


def check_region(region: str, needed: set[str], profile: str | None,
                 expect_global: bool) -> list[str]:
    """Assert one Region's recorder can actually evaluate what we are deploying."""
    problems: list[str] = []

    recorders = _aws(["configservice", "describe-configuration-recorders"],
                     region, profile).get("ConfigurationRecorders") or []
    if not recorders:
        return [f"{region}: no AWS Config recorder exists. Every rule deployed here "
                f"would report INSUFFICIENT_DATA, which reads as 'not failing'."]

    status = _aws(["configservice", "describe-configuration-recorder-status"],
                  region, profile).get("ConfigurationRecordersStatus") or []
    if not any(s.get("recording") for s in status):
        problems.append(f"{region}: a recorder exists but is NOT RECORDING. This is the "
                        f"worst of the three states — the pack deploys, the console looks "
                        f"configured, and nothing is ever evaluated.")

    rec = recorders[0]
    group = rec.get("recordingGroup") or {}
    all_supported = bool(group.get("allSupported"))
    recorded = set(group.get("resourceTypes") or [])
    strategy = (group.get("recordingStrategy") or {}).get("useOnly", "")
    exclusions = set(((group.get("exclusionByResourceTypes") or {}).get("resourceTypes")) or [])

    if strategy == "EXCLUSION_BY_RESOURCE_TYPES" or exclusions:
        missing = needed & exclusions
        if missing:
            using = rules_using(missing)
            detail = "; ".join(
                f"{rt} -> {', '.join(using.get(rt, ['(pack prerequisite only)'])[:4])}"
                + (" ..." if len(using.get(rt, [])) > 4 else "")
                for rt in sorted(missing))
            problems.append(
                f"{region}: the recorder EXCLUDES resource types the selected packs "
                f"need, so these rules would never evaluate — they would report "
                f"INSUFFICIENT_DATA, which reads as 'not failing':\n      {detail}")
    elif not all_supported:
        missing = needed - recorded
        if missing:
            problems.append(f"{region}: the recorder does not capture {sorted(missing)}. "
                            f"Rules scoped to them report INSUFFICIENT_DATA rather than "
                            f"failing.")

    # WHETHER GLOBAL RESOURCES ARE RECORDED DEPENDS ON THE STRATEGY, and reading
    # `includeGlobalResourceTypes` on its own gets it wrong.
    #
    # Found against a live account: a recorder using EXCLUSION_BY_RESOURCE_TYPES
    # reported `includeGlobalResourceTypes: false` while demonstrably recording
    # IAM users, roles and policies. Under that strategy AWS records every
    # supported type NOT on the exclusion list, and the flag is vestigial.
    #
    # The earlier check read the flag literally, refused, and would have had
    # someone make an unnecessary change to a production recorder to satisfy it.
    # That is the third time a guard here has refused valid work, and the first
    # time one nearly caused the damage it existed to prevent.
    GLOBAL_PREFIXES = ("AWS::IAM::", "AWS::Organizations::", "AWS::CloudFront::",
                       "AWS::Shield", "AWS::GlobalAccelerator::", "AWS::Route53::")
    if strategy == "EXCLUSION_BY_RESOURCE_TYPES" or exclusions:
        excluded_global = sorted(x for x in exclusions if x.startswith(GLOBAL_PREFIXES))
        records_global = not excluded_global
        global_detail = (f"global resource types {excluded_global} are on the exclusion list"
                         if excluded_global else "no global resource type is excluded")
    elif all_supported:
        records_global = bool(group.get("includeGlobalResourceTypes"))
        global_detail = f"allSupported with includeGlobalResourceTypes={records_global}"
    else:
        # An explicit inclusion list records only what it names.
        records_global = any(rt.startswith(GLOBAL_PREFIXES) for rt in recorded)
        global_detail = "explicit resource-type list"

    if expect_global and not records_global:
        problems.append(
            f"{region}: designated as the global-resource Region but does not record "
            f"global resource types ({global_detail}). IAM is global, so an IAM pack "
            f"deployed anywhere would evaluate nothing.")
    if not expect_global and records_global and strategy != "EXCLUSION_BY_RESOURCE_TYPES":
        # Only warned for an explicit configuration. Under the exclusion strategy
        # recording global types is the DEFAULT, so flagging it would fire in
        # every Region of every account using that strategy.
        problems.append(
            f"{region}: records global resources, but `global_resource_region` names "
            f"another Region. Global resources recorded in more than one Region "
            f"duplicate configuration items and duplicate the bill.")

    channels = _aws(["configservice", "describe-delivery-channels"],
                    region, profile).get("DeliveryChannels") or []
    if not channels:
        problems.append(f"{region}: no delivery channel. Config has nowhere to write "
                        f"results, so there is no evidence even when rules do evaluate.")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inputs", type=Path, default=Path("inputs.yml"))
    ap.add_argument("--profile", default=None)
    ap.add_argument("--dry-run", action="store_true",
                    help="report what WOULD be asserted, making no AWS calls")
    args = ap.parse_args()

    try:
        if args.profile:
            # Reaches an AWS CLI argv. The call passes a list rather than a shell
            # string, so this is defence in depth -- but an argv element is still
            # an injection surface for the program being invoked.
            args.profile = safe_paths.token(args.profile, "--profile")
        if not args.inputs.exists():
            raise PreflightError(
                f"{args.inputs} does not exist. Copy inputs.template.yml and fill it in; "
                f"nothing in it has a default, deliberately.")
        cfg = yaml.safe_load(
            safe_paths.consumer_file(args.inputs, "--inputs").read_text()) or {}
        packs = cfg.get("packs") or []
        regions = cfg.get("regions") or []
        global_region = cfg.get("global_resource_region") or ""
        bnd_services: set[str] | None = None
        svc = None
        try:
            sys.path.insert(0, str(ROOT))
            from tools import aws_services, boundary as boundary_mod
            svc = aws_services.load()
            b = boundary_mod.resolve(cfg, set(svc.services), ROOT)
            if b.declared:
                bnd_services = set(b.services)
        except Exception as exc:                          # noqa: BLE001
            # A boundary that cannot be resolved must not silently widen the
            # preflight back to everything; that would be the stricter, refusing
            # behaviour arriving by accident.
            raise PreflightError(f"boundary could not be resolved: {exc}") from exc

        want = required_resource_types(packs, bnd_services, svc)
        if bnd_services:
            print(f"boundary: {len(bnd_services)} service(s); asserting only what "
                  f"the composed packs actually reference")

        print(f"packs   : {', '.join(packs)}")
        print(f"regions : {', '.join(regions)}")
        for dom, types in sorted(want.items()):
            print(f"  {dom}: needs {len(types)} recorded resource type(s)")

        if args.dry_run:
            print("\n--dry-run: no AWS calls made. Nothing has been asserted, and this "
                  "is NOT a pass.")
            return 0

        problems: list[str] = []
        for region in regions:
            needed = set().union(*want.values()) if want else set()
            problems += check_region(region, needed, args.profile,
                                     expect_global=(region == global_region))

        if problems:
            print("\nPREFLIGHT REFUSED — deploying now would produce a green board and "
                  "no evidence:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            print("\n::error::Recorder preflight failed. Fix the recorder, or understand "
                  "that these packs will report INSUFFICIENT_DATA rather than findings.",
                  file=sys.stderr)
            return 1
        print("\npreflight passed: every selected pack's resource types are recorded, "
              "in every target Region.")
        return 0
    except safe_paths.UnsafePath as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    except PreflightError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

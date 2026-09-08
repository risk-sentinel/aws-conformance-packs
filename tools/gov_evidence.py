#!/usr/bin/env python3
"""GOV — evidence for controls AWS Config cannot see. Emits HDF.

    python3 tools/gov_evidence.py --inputs inputs.yml --out out/

Roughly 120 Moderate controls have no resource-configuration signal: the 18 `-1`
policy controls plus AT, PS, PL, PM, SA and SR in bulk. They are evidenced here
against policy artifacts in a repository.

THE FAILURE THIS MUST NOT BECOME
--------------------------------
"The policy file exists" is not evidence. A producer that checks presence and
reports PASS is theater, and worse than nothing because it occupies the slot
where real evidence would go.

So every emitted control carries an `evidence_strength` tag, existence is never
reported as satisfying a control on its own, and the three checks that actually
matter -- review recency, an authorized approver of record, and SSP-version
reconciliation -- are separate results a reader can weigh.

Output is the legacy HDF `profiles[].controls[]` shape, so it joins the same
pipeline as the Config-rule evidence with no custom shape handling. Control ids
come from tools/control_ids.py -- the SAME normalizer the pack generator uses,
because if GOV emits `AC-1` and a pack emits `ac-2` the Heimdall rollup
fragments, and a fragmented rollup does not look broken. It looks like partial
coverage.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.control_ids import normalize_control_id  # noqa: E402
from tools import fedramp  # noqa: E402

PASSED, FAILED, SKIPPED = "passed", "failed", "skipped"


def _front_matter(path: Path) -> tuple[dict, str] | None:
    text = path.read_text()
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    return yaml.safe_load(parts[1]) or {}, parts[2]


def _result(status: str, desc: str, message: str = "") -> dict:
    r = {"status": status, "code_desc": desc, "start_time": datetime.now().isoformat()}
    if message:
        r["message"] = message
    return r


def evaluate(artifact_dir: Path, odps: dict, today: date | None = None) -> list[dict]:
    """One HDF control per artifact, with a result per check.

    A control is FAILED if any real check fails. Existence alone never passes a
    control -- it is emitted as its own result and labelled weak.
    """
    today = today or date.today()
    review_days = odps["policy_review_interval_days"]
    proc_days = odps["procedure_review_interval_days"]
    approvers = {str(a).lower() for a in odps["approved_policy_approver_roles"]}

    controls: list[dict] = []
    for path in sorted(artifact_dir.glob("*.md")):
        fm = _front_matter(path)
        if fm is None:
            controls.append({
                "id": f"gov-{path.stem}", "title": f"Artifact {path.name}",
                "desc": "Artifact has no YAML front matter, so nothing about it can be "
                        "evaluated. An unparseable artifact is a FAILURE, not a skip -- "
                        "a skip would read as 'nothing to check here'.",
                "impact": 0.7, "refs": [], "tags": {"evidence_strength": "n/a"},
                "results": [_result(FAILED, f"{path.name} front matter", "no front matter")],
            })
            continue
        meta, _body = fm
        ids = [normalize_control_id(c) for c in (meta.get("controls") or [])]
        kind = meta.get("kind", "policy")
        limit = proc_days if kind == "procedure" else review_days
        results: list[dict] = []

        # 1. Existence — WEAK. Emitted so its weakness is visible, never as the
        #    thing that satisfies the control.
        results.append(_result(
            PASSED, f"{path.name} exists",
            "WEAK EVIDENCE: presence of a document is a precondition, not compliance. "
            "The review, approver and SSP-version results below are what count."))

        # 2. Review recency — REAL. Expires by the passage of time, which is why
        #    this producer runs on a schedule and not only on commit.
        reviewed = meta.get("reviewed")
        if not reviewed:
            results.append(_result(FAILED, f"{path.name} reviewed date",
                                   "no `reviewed` date; recency cannot be established"))
        else:
            try:
                d = reviewed if isinstance(reviewed, date) else date.fromisoformat(str(reviewed))
                age = (today - d).days
                if age > limit:
                    results.append(_result(
                        FAILED, f"{path.name} reviewed within {limit} days",
                        f"last reviewed {d.isoformat()}, {age} days ago, exceeding the "
                        f"organization-defined interval of {limit} days"))
                else:
                    results.append(_result(
                        PASSED, f"{path.name} reviewed within {limit} days",
                        f"last reviewed {d.isoformat()}, {age} days ago"))
            except ValueError:
                results.append(_result(FAILED, f"{path.name} reviewed date",
                                       f"`reviewed` is {reviewed!r}, not an ISO 8601 date"))

        # 3. Approver of record — REAL. Distinguishes a reviewed policy from an
        #    edited file.
        who, role = meta.get("approved_by"), str(meta.get("approver_role", "")).lower()
        if not who:
            results.append(_result(FAILED, f"{path.name} approver",
                                   "no `approved_by`; a document approved by nobody is "
                                   "not evidence of a decision"))
        elif role not in approvers:
            results.append(_result(
                FAILED, f"{path.name} approver role",
                f"approver role {role!r} is not one of {sorted(approvers)}. Approval by "
                f"someone without authority to accept the risk is not approval."))
        else:
            results.append(_result(PASSED, f"{path.name} approver",
                                   f"approved by {who} ({role})"))

        # 4. SSP-version reconciliation — STRONGEST. Catches the drift where the
        #    SSP describes a policy nobody is following.
        v, sv = str(meta.get("version", "")), str(meta.get("ssp_version", ""))
        if not v or not sv:
            results.append(_result(FAILED, f"{path.name} SSP version reconciliation",
                                   "`version` or `ssp_version` missing; the strongest "
                                   "available check cannot be performed"))
        elif v != sv:
            results.append(_result(
                FAILED, f"{path.name} SSP version reconciliation",
                f"document is version {v} but the SSP cites {sv}. The SSP describes a "
                f"policy that is not the one in force."))
        else:
            results.append(_result(PASSED, f"{path.name} SSP version reconciliation",
                                   f"document and SSP agree at version {v}"))

        failed = any(r["status"] == FAILED for r in results)
        controls.append({
            "id": f"gov-{'-'.join(ids) or path.stem}",
            "title": meta.get("title", path.stem),
            "desc": f"Policy artifact evidence for {', '.join(ids) or 'no declared control'}. "
                    f"Existence alone does not satisfy the control; review recency, an "
                    f"authorized approver and SSP-version agreement are what do.",
            "impact": 0.7,
            # A consumer's artifact directory is outside this repo by design, so
            # relative_to(ROOT) is not always possible.
            "refs": [{"url": str(path.relative_to(ROOT)
                                 if path.is_relative_to(ROOT) else path)}],
            "tags": {
                "nist": [c.upper() for c in ids],
                "evidence_strength": "artifact-review",
                "producer": "gov",
                "artifact_kind": kind,
                "review_interval_days": limit,
            },
            "results": results,
            "status": "failed" if failed else "passed",
        })
    return controls


def inventory_reconciliation(iac: Path | None, recorded: Path | None) -> dict:
    """KSI-PIY-GIV — the check that earns its place.

    Diffing IaC-declared resources against what AWS Config actually recorded
    catches drift and shadow resources no conformance pack will ever see, and it
    is genuinely hard to fake.

    With no inputs it reports SKIPPED, never passed. An absent input must not
    read as a clean result -- that is the whole failure mode this repository
    exists to avoid.
    """
    ctrl = {
        "id": "gov-cm-8-inventory-reconciliation",
        "title": "IaC-declared inventory reconciles against AWS Config's recorded inventory",
        "desc": "Shadow resources and drift are invisible to every conformance pack, "
                "because a pack only evaluates what the recorder already knows about. "
                "This is the check that sees what the packs cannot.",
        "impact": 0.7, "refs": [],
        "tags": {"nist": ["CM-8", "PM-5"], "evidence_strength": "reconciliation",
                 "producer": "gov", "ksi": ["KSI-PIY-GIV"]},
        "results": [],
    }
    if not iac or not recorded:
        ctrl["results"] = [_result(
            SKIPPED, "inventory reconciliation",
            "no IaC inventory or recorded inventory supplied. Reported as SKIPPED and "
            "NOT as passed: an absent input must never read as a clean result.")]
        ctrl["status"] = "skipped"
        return ctrl

    declared = {str(x) for x in json.loads(iac.read_text())}
    actual = {str(x) for x in json.loads(recorded.read_text())}
    shadow, missing = actual - declared, declared - actual
    if shadow:
        ctrl["results"].append(_result(
            FAILED, "no shadow resources",
            f"{len(shadow)} resource(s) recorded by AWS Config that IaC does not declare. "
            f"These exist, are evaluated by nothing anyone planned, and are the resources "
            f"most likely to be misconfigured: {sorted(shadow)[:10]}"))
    else:
        ctrl["results"].append(_result(PASSED, "no shadow resources",
                                       f"all {len(actual)} recorded resources are declared"))
    if missing:
        ctrl["results"].append(_result(
            FAILED, "no undeployed declarations",
            f"{len(missing)} resource(s) declared in IaC but not recorded. Either they "
            f"failed to deploy, or the recorder is not capturing their type -- and the "
            f"second case means every rule scoped to them is silently inert: "
            f"{sorted(missing)[:10]}"))
    else:
        ctrl["results"].append(_result(PASSED, "no undeployed declarations",
                                       f"all {len(declared)} declared resources are recorded"))
    ctrl["status"] = "failed" if (shadow or missing) else "passed"
    return ctrl


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inputs", type=Path, default=Path("inputs.yml"))
    ap.add_argument("--artifact-dir", type=Path, default=None)
    ap.add_argument("--overlay", type=Path, default=None)
    ap.add_argument("--iac-inventory", type=Path, default=None)
    ap.add_argument("--recorded-inventory", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=Path("out"))
    args = ap.parse_args()

    cfg = yaml.safe_load(args.inputs.read_text()) if args.inputs.exists() else {}
    gov = cfg.get("gov") or {}
    art = args.artifact_dir or (Path(gov["artifact_dir"]) if gov.get("artifact_dir") else None)
    if art is None:
        print("::error::no artifact directory. Set `gov.artifact_dir` in inputs.yml or "
              "pass --artifact-dir. There is no default, because a default would point "
              "at somebody else's policies.", file=sys.stderr)
        return 1
    if not art.is_dir():
        print(f"::error::{art} is not a directory", file=sys.stderr)
        return 1

    overlay_path = args.overlay or Path(cfg.get("overlay") or "overlays/vanilla.yaml")
    catalog = yaml.safe_load((ROOT / "odp/catalog.yaml").read_text())["odps"]
    overlay = yaml.safe_load(overlay_path.read_text())
    vals = {e["param_id"]: e["value"] for e in (overlay.get("parameters") or [])}
    odps = {k: vals.get(k, v["default"]) for k, v in catalog.items()}

    controls = evaluate(art, odps)
    controls.append(inventory_reconciliation(args.iac_inventory, args.recorded_inventory))
    snap = fedramp.load()

    hdf = {
        "platform": {"name": "aws-conformance-packs/gov", "release": "1"},
        "version": "1",
        "profiles": [{
            "name": "gov-policy-evidence",
            "title": "GOV — policy artifact evidence for controls AWS Config cannot see",
            "summary": "Zero AWS Config rules by design. Evidence for the -1 policy "
                       "controls and other process artifacts, evaluated against a policy "
                       "repository. Existence alone never satisfies a control.",
            "version": "1.0.0",
            "supports": [],
            "attributes": [],
            "controls": controls,
            "groups": [],
            "sha256": "",
        }],
        "statistics": {},
        "passthrough": {
            "producer": "gov",
            "artifact_dir": str(art),
            "fedramp_snapshot": {"version": snap.version, "last_updated": snap.last_updated},
            "generated": datetime.now().isoformat(),
        },
    }
    args.out.mkdir(parents=True, exist_ok=True)
    p = args.out / "gov-policy-evidence.hdf.json"
    p.write_text(json.dumps(hdf, indent=2) + "\n")

    n_fail = sum(1 for c in controls if c.get("status") == "failed")
    n_skip = sum(1 for c in controls if c.get("status") == "skipped")
    print(f"wrote {p} — {len(controls)} control(s), {n_fail} failed, {n_skip} skipped")
    for c in controls:
        if c.get("status") == "failed":
            for r in c["results"]:
                if r["status"] == FAILED:
                    print(f"  FAIL {c['id']}: {r.get('message', r['code_desc'])[:110]}")
    # Findings are the output, not an error. A non-zero exit here would make a
    # non-compliant policy indistinguishable from a broken producer.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

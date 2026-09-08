#!/usr/bin/env python3
"""Render AWS Config conformance packs from a portable catalog plus an overlay.

    python3 generate.py --overlay overlays/vanilla.yaml --emit-oscal

THIS PROGRAM IS ALSO THE VALIDATOR. It fails rather than emitting a pack whose
thresholds nobody chose. A wrong value in a conformance pack does not crash: it
deploys, evaluates, and reports a clean result against a number that came from
nowhere. Every check below therefore exits non-zero rather than warning.

Resolution precedence, highest first:

    1. the overlay                 (an organization's decision)
    2. an OSCAL set-parameter      (a tailored profile's decision)
    3. the catalog default         (nobody's decision -- a fallback)

The winning source is recorded per value as `assigned_by` in the traceability
CSV. That column is the point: it is how an assessor distinguishes a threshold
somebody chose from one that merely rendered.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from tools.control_ids import is_control_id, normalize_control_id  # noqa: E402
from tools import aws_pack, fedramp  # noqa: E402

# Non-increasable AWS Config service limits.
MAX_RULES_PER_PACK = 130
MAX_PARAMS_PER_PACK = 60
MAX_INLINE_TEMPLATE_BYTES = 51_200
MAX_S3_TEMPLATE_BYTES = 300 * 1024

VALID_BASELINES = ("low", "moderate", "high")
VALID_COVERAGE = ("full", "partial", "supporting")


class GenerationError(Exception):
    """Raised for any condition that must stop a pack from being emitted."""


@dataclass
class Resolved:
    """One ODP value, and where it came from."""
    odp_key: str
    value: object
    assigned_by: str          # overlay | oscal-set-parameter | catalog-default
    oscal_param_id: str
    oscal_alt_id: str
    control: str


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise GenerationError(f"{path} does not exist")
    try:
        return yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise GenerationError(f"{path} does not parse: {exc}") from exc


def _violates(value, odp: dict) -> str | None:
    typ, con = odp.get("type"), odp.get("constraint") or {}
    if typ == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"expected an integer, got {type(value).__name__} ({value!r})"
        if (lo := con.get("min")) is not None and value < lo:
            return f"{value} is below the minimum of {lo}"
        if (hi := con.get("max")) is not None and value > hi:
            return f"{value} is above the maximum of {hi}"
    elif typ == "boolean" and not isinstance(value, bool):
        return f"expected a boolean, got {type(value).__name__} ({value!r})"
    elif typ == "enum" and value not in (con.get("values") or []):
        return f"{value!r} is not one of {con.get('values')}"
    elif typ == "string" and not isinstance(value, str):
        return f"expected a string, got {type(value).__name__} ({value!r})"
    elif typ == "duration":
        if not isinstance(value, dict) or set(value) != {"value", "unit"}:
            return f"expected a mapping with exactly `value` and `unit`, got {value!r}"
        v, u = value["value"], value["unit"]
        if isinstance(v, bool) or not isinstance(v, int):
            return f"value {v!r} is not an integer"
        units = con.get("units") or []
        if u not in units:
            return f"unit {u!r} is not one of {units}"
        if (lo := con.get("min")) is not None and v < lo:
            return f"{v} is below the minimum of {lo}"
        if (hi := con.get("max")) is not None and v > hi:
            return f"{v} is above the maximum of {hi}"
    elif typ == "list":
        if not isinstance(value, list):
            return f"expected a list, got {type(value).__name__} ({value!r})"
        if (mx := con.get("max_items")) is not None and len(value) > mx:
            return (f"{len(value)} items exceeds max_items {mx}. This is not a style "
                    f"limit: past it the extra entries are never rendered, so they go "
                    f"unchecked while the catalog claims otherwise")
        it = odp.get("item_type")
        for v in value:
            if it == "integer":
                if isinstance(v, bool) or not isinstance(v, int):
                    return f"item {v!r} is not an integer"
                if (lo := con.get("item_min")) is not None and v < lo:
                    return f"item {v} is below item_min {lo}"
                if (hi := con.get("item_max")) is not None and v > hi:
                    return f"item {v} is above item_max {hi}"
            elif it == "string" and not isinstance(v, str):
                return f"item {v!r} is not a string"
    return None


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------

def resolve(catalog: dict, overlay: dict, oscal: dict | None) -> dict[str, Resolved]:
    """Apply precedence and validate every resulting value.

    An out-of-range value is rejected wherever it came from. A tailored OSCAL
    profile is not more trusted than an overlay -- both are inputs, and the
    catalog's constraint is what says a value is legal.
    """
    odps = catalog.get("odps") or {}

    overlay_vals: dict[str, object] = {}
    for entry in overlay.get("parameters") or []:
        pid = entry.get("param_id")
        if pid not in odps:
            raise GenerationError(
                f"overlay sets param_id {pid!r}, which odp/catalog.yaml does not "
                f"declare. It would render nothing while looking like an applied "
                f"decision."
            )
        overlay_vals[pid] = entry.get("value")

    # An OSCAL set-parameter file is keyed by OSCAL param id, so it may address
    # several of our ODPs at once -- which is exactly the many-to-one case the
    # catalog exists to model.
    oscal_vals: dict[str, object] = {}
    if oscal:
        by_oscal: dict[str, list[str]] = {}
        for key, odp in odps.items():
            by_oscal.setdefault(odp["oscal_param_id"], []).append(key)
            by_oscal.setdefault(odp["oscal_alt_id"], []).append(key)
        for sp in oscal.get("set-parameters") or oscal.get("set_parameters") or []:
            pid = sp.get("param-id") or sp.get("param_id")
            vals = sp.get("values") or ([sp["value"]] if "value" in sp else [])
            targets = by_oscal.get(pid)
            if not targets:
                raise GenerationError(
                    f"OSCAL set-parameter names {pid!r}, which no ODP in "
                    f"odp/catalog.yaml joins to."
                )
            if len(vals) != 1:
                raise GenerationError(
                    f"OSCAL set-parameter {pid!r} carries {len(vals)} values; "
                    f"exactly one is required to bind a rule parameter."
                )
            for t in targets:
                oscal_vals[t] = vals[0]

    resolved: dict[str, Resolved] = {}
    for key, odp in odps.items():
        if key in overlay_vals:
            value, src = overlay_vals[key], "overlay"
        elif key in oscal_vals:
            value, src = oscal_vals[key], "oscal-set-parameter"
        else:
            value, src = odp["default"], "catalog-default"

        # An OSCAL file carries strings; coerce before checking so a correct
        # value is not rejected for its JSON type.
        if odp["type"] == "integer" and isinstance(value, str) and value.strip().lstrip("-").isdigit():
            value = int(value)

        if (why := _violates(value, odp)):
            raise GenerationError(f"ODP {key} (from {src}): {why}")

        resolved[key] = Resolved(
            odp_key=key, value=value, assigned_by=src,
            oscal_param_id=odp["oscal_param_id"], oscal_alt_id=odp["oscal_alt_id"],
            control=normalize_control_id(odp["control"]),
        )
    return resolved


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _cfn_param_name(rule_name: str, param: str) -> str:
    """awslabs naming: IamPasswordPolicyParamMinimumPasswordLength."""
    rule_camel = "".join(p.capitalize() for p in rule_name.split("-"))
    return f"{rule_camel}Param{param[0].upper()}{param[1:]}"


def _rule_logical_id(rule_name: str) -> str:
    return "".join(p.capitalize() for p in rule_name.split("-"))


def _rendered_description(rule: dict) -> str:
    """The description an operator sees in the Config console.

    A caveat that lives only in the catalog is a caveat nobody reads. Issue #2 is
    explicit that the Identity Center and phishing-resistance limits belong in the
    rendered description, so they travel with the deployed rule.
    """
    ctrls = ", ".join(normalize_control_id(c) for c in rule["controls"].get("nist_800_53_r5", []))
    ksis = ", ".join(rule["controls"].get("ksi", []))
    # AWS::Config::ConfigRule inside a conformance pack does NOT support Tags, so
    # Description is the only field that travels with the deployed artifact. An
    # adopter reading the Config console -- or anyone handed the template without
    # our sidecar CSV -- otherwise cannot tell which control a rule serves.
    prefix = f"[800-53r5: {ctrls}]"
    if ksis:
        prefix += f" [20x: {ksis}]"
    prefix += f" [coverage: {rule['coverage']}]"
    parts = [prefix, " ".join((rule.get("description") or "").split())]
    if note := rule.get("coverage_note"):
        parts.append(f"COVERAGE ({rule['coverage']}): {' '.join(note.split())}")
    if note := rule.get("periodic_note"):
        parts.append(f"TIMING: {' '.join(note.split())}")
    # IPv6 is the silent gap in boundary rules: several managed rules evaluate
    # 0.0.0.0/0 and not ::/0. An operator cannot tell from a PASS, so say it here.
    ipv6 = rule.get("ipv6_evaluated")
    if ipv6 is False:
        parts.append("IPv6: NOT evaluated by this rule -- a resource open on ::/0 "
                     "can pass. Do not read a PASS as dual-stack coverage.")
    elif ipv6 == "unknown":
        parts.append("IPv6: UNVERIFIED for this rule. Confirm against a live account "
                     "before relying on it for a dual-stack boundary.")
    return " ".join(parts)


def render_pack(catalog: dict, rules_doc: dict, resolved: dict[str, Resolved],
                baseline: str) -> tuple[dict, list[dict], list[dict]]:
    """Build the CloudFormation template and the traceability rows.

    Emits the awslabs shape -- Parameter(Default) + Condition(not-empty) +
    Fn::If -> Ref | AWS::NoValue. Copied rather than invented for two reasons:
    it is what the packs already deployed in this estate look like, and passing
    an empty string at deploy time falls back to the managed rule's own default,
    which a bare `Ref` would lose.
    """
    odps = catalog["odps"]
    parameters, conditions, resources, trace = {}, {}, {}, []
    excluded: list[dict] = []

    for rule_name, rule in (rules_doc.get("rules") or {}).items():
        rule_params: dict[str, object] = {}

        # A rule binding an ODP whose control is outside the TARGET baseline is
        # skipped, not fatal. Failing the build would make a Low pack
        # ungeneratable from any catalog containing a Moderate-only rule, which
        # is not a safety property -- it just means Low cannot be built.
        #
        # But an exclusion must never be inferred from absence. It is recorded
        # with its reason and rendered into the coverage report, so a smaller
        # pack is visibly smaller BECAUSE the baseline does not ask for those
        # controls -- not silently missing them.
        out_of_baseline = [
            (param, b["odp"], odps[b["odp"]]["control"])
            for param, b in (rule.get("parameters") or {}).items()
            if "literal" not in b and b.get("odp") in odps
            and baseline not in (odps[b["odp"]].get("baselines") or [])
        ] + [
            # Guard rules bind ODPs through `tokens`, not `parameters`. Without
            # this they took the fatal path while managed rules took the exclusion
            # path -- and a Low pack containing any Guard rule became
            # ungeneratable again, which is the bug this whole branch fixed once.
            (f"guard:{token}", key, odps[key]["control"])
            for token, key in (rule.get("tokens") or {}).items()
            if key in odps and baseline not in (odps[key].get("baselines") or [])
        ]
        if out_of_baseline:
            excluded.append({
                "rule": rule_name,
                "reason": f"binds ODP(s) whose control is not in the {baseline} baseline",
                "detail": "; ".join(f"{p} -> {o} ({c})" for p, o, c in out_of_baseline),
                "controls": [normalize_control_id(c)
                             for c in rule["controls"].get("nist_800_53_r5", [])],
            })
            continue

        for param, binding in (rule.get("parameters") or {}).items():
            # A literal is a fixed assertion, not an organizational decision --
            # alarmActionRequired=true is what the rule MEANS, not something a
            # tenant tailors. Kept distinct from an ODP so it never appears in
            # traceability as a value somebody chose.
            if "literal" in binding:
                cfn_name = _cfn_param_name(rule_name, param)
                cond_name = cfn_name[0].lower() + cfn_name[1:]
                parameters[cfn_name] = {"Default": str(binding["literal"]), "Type": "String"}
                conditions[cond_name] = {"Fn::Not": [{"Fn::Equals": ["", {"Ref": cfn_name}]}]}
                rule_params[param] = {
                    "Fn::If": [cond_name, {"Ref": cfn_name}, {"Ref": "AWS::NoValue"}]}
                continue

            key = binding.get("odp")
            if key not in odps:
                raise GenerationError(
                    f"rule {rule_name}.{param} binds ODP {key!r}, which "
                    f"odp/catalog.yaml does not declare."
                )
            odp = odps[key]
            # An evidence-only ODP is one no managed rule can enforce. Binding it
            # to a rule parameter would make an unenforceable value look enforced,
            # which is the single thing this catalog most exists to prevent.
            if odp.get("evidence_only"):
                raise GenerationError(
                    f"rule {rule_name}.{param} binds ODP {key}, which is declared "
                    f"`evidence_only`. An evidence-only ODP has no rule that can "
                    f"enforce it; binding it to a parameter would make an "
                    f"unenforceable value look like a control."
                )
            r = resolved[key]

            # Some managed rules take a list as N discrete numbered parameters
            # rather than one delimited string -- RESTRICTED_INCOMING_TRAFFIC
            # exposes blockedPort1..blockedPort5. `expand` says how many slots the
            # rule actually has.
            #
            # This is the check issue #3 asks for. A sixth port does NOT error at
            # deploy time; it is simply never rendered, so it goes unchecked while
            # the catalog claims it is blocked. That is a false assurance, so it
            # fails the build here.
            expand = binding.get("expand")
            if expand:
                if not isinstance(r.value, list):
                    raise GenerationError(
                        f"rule {rule_name}.{param} uses `expand` but ODP {key} is "
                        f"{odp['type']}, not a list."
                    )
                if len(r.value) > expand:
                    raise GenerationError(
                        f"rule {rule_name}.{param}: ODP {key} has {len(r.value)} "
                        f"items but the rule exposes only {expand} slots "
                        f"({param.replace('{n}', '1')}..{param.replace('{n}', str(expand))}). "
                        f"The extra entries would never be rendered and would go "
                        f"unchecked while appearing configured. Move this rule to a "
                        f"Guard policy, or shorten the list."
                    )
                for idx, item in enumerate(r.value, start=1):
                    slot = param.replace("{n}", str(idx))
                    cfn_name = _cfn_param_name(rule_name, slot)
                    cond_name = cfn_name[0].lower() + cfn_name[1:]
                    parameters[cfn_name] = {"Default": str(item), "Type": "String"}
                    conditions[cond_name] = {
                        "Fn::Not": [{"Fn::Equals": ["", {"Ref": cfn_name}]}]}
                    rule_params[slot] = {
                        "Fn::If": [cond_name, {"Ref": cfn_name}, {"Ref": "AWS::NoValue"}]}
            elif "derive" in binding:
                # A duration ODP drives BOTH requiredFrequencyValue and
                # requiredFrequencyUnit from ONE source, so the pair is
                # structurally incapable of disagreeing. Issue #7: a mismatched
                # unit silently changes the meaning of the check by a factor of
                # 24, and validating the two independently cannot catch it.
                facet = binding["derive"]
                if not isinstance(r.value, dict) or facet not in r.value:
                    raise GenerationError(
                        f"rule {rule_name}.{param}: `derive: {facet}` needs ODP "
                        f"{key} to be a duration with that facet; got {r.value!r}."
                    )
                rendered = str(r.value[facet])
                cfn_name = _cfn_param_name(rule_name, param)
                cond_name = cfn_name[0].lower() + cfn_name[1:]
                parameters[cfn_name] = {"Default": rendered, "Type": "String"}
                conditions[cond_name] = {"Fn::Not": [{"Fn::Equals": ["", {"Ref": cfn_name}]}]}
                rule_params[param] = {
                    "Fn::If": [cond_name, {"Ref": cfn_name}, {"Ref": "AWS::NoValue"}]}
                for control in rule["controls"].get("nist_800_53_r5", []):
                    trace.append({
                        "pack": rules_doc["pack_slug"], "rule": rule_name,
                        "control": normalize_control_id(control),
                        "ksi": ";".join(rule["controls"].get("ksi", [])),
                        "coverage": rule["coverage"], "odp": key,
                        "oscal_param_id": r.oscal_param_id, "oscal_alt_id": r.oscal_alt_id,
                        "parameter": param, "value": rendered,
                        "assigned_by": r.assigned_by,
                    })
            else:
                # A list with no `expand` renders as one comma-joined string,
                # which is how authorizedTcpPorts and friends take it.
                rendered = (",".join(str(v) for v in r.value)
                            if isinstance(r.value, list) else str(r.value))
                cfn_name = _cfn_param_name(rule_name, param)
                cond_name = cfn_name[0].lower() + cfn_name[1:]
                parameters[cfn_name] = {"Default": rendered, "Type": "String"}
                conditions[cond_name] = {"Fn::Not": [{"Fn::Equals": ["", {"Ref": cfn_name}]}]}
                rule_params[param] = {
                    "Fn::If": [cond_name, {"Ref": cfn_name}, {"Ref": "AWS::NoValue"}]}

            for control in rule["controls"].get("nist_800_53_r5", []):
                trace.append({
                    "pack": rules_doc["pack_slug"], "rule": rule_name,
                    "control": normalize_control_id(control),
                    "ksi": ";".join(rule["controls"].get("ksi", [])),
                    "coverage": rule["coverage"], "odp": key,
                    "oscal_param_id": r.oscal_param_id, "oscal_alt_id": r.oscal_alt_id,
                    "parameter": param, "assigned_by": r.assigned_by,
                    "value": (",".join(str(v) for v in r.value)
                              if isinstance(r.value, list) else r.value),
                })

        if rule.get("source") == "guard":
            # CUSTOM_POLICY rules do NOT accept InputParameters. Every ODP value a
            # Guard policy needs is substituted into the policy TEXT here, at
            # generation time -- which is why a Guard-bound ODP always means
            # regenerate + redeploy rather than a stack parameter update.
            policy_path = Path("guard") / rule["policy"]
            if not policy_path.exists():
                raise GenerationError(
                    f"rule {rule_name}: policy {policy_path} does not exist")
            text = policy_path.read_text()

            for token, key in (rule.get("tokens") or {}).items():
                if key not in odps:
                    raise GenerationError(
                        f"rule {rule_name}: token {{{{{token}}}}} binds ODP {key!r}, "
                        f"which odp/catalog.yaml does not declare."
                    )
                r = resolved[key]
                val = (", ".join(f'"{v}"' for v in r.value)
                       if isinstance(r.value, list) else str(r.value))
                if f"{{{{{token}}}}}" not in text:
                    raise GenerationError(
                        f"rule {rule_name}: declares token {{{{{token}}}}} but "
                        f"{policy_path} contains no such placeholder. A declared "
                        f"binding that substitutes nothing is a threshold that "
                        f"silently does not apply."
                    )
                text = text.replace(f"{{{{{token}}}}}", val)

                for control in rule["controls"].get("nist_800_53_r5", []):
                    trace.append({
                        "pack": rules_doc["pack_slug"], "rule": rule_name,
                        "control": normalize_control_id(control),
                        "ksi": ";".join(rule["controls"].get("ksi", [])),
                        "coverage": rule["coverage"], "odp": key,
                        "oscal_param_id": r.oscal_param_id,
                        "oscal_alt_id": r.oscal_alt_id,
                        "parameter": f"guard:{token}", "assigned_by": r.assigned_by,
                        "value": (",".join(str(v) for v in r.value)
                                  if isinstance(r.value, list) else r.value),
                    })

            if left := re.findall(r"\{\{(\w+)\}\}", text):
                raise GenerationError(
                    f"rule {rule_name}: {policy_path} still contains unsubstituted "
                    f"token(s) {sorted(set(left))}. Guard does NOT error on a live "
                    f"placeholder -- it evaluates against the literal text and the "
                    f"rule reports a result nobody should trust."
                )

            props = {
                "ConfigRuleName": rule_name,
                "Description": _rendered_description(rule),
                "Source": {
                    "Owner": "CUSTOM_POLICY",
                    "SourceDetails": [{
                        "EventSource": "aws.config",
                        "MessageType": "ConfigurationItemChangeNotification",
                    }],
                    "CustomPolicyDetails": {
                        "PolicyRuntime": rule.get("policy_runtime", "guard-2.x.x"),
                        "PolicyText": text,
                        "EnableDebugLogDelivery": False,
                    },
                },
            }
        else:
            props = {
                "ConfigRuleName": rule_name,
                "Description": _rendered_description(rule),
                "Source": {"Owner": "AWS", "SourceIdentifier": rule["identifier"]},
            }
            if rule_params:
                props["InputParameters"] = rule_params
        if scope := rule.get("resource_types"):
            props["Scope"] = {"ComplianceResourceTypes": scope}
        resources[_rule_logical_id(rule_name)] = {
            "Type": "AWS::Config::ConfigRule", "Properties": props,
        }

        # A rule that contributed no ODP-bound row still crosswalks. Testing for
        # "has no parameters" was not enough: a rule whose parameters are ALL
        # literals has parameters, binds no ODP, and so produced nothing at all --
        # it vanished from traceability and the pack under-reported its own
        # coverage. Test what was actually emitted, not what was declared.
        if not any(t["rule"] == rule_name for t in trace):
            for control in rule["controls"].get("nist_800_53_r5", []):
                trace.append({
                    "pack": rules_doc["pack_slug"], "rule": rule_name,
                    "control": normalize_control_id(control),
                    "ksi": ";".join(rule["controls"].get("ksi", [])),
                    "coverage": rule["coverage"], "odp": "", "oscal_param_id": "",
                    "oscal_alt_id": "", "parameter": "", "value": "", "assigned_by": "",
                })

    template = {
        "Description": (
            f"{rules_doc['domain']} conformance pack - NIST SP 800-53 Rev 5 "
            f"({baseline} baseline). Generated; do not edit by hand."
        ),
        "Parameters": parameters,
        "Conditions": conditions,
        "Resources": resources,
    }
    return template, trace, excluded


# ---------------------------------------------------------------------------
# validation of the rendered artifact
# ---------------------------------------------------------------------------

def validate_rendered(template: dict, body: bytes, rules_doc: dict) -> list[str]:
    """Cap checks against what was actually produced, not what was intended."""
    notes: list[str] = []
    n_rules = sum(1 for r in template["Resources"].values()
                  if r["Type"] == "AWS::Config::ConfigRule")
    n_params = len(template["Parameters"])

    if n_rules > MAX_RULES_PER_PACK:
        raise GenerationError(
            f"{rules_doc['pack_slug']}: {n_rules} rules exceeds the hard cap of "
            f"{MAX_RULES_PER_PACK}. Split the domain; the cap is not increasable."
        )
    if n_params > MAX_PARAMS_PER_PACK:
        raise GenerationError(
            f"{rules_doc['pack_slug']}: {n_params} parameters exceeds the hard cap "
            f"of {MAX_PARAMS_PER_PACK}. Past this, values must bake at generation "
            f"time and lose deploy-time tunability."
        )
    if len(body) > MAX_S3_TEMPLATE_BYTES:
        raise GenerationError(
            f"{rules_doc['pack_slug']}: {len(body)} bytes exceeds the "
            f"{MAX_S3_TEMPLATE_BYTES}-byte S3 template limit."
        )
    if len(body) > MAX_INLINE_TEMPLATE_BYTES:
        notes.append(
            f"{len(body)} bytes is over the {MAX_INLINE_TEMPLATE_BYTES}-byte inline "
            f"limit: stage in S3 and deploy with --template-s3-uri."
        )

    if b"{{" in body:
        raise GenerationError(
            f"{rules_doc['pack_slug']}: the rendered template still contains a "
            f"'{{{{' placeholder. An unsubstituted Guard token does not error at "
            f"deploy time -- it evaluates against the literal text and the rule "
            f"reports a result nobody should trust."
        )
    return notes


# ---------------------------------------------------------------------------
# emitters
# ---------------------------------------------------------------------------

TRACE_COLUMNS = ["pack", "rule", "control", "ksi", "coverage", "odp",
                 "oscal_param_id", "oscal_alt_id", "parameter", "value", "assigned_by"]


def emit(out_dir: Path, slug: str, template: dict, body: bytes, trace: list[dict],
         resolved: dict[str, Resolved], rules_doc: dict, baseline: str,
         notes: list[str], emit_oscal: bool, snap=None,
         excluded: list[dict] | None = None,
         catalog_odps: dict | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    p = out_dir / f"{slug}.yaml"; p.write_bytes(body); written.append(p)

    p = out_dir / f"{slug}.traceability.csv"
    with p.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=TRACE_COLUMNS)
        w.writeheader()
        w.writerows(sorted(trace, key=lambda r: (r["control"], r["rule"], r["parameter"])))
    written.append(p)

    # Evidence tags pair the control with THE VALUE THE CHECK MEASURED AGAINST.
    # A control id alone says a rule ran; it does not say what it required.
    p = out_dir / f"{slug}.evidence-tags.json"
    p.write_text(json.dumps({
        "pack": slug, "baseline": baseline, "region_scope": rules_doc.get("region_scope"),
        "fedramp_snapshot": {"version": getattr(snap, "version", "unknown"),
                             "last_updated": getattr(snap, "last_updated", "unknown")},
        # Declared, valued, and NOT ENFORCED BY ANY RULE. Present so the value is
        # visible in evidence rather than silently absent -- and named as
        # unenforced so it is never read as a control that passed.
        "evidence_only_odps": [
            {"odp": k, "control": normalize_control_id(o["control"]),
             "oscal_param_id": o["oscal_param_id"],
             "value": resolved[k].value, "assigned_by": resolved[k].assigned_by,
             "why_unenforced": o.get("evidence_only")}
            for k, o in sorted((catalog_odps or {}).items()) if o.get("evidence_only")
        ],
        "rules": [
            {
                "rule": name,
                "controls": [normalize_control_id(c) for c in r["controls"].get("nist_800_53_r5", [])],
                "ksi": r["controls"].get("ksi", []),
                "coverage": r["coverage"],
                # A literal is recorded with assigned_by "rule-literal" so it is
                # never mistaken for a threshold a tenant chose. That distinction
                # is the entire point of the provenance column.
                "measured_against": {
                    param: (
                        {"odp": b["odp"], "value": resolved[b["odp"]].value,
                         "assigned_by": resolved[b["odp"]].assigned_by}
                        if "odp" in b else
                        {"odp": None, "value": b["literal"], "assigned_by": "rule-literal"}
                    )
                    for param, b in (r.get("parameters") or {}).items()
                },
            }
            for name, r in rules_doc["rules"].items()
        ],
    }, indent=2) + "\n")
    written.append(p)

    by_cov: dict[str, list[str]] = {}
    for name, r in rules_doc["rules"].items():
        by_cov.setdefault(r["coverage"], []).append(name)
    controls = sorted({row["control"] for row in trace})

    p = out_dir / f"{slug}.coverage.md"
    p.write_text(
        f"# {slug} — coverage\n\n"
        f"Baseline: **{baseline}** · Rules: **{len(rules_doc['rules'])}** · "
        f"Controls referenced: **{len(controls)}**\n\n"
        "## Read this denominator carefully\n\n"
        "The controls counted below are the ones **this catalog already references**, "
        "not the size of the baseline. A pack reporting high coverage means the "
        "controls it models are automated — never that the baseline is covered. Diff "
        "the catalog against the full tailored profile before reporting anything "
        "outward.\n\n"
        "`INSUFFICIENT_DATA` is not compliance. A rule with no in-scope resources "
        "reports insufficient data, which most dashboards render as \"not failing\".\n\n"
        + (f"**Region scope: {rules_doc['region_scope']}.** These resource types are "
           "recorded in exactly one Region; deployed elsewhere every rule reports "
           "`INSUFFICIENT_DATA`.\n\n" if rules_doc.get("region_scope") == "global" else "")
        + "## Coverage by rule\n\n| Coverage | Rules |\n|---|---|\n"
        + "".join(f"| `{k}` | {', '.join(sorted(v))} |\n" for k, v in sorted(by_cov.items()))
        + (f"\n## Domain caveat\n\n{' '.join(rules_doc['domain_caveat'].split())}\n"
           if rules_doc.get("domain_caveat") else "")
        + ("\n## Not modeled by any rule in this pack\n\nThese indicators are in "
           "scope for the domain and are deliberately NOT forced onto a Config rule. "
           "Saying so is the point: a rule bolted onto an indicator it cannot measure "
           "is worse than an acknowledged gap.\n\n"
           "| Indicator | Why not |\n|---|---|\n"
           + "".join(f"| `{k}` | {' '.join(v.split())} |\n"
                     for k, v in (rules_doc.get("not_modeled") or {}).items()) + "\n"
           if rules_doc.get("not_modeled") else "")
        + ("\n## Excluded from this baseline\n\nThese rules are NOT in this pack. They are "
           "absent because the controls they bind are not in the " + baseline + " baseline -- "
           "not because they were forgotten. Coverage must never be inferred from absence.\n\n"
           "| Rule | Controls | Reason |\n|---|---|---|\n"
           + "".join(f"| `{e['rule']}` | {', '.join(e['controls'])} | {e['detail']} |\n"
                     for e in excluded) + "\n" if excluded else "")
        + ("\n## Declared but NOT ENFORCED\n\nThese organization-defined parameters have "
           "a value and appear in the evidence tags, and **no rule in this pack enforces "
           "them**. No managed rule exposes the knob. They are listed so the value is "
           "visible rather than silently absent — never as a control that passed.\n\n"
           "| ODP | Control | Why unenforced |\n|---|---|---|\n"
           + "".join(f"| `{k}` | {normalize_control_id(o['control'])} | "
                     f"{' '.join(str(o['evidence_only']).split())} |\n"
                     for k, o in sorted((catalog_odps or {}).items()) if o.get("evidence_only"))
           + "\n" if any(o.get("evidence_only") for o in (catalog_odps or {}).values()) else "")
        + ("\n## Not verifiable against AWS's published pack\n\nThese rules are "
           "real, but absent from AWS's own NIST 800-53 Rev 5 conformance pack, so "
           "their identifier and parameter names could not be checked against a "
           "published AWS artifact. A wrong identifier does not fail at deploy time "
           "-- it reports `INSUFFICIENT_DATA` forever. Confirm these on first live "
           "deploy.\n\n| Rule | Note |\n|---|---|\n"
           + "".join(f"| `{n}` | {' '.join(r['not_in_aws_pack'].split())} |\n"
                     for n, r in rules_doc["rules"].items() if r.get("not_in_aws_pack"))
           + "\n" if any(r.get("not_in_aws_pack") for r in rules_doc["rules"].values()) else "")
        + ("\n## IPv6 evaluation\n\n| Rule | IPv6 evaluated |\n|---|---|\n"
           + "".join(f"| `{n}` | {r.get('ipv6_evaluated', 'not recorded')} |\n"
                     for n, r in rules_doc["rules"].items()
                     if "ipv6_evaluated" in r) + "\n"
           if any("ipv6_evaluated" in r for r in rules_doc["rules"].values()) else "")
        + "\n## Recorder prerequisite\n\nEvery rule here is inert unless the recorder "
          "captures:\n\n"
        + "".join(f"- `{t}`\n" for t in rules_doc.get("required_resource_types", []))
        + ("\n## Notes\n\n" + "".join(f"- {n}\n" for n in notes) if notes else "")
    )
    written.append(p)

    if emit_oscal:
        p = out_dir / f"{slug}.oscal-set-params.json"
        p.write_text(json.dumps({
            "set-parameters": [
                {"param-id": r.oscal_param_id, "values": [str(r.value)],
                 "remarks": f"{r.odp_key} (assigned_by: {r.assigned_by})"}
                for r in sorted(resolved.values(), key=lambda x: x.oscal_param_id)
            ]
        }, indent=2) + "\n")
        written.append(p)

    return written


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--overlay", type=Path, required=True)
    ap.add_argument("--catalog", type=Path, default=Path("odp/catalog.yaml"))
    ap.add_argument("--rules", type=Path, nargs="*", default=None,
                    help="rule catalogs; default every rules/*.yaml")
    ap.add_argument("--set-parameters-from", type=Path, default=None,
                    help="OSCAL set-parameter JSON; loses to the overlay, beats the default")
    ap.add_argument("--baseline", choices=VALID_BASELINES, default=None,
                    help="override the overlay's baseline_level")
    ap.add_argument("--out", type=Path, default=Path("out"))
    ap.add_argument("--emit-oscal", action="store_true")
    args = ap.parse_args()

    try:
        catalog = _load_yaml(args.catalog)
        overlay = _load_yaml(args.overlay)
        oscal = None
        if args.set_parameters_from:
            oscal = json.loads(args.set_parameters_from.read_text())

        baseline = args.baseline or overlay.get("baseline_level")
        if baseline not in VALID_BASELINES:
            raise GenerationError(
                f"baseline {baseline!r} is not one of {list(VALID_BASELINES)}; set "
                f"`baseline_level` in the overlay or pass --baseline"
            )

        rule_files = args.rules if args.rules else sorted(Path("rules").glob("*.yaml"))
        if not rule_files:
            raise GenerationError("no rule catalogs found under rules/")

        snap = fedramp.load()
        awsp = aws_pack.load()
        resolved = resolve(catalog, overlay, oscal)

        for rf in rule_files:
            rules_doc = _load_yaml(Path(rf))
            for name, rule in (rules_doc.get("rules") or {}).items():
                if rule.get("coverage") not in VALID_COVERAGE:
                    raise GenerationError(
                        f"{rf}:{name}: coverage {rule.get('coverage')!r} is not one of "
                        f"{list(VALID_COVERAGE)}"
                    )
                if rule.get("coverage") in ("partial", "supporting") and not rule.get("coverage_note"):
                    raise GenerationError(
                        f"{rf}:{name}: coverage is {rule['coverage']!r} but no "
                        f"`coverage_note` says why. An unexplained partial is "
                        f"indistinguishable from an overstated full."
                    )
                for c in rule.get("controls", {}).get("nist_800_53_r5", []):
                    if not is_control_id(c):
                        raise GenerationError(
                            f"{rf}:{name}: {c!r} is not a control id. A KSI belongs "
                            f"under `ksi:`, not in the 800-53 crosswalk."
                        )
                # Every KSI must EXIST in the vendored FedRAMP snapshot, and must
                # actually claim one of this rule's controls. The first check kills
                # stale ids -- FedRAMP re-keyed every indicator from numbered to
                # mnemonic form and nothing in this estate noticed. The second kills
                # a plausible-looking but wrong assignment, which is the failure a
                # shape-only check cannot see.
                # Verify the managed rule against AWS's own published pack.
                # An identifier or parameter name asserted from documentation and
                # never checked is the defect class this catches: it does not fail
                # at generation, it fails at put-conformance-pack -- or it deploys
                # and reports INSUFFICIENT_DATA forever, which reads as "not
                # failing" on every dashboard.
                if rule.get("source") == "managed":
                    known = awsp.get(name, rule.get("identifier"))
                    excuse = rule.get("not_in_aws_pack")
                    if known is None and not excuse:
                        raise GenerationError(
                            f"{rf}:{name}: neither the rule name nor identifier "
                            f"{rule.get('identifier')!r} appears in AWS's published "
                            f"NIST 800-53 Rev 5 pack. If the rule is real but newer "
                            f"than that pack, say so explicitly with "
                            f"`not_in_aws_pack: <reason>` -- an unverified identifier "
                            f"does not fail at deploy time, it reports "
                            f"INSUFFICIENT_DATA forever."
                        )
                    if known is not None:
                        if known.identifier and rule.get("identifier") != known.identifier:
                            raise GenerationError(
                                f"{rf}:{name}: identifier is {rule.get('identifier')!r} "
                                f"but AWS publishes {known.identifier!r} for this rule."
                            )
                        declared = {p.replace("{n}", "1")
                                    for p in (rule.get("parameters") or {})}
                        unknown = {d for d in declared if d not in known.parameters}
                        if unknown and known.parameters:
                            raise GenerationError(
                                f"{rf}:{name}: parameter(s) {sorted(unknown)} are not "
                                f"published for this rule. AWS accepts "
                                f"{sorted(known.parameters)}. An unrecognised "
                                f"InputParameter is ignored at evaluation time, so the "
                                f"threshold silently does not apply."
                            )

                rule_controls = {normalize_control_id(c)
                                 for c in rule.get("controls", {}).get("nist_800_53_r5", [])}
                for k in rule.get("controls", {}).get("ksi", []):
                    ind = snap.indicators.get(k)
                    if ind is None:
                        hint = fedramp.suggest(k, snap)
                        raise GenerationError(
                            f"{rf}:{name}: {k!r} is not an indicator in the vendored "
                            f"FedRAMP snapshot ({snap.version}). "
                            + (f"Candidates in the successor family: {', '.join(hint)}. "
                               f"The re-key is NOT 1:1 -- choose deliberately."
                               if hint else
                               "That family no longer exists; there is no successor.")
                        )
                    if not (rule_controls & {normalize_control_id(c) for c in ind.controls}):
                        raise GenerationError(
                            f"{rf}:{name}: {k} ({ind.name}) claims none of this rule's "
                            f"controls {sorted(rule_controls)}. FedRAMP publishes each "
                            f"indicator's own crosswalk; an assignment that does not "
                            f"intersect it is asserting coverage FedRAMP does not."
                        )

            template, trace, excluded = render_pack(catalog, rules_doc, resolved, baseline)
            body = yaml.safe_dump(template, sort_keys=False, width=100).encode()
            notes = validate_rendered(template, body, rules_doc)

            slug = rules_doc["pack_slug"]
            written = emit(args.out, slug, template, body, trace, resolved,
                           rules_doc, baseline, notes, args.emit_oscal, snap, excluded,
                           catalog.get('odps'))

            n_rules = len(rules_doc["rules"])
            rendered = sum(1 for r in template["Resources"].values()
                           if r["Type"] == "AWS::Config::ConfigRule")
            print(f"{slug} [{baseline}]: {rendered} rules, {len(template['Parameters'])} "
                  f"parameters, {len(body)} bytes, {len(trace)} traceability rows")
            for e in excluded:
                print(f"  excluded: {e['rule']} — {e['reason']}")
            for n in notes:
                print(f"  note: {n}")
            for p in written:
                print(f"  wrote {p}")

    except GenerationError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

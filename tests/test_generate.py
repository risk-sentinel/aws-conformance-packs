"""Generator tests, weighted toward the failures that matter.

A conformance pack does not crash when it is wrong. It deploys, evaluates, and
reports a clean result against a threshold nobody chose. So most of what is
tested here is that the generator REFUSES -- a guard that has never been shown to
fail is not a guard.

    python3 -m pytest tests/test_generate.py -q
"""

from __future__ import annotations

import copy
from datetime import date
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate  # noqa: E402
from tools.control_ids import normalize_control_id  # noqa: E402
from generate import GenerationError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CATALOG = yaml.safe_load((ROOT / "odp/catalog.yaml").read_text())
OVERLAY = yaml.safe_load((ROOT / "overlays/vanilla.yaml").read_text())
RULES = yaml.safe_load((ROOT / "rules/iam.yaml").read_text())


def cat(): return copy.deepcopy(CATALOG)
def ov(): return copy.deepcopy(OVERLAY)
def rl(): return copy.deepcopy(RULES)


# --- precedence -------------------------------------------------------------

def test_overlay_wins_and_is_attributed():
    r = generate.resolve(cat(), ov(), None)
    assert r["password_minimum_length"].value == 14
    assert r["password_minimum_length"].assigned_by == "overlay"


def test_catalog_default_used_when_overlay_silent():
    o = ov()
    o["parameters"] = [p for p in o["parameters"] if p["param_id"] != "password_minimum_length"]
    r = generate.resolve(cat(), o, None)
    assert r["password_minimum_length"].value == 14
    # The value is identical to the overlay's; only `assigned_by` distinguishes a
    # decision from a fallback. That column is the entire point.
    assert r["password_minimum_length"].assigned_by == "catalog-default"


def test_oscal_beats_default_and_loses_to_overlay():
    o = ov()
    o["parameters"] = [p for p in o["parameters"] if p["param_id"] != "password_minimum_length"]
    oscal = {"set-parameters": [{"param-id": "ia-05.01_odp.02", "values": ["20"]}]}
    r = generate.resolve(cat(), o, oscal)
    assert r["password_minimum_length"].value == 20
    assert r["password_minimum_length"].assigned_by == "oscal-set-parameter"

    r2 = generate.resolve(cat(), ov(), oscal)          # overlay present this time
    assert r2["password_minimum_length"].value == 14
    assert r2["password_minimum_length"].assigned_by == "overlay"


def test_oscal_set_parameter_fans_out_to_every_joined_odp():
    """One OSCAL param legitimately drives several ODPs -- the many-to-one case."""
    o = ov()
    o["parameters"] = []
    oscal = {"set-parameters": [{"param-id": "ia-05.01_odp.02", "values": ["20"]}]}
    r = generate.resolve(cat(), o, oscal)
    for k in ("password_minimum_length", "password_maximum_age_days", "password_reuse_prevention"):
        assert r[k].value == 20, k
        assert r[k].assigned_by == "oscal-set-parameter"


def test_oscal_string_coerced_for_integer_odp():
    o = ov(); o["parameters"] = []
    oscal = {"set-parameters": [{"param-id": "ia-5_prm_1", "values": ["45"]}]}   # alt id
    r = generate.resolve(cat(), o, oscal)
    assert r["access_key_maximum_age_days"].value == 45


# --- resolution refusals ----------------------------------------------------

def test_overlay_value_out_of_range_refused():
    # Addressed by param_id, not by index: the overlay is grouped by control, so
    # position is not stable and an index-based mutation silently targets the
    # wrong ODP as the catalog grows.
    o = ov()
    for entry in o["parameters"]:
        if entry["param_id"] == "password_minimum_length":
            entry["value"] = 999
    with pytest.raises(GenerationError, match="above the maximum"):
        generate.resolve(cat(), o, None)


def test_oscal_value_out_of_range_refused():
    """A tailored profile is not more trusted than an overlay."""
    o = ov(); o["parameters"] = []
    oscal = {"set-parameters": [{"param-id": "ia-05.01_odp.02", "values": ["999"]}]}
    with pytest.raises(GenerationError, match="above the maximum"):
        generate.resolve(cat(), o, oscal)


def test_undeclared_overlay_param_refused():
    o = ov(); o["parameters"].append({"param_id": "nope", "value": 1})
    with pytest.raises(GenerationError, match="does not declare"):
        generate.resolve(cat(), o, None)


def test_unjoined_oscal_param_refused():
    oscal = {"set-parameters": [{"param-id": "zz-99_odp.01", "values": ["1"]}]}
    with pytest.raises(GenerationError, match="no ODP"):
        generate.resolve(cat(), ov(), oscal)


def test_multivalued_oscal_set_parameter_refused():
    oscal = {"set-parameters": [{"param-id": "ia-05_odp.01", "values": ["1", "2"]}]}
    with pytest.raises(GenerationError, match="carries 2 values"):
        generate.resolve(cat(), ov(), oscal)


# --- render refusals --------------------------------------------------------

def test_rule_binding_undeclared_odp_refused():
    r = rl(); r["rules"]["access-keys-rotated"]["parameters"]["maxAccessKeyAge"]["odp"] = "ghost"
    with pytest.raises(GenerationError, match="does not declare"):
        generate.render_pack(cat(), r, generate.resolve(cat(), ov(), None), "moderate")


def test_odp_outside_target_baseline_is_excluded_and_recorded():
    """ac-2.3 is absent from Low, so its rules must not render into a Low pack.

    Skipped rather than fatal: failing would make a Low pack ungeneratable from
    any catalog holding a Moderate-only rule, which is not a safety property. But
    the exclusion is RECORDED -- coverage must never be inferred from absence.
    """
    t, _, excluded = generate.render_pack(cat(), rl(), generate.resolve(cat(), ov(), None), "low")
    names = {e["rule"] for e in excluded}
    # ac-2.3 is absent from Low, so both rules binding it must go. Asserted as a
    # subset rather than an exact set: more rules legitimately join this list as
    # the catalog grows (ac-6.1 is Moderate+ too), and an exact-equality assertion
    # would fail on correct work.
    assert {"iam-user-unused-credentials-check", "secretsmanager-secret-unused"} <= names
    assert all("low baseline" in e["reason"] for e in excluded)
    assert all(e["detail"] and e["controls"] for e in excluded), "an exclusion must name what it cost"
    assert not any(n in t["Resources"] for n in ("IamUserUnusedCredentialsCheck",
                                                 "SecretsmanagerSecretUnused"))
    # ...and the rules the Low baseline DOES ask for are still there.
    assert "IamPasswordPolicy" in t["Resources"]


def test_low_baseline_coverage_report_states_the_exclusions(tmp_path):
    assert _run_cli(tmp_path, ["--baseline", "low"]) == 0
    md = (tmp_path / "out/800-53r5-IAM.coverage.md").read_text()
    assert "Excluded from this baseline" in md
    assert "iam-user-unused-credentials-check" in md
    assert "not because they were forgotten" in md


# --- cap and placeholder refusals -------------------------------------------

def _rendered(rules_doc, baseline="moderate"):
    t, _, _ = generate.render_pack(cat(), rules_doc, generate.resolve(cat(), ov(), None), baseline)
    return t, yaml.safe_dump(t, sort_keys=False).encode()


def test_rule_cap_refused():
    t, body = _rendered(rl())
    one = next(iter(t["Resources"].values()))
    for i in range(generate.MAX_RULES_PER_PACK + 1):
        t["Resources"][f"Filler{i}"] = copy.deepcopy(one)
    with pytest.raises(GenerationError, match="exceeds the hard cap of 130"):
        generate.validate_rendered(t, body, rl())


def test_parameter_cap_refused():
    t, body = _rendered(rl())
    for i in range(generate.MAX_PARAMS_PER_PACK + 1):
        t["Parameters"][f"Filler{i}"] = {"Type": "String", "Default": "1"}
    with pytest.raises(GenerationError, match="exceeds the hard cap of 60"):
        generate.validate_rendered(t, body, rl())


def test_s3_template_size_refused():
    t, _ = _rendered(rl())
    with pytest.raises(GenerationError, match="S3 template limit"):
        generate.validate_rendered(t, b"x" * (generate.MAX_S3_TEMPLATE_BYTES + 1), rl())


def test_inline_size_is_a_note_not_a_failure():
    """Over inline but under S3 is a real, deployable pack -- it just needs staging."""
    t, _ = _rendered(rl())
    notes = generate.validate_rendered(t, b"x" * (generate.MAX_INLINE_TEMPLATE_BYTES + 1), rl())
    assert any("template-s3-uri" in n for n in notes)


def test_unsubstituted_guard_token_refused():
    t, _ = _rendered(rl())
    with pytest.raises(GenerationError, match="placeholder"):
        generate.validate_rendered(t, b"Resources:\n  X:\n    P: {{RotationPeriodInDays}}\n", rl())


# --- honesty of the catalog itself ------------------------------------------

def test_partial_coverage_without_a_note_refused(tmp_path):
    r = rl(); r["rules"]["iam-user-mfa-enabled"].pop("coverage_note")
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    rc = _run_cli(tmp_path, ["--rules", str(tmp_path / "iam.yaml")])
    assert rc == 1


def test_ksi_in_the_800_53_column_refused(tmp_path):
    r = rl(); r["rules"]["iam-user-mfa-enabled"]["controls"]["nist_800_53_r5"] = ["KSI-IAM-01"]
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    assert _run_cli(tmp_path, ["--rules", str(tmp_path / "iam.yaml")]) == 1


def _run_cli(tmp_path, extra):
    import subprocess
    return subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--catalog", str(ROOT / "odp/catalog.yaml"), "--out", str(tmp_path / "out"), *extra],
        capture_output=True, text=True, cwd=ROOT,
    ).returncode


# --- emitted artifacts ------------------------------------------------------

def test_evidence_tags_pair_control_with_the_value_measured_against(tmp_path):
    assert _run_cli(tmp_path, []) == 0
    tags = json.loads((tmp_path / "out/800-53r5-IAM.evidence-tags.json").read_text())
    rule = next(r for r in tags["rules"] if r["rule"] == "iam-password-policy")
    m = rule["measured_against"]["MinimumPasswordLength"]
    assert m["value"] == 14 and m["assigned_by"] == "overlay"
    assert "ia-5.1" in rule["controls"]


def test_coverage_report_states_its_denominator(tmp_path):
    assert _run_cli(tmp_path, []) == 0
    md = (tmp_path / "out/800-53r5-IAM.coverage.md").read_text()
    assert "not the size of the baseline" in md
    assert "`INSUFFICIENT_DATA` is not compliance" in md
    assert "Region scope: global" in md


def test_control_ids_are_normalized_in_traceability(tmp_path):
    assert _run_cli(tmp_path, []) == 0
    csv_text = (tmp_path / "out/800-53r5-IAM.traceability.csv").read_text()
    assert "ac-2.3" in csv_text
    assert "AC-2(3)" not in csv_text and "ac-02.03," not in csv_text


# --- FedRAMP snapshot: the drift that already bit us -------------------------

def test_vendored_snapshot_loads_and_is_versioned():
    from tools import fedramp
    s = fedramp.load()
    assert s.version != "unknown" and s.indicators
    # FedRAMP publishes each indicator's own 800-53 crosswalk. This repository
    # consumes it and does not own its accuracy.
    assert any(i.controls for i in s.indicators.values())


def test_stale_numbered_ksi_id_refused_with_candidates(tmp_path):
    """The exact defect that shipped: KSI-IAM-01 no longer exists."""
    import subprocess
    r = rl(); r["rules"]["iam-user-mfa-enabled"]["controls"]["ksi"] = ["KSI-IAM-01"]
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "not an indicator" in proc.stderr
    assert "KSI-IAM-APM" in proc.stderr          # names real successors
    assert "NOT 1:1" in proc.stderr               # and refuses to pretend it is


def test_ksi_from_a_deleted_family_says_there_is_no_successor(tmp_path):
    """TPR is named in issue #8 and no longer exists in any form."""
    import subprocess
    r = rl(); r["rules"]["iam-user-mfa-enabled"]["controls"]["ksi"] = ["KSI-TPR-01"]
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "no successor" in proc.stderr


def test_real_ksi_that_claims_none_of_the_rules_controls_refused(tmp_path):
    """A shape-only check cannot see this: the id exists, the assignment is wrong."""
    import subprocess
    r = rl()
    # KSI-RPL-TRC is a real indicator; it claims no IAM MFA control.
    r["rules"]["iam-user-mfa-enabled"]["controls"]["ksi"] = ["KSI-RPL-TRC"]
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "claims none of this rule's controls" in proc.stderr


def test_deployed_rule_carries_its_own_crosswalk(tmp_path):
    """Conformance-pack rules do not support Tags, so Description is the only
    field that travels. Without this an adopter cannot tell what a rule serves."""
    assert _run_cli(tmp_path, []) == 0
    t = yaml.safe_load((tmp_path / "out/800-53r5-IAM.yaml").read_text())
    desc = t["Resources"]["IamPasswordPolicy"]["Properties"]["Description"]
    assert desc.startswith("[800-53r5: ia-5.1, ia-5] [20x: KSI-IAM-APM] [coverage: partial]")


def test_evidence_names_the_snapshot_it_was_assessed_against(tmp_path):
    assert _run_cli(tmp_path, []) == 0
    tags = json.loads((tmp_path / "out/800-53r5-IAM.evidence-tags.json").read_text())
    assert tags["fedramp_snapshot"]["version"] != "unknown"


# --- NET: list ODPs and the five-slot rule cap -------------------------------

NET = yaml.safe_load((ROOT / "rules/net.yaml").read_text())


def net(): return copy.deepcopy(NET)


def _ov_with(param_id, value):
    o = ov()
    o["parameters"] = [p for p in o["parameters"] if p["param_id"] != param_id]
    o["parameters"].append({"param_id": param_id, "value": value})
    return o


def test_list_odp_renders_as_numbered_slots():
    """RESTRICTED_INCOMING_TRAFFIC takes blockedPort1..5, not one list."""
    t, _, _ = generate.render_pack(cat(), net(), generate.resolve(cat(), ov(), None), "moderate")
    ip = t["Resources"]["RestrictedCommonPorts"]["Properties"]["InputParameters"]
    assert sorted(ip) == [f"blockedPort{i}" for i in range(1, 6)]


def test_list_odp_without_expand_renders_comma_joined():
    t, _, _ = generate.render_pack(cat(), net(), generate.resolve(cat(), ov(), None), "moderate")
    p = t["Parameters"]["VpcSgOpenOnlyToAuthorizedPortsParamAuthorizedTcpPorts"]
    assert p["Default"] == "443"


def test_too_many_ports_for_the_rules_slots_refused():
    """The guard issue #3 asks for. A 6th port does NOT error at deploy time --
    it is simply never rendered, so it goes unchecked while appearing set."""
    c = cat()
    c["odps"]["blocked_ingress_ports"]["constraint"]["max_items"] = 10   # catalog allows it
    o = _ov_with("blocked_ingress_ports", [20, 21, 23, 25, 3389, 3306, 4333])
    with pytest.raises(GenerationError, match="only 5 slots"):
        generate.render_pack(c, net(), generate.resolve(c, o, None), "moderate")


def test_list_item_out_of_range_refused():
    with pytest.raises(GenerationError, match="above item_max"):
        generate.resolve(cat(), _ov_with("blocked_ingress_ports", [70000]), None)


def test_list_item_of_wrong_type_refused():
    with pytest.raises(GenerationError, match="is not an integer"):
        generate.resolve(cat(), _ov_with("blocked_ingress_ports", [22, "ssh"]), None)


def test_scalar_where_a_list_is_declared_refused():
    with pytest.raises(GenerationError, match="expected a list"):
        generate.resolve(cat(), _ov_with("blocked_ingress_ports", 22), None)


def test_ipv6_gap_is_rendered_into_the_description():
    """An operator reading a green console cannot otherwise know."""
    t, _, _ = generate.render_pack(cat(), net(), generate.resolve(cat(), ov(), None), "moderate")
    d = t["Resources"]["SubnetAutoAssignPublicIpDisabled"]["Properties"]["Description"]
    assert "IPv6: NOT evaluated" in d
    d2 = t["Resources"]["VpcSgOpenOnlyToAuthorizedPorts"]["Properties"]["Description"]
    assert "IPv6: UNVERIFIED" in d2


def test_net_coverage_report_states_reachability_and_unmodeled(tmp_path):
    rc = _run_cli(tmp_path, ["--rules", str(ROOT / "rules/net.yaml")])
    assert rc == 0
    md = (tmp_path / "out/800-53r5-NET.coverage.md").read_text()
    assert "not as reachability" in md
    assert "Not modeled by any rule in this pack" in md
    # CNA-EIS stays unmodeled: redeploy-vs-modify is not a resource attribute.
    assert "KSI-CNA-EIS" in md
    assert "IPv6 evaluation" in md


def test_waf_rules_are_supporting_not_a_dos_claim():
    """A WAF association is not sc-5. Shield subscription state is not even a
    Config resource, so a PASS here must never read as DoS protection."""
    t, _, _ = generate.render_pack(cat(), net(), generate.resolve(cat(), ov(), None), "moderate")
    for logical in ("AlbWafEnabled", "ApiGwAssociatedWithWaf", "CloudfrontAssociatedWithWaf"):
        d = t["Resources"][logical]["Properties"]["Description"]
        assert "[coverage: supporting]" in d, logical
    assert "never read a PASS here as" in t["Resources"]["AlbWafEnabled"]["Properties"]["Description"]


def test_every_candidate_rule_named_in_the_issue_is_built():
    """Applies to EVERY domain with a rule catalog, not just NET.

    The first NET pass built 8 of 18 candidates and closed the issue, which let a
    status table redefine the target rather than record a shortfall. A domain with
    no catalog yet is not a failure -- it has not been started. A domain WITH a
    catalog that does not cover its issue is.
    """
    import re
    domains = {
        "iam": "01-identity-access", "net": "02-network-boundary",
        "crypto": "03-crypto-data-protection", "log": "04-logging-monitoring-audit",
        "vcm": "05-vuln-config-management", "rpl": "06-resilience-recovery",
    }
    started, shortfalls = [], {}
    for dom, issue in domains.items():
        cat = ROOT / f"rules/{dom}.yaml"
        if not cat.exists():
            continue
        started.append(dom)
        sec = (ROOT / f"issues/{issue}.md").read_text() \
            .split("## Candidate managed rules")[1].split("\n## ")[0]
        cands = {c for c in re.findall(r"`([a-z0-9]+(?:-[a-z0-9]+)+)`", sec) if not c.isupper()}
        # A rule an issue marks "(shared with NET)" is satisfied by being built
        # in the domain that owns it. The test asks whether any named rule goes
        # UNBUILT, not whether each domain re-declares rules it shares.
        built = set()
        for other in (ROOT / "rules").glob("*.yaml"):
            built |= set(yaml.safe_load(other.read_text())["rules"])
        if missing := cands - built:
            shortfalls[dom] = sorted(missing)
    assert started, "no rule catalogs found at all"
    assert not shortfalls, (
        "domain catalogs do not cover every candidate their issue names: "
        + "; ".join(f"{d} missing {len(m)} ({', '.join(m[:5])}...)"
                    for d, m in shortfalls.items())
    )


# --- verification against AWS's own published pack ---------------------------

def test_aws_index_loads_and_indexes_both_ways():
    from tools import aws_pack
    p = aws_pack.load()
    assert len(p.rules_by_name) > 400           # derived from ALL published packs
    r = p.get("iam-password-policy")
    assert r.identifier == "IAM_PASSWORD_POLICY"
    assert "MinimumPasswordLength" in r.parameters
    assert r.packs                               # the claim is traceable to a pack


def test_index_records_upstream_identifier_disagreements():
    """AWS's own packs disagree about two rules. A silent first- or last-wins
    could accept a wrong identifier as verified; the majority wins and the
    disagreement stays visible."""
    from tools import aws_pack
    r = aws_pack.load().get("autoscaling-multiple-az")
    assert r.identifier == "AUTOSCALING_MULTIPLE_AZ"
    assert "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED" in r.alternates
    # a rule must not be rejected because one upstream pack has a typo
    assert r.accepts_identifier("AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED")


def test_multipack_index_verifies_what_the_single_pack_could_not():
    """22 rules were unverifiable only because the NIST r5 pack does not carry
    them. Verification is now 155/157."""
    import glob
    unverified = set()
    for f in glob.glob(str(ROOT / "rules/*.yaml")):
        for n, r in yaml.safe_load(open(f))["rules"].items():
            if r.get("not_in_aws_pack"):
                unverified.add(n)
    assert unverified == {"sqs-queue-encrypted", "approved-amis-by-id"}


def test_wrong_identifier_refused(tmp_path):
    """Does not fail at deploy time -- it reports INSUFFICIENT_DATA forever."""
    import subprocess
    r = rl(); r["rules"]["iam-password-policy"]["identifier"] = "IAM_PASSWORD_POLICY_V2"
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "AWS publishes" in proc.stderr


def test_unpublished_parameter_name_refused(tmp_path):
    """An unrecognised InputParameter is IGNORED at evaluation time, so the
    threshold silently does not apply -- the rule passes on AWS's default."""
    import subprocess
    r = rl()
    r["rules"]["iam-password-policy"]["parameters"]["MinPasswordLen"] = \
        r["rules"]["iam-password-policy"]["parameters"].pop("MinimumPasswordLength")
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "not published for this rule" in proc.stderr


def test_unknown_rule_needs_an_explicit_declaration(tmp_path):
    import subprocess
    r = rl()
    r["rules"]["totally-made-up-rule"] = {
        "source": "managed", "identifier": "TOTALLY_MADE_UP_RULE",
        "description": "x", "resource_types": ["AWS::IAM::User"],
        "controls": {"nist_800_53_r5": ["ia-5"], "ksi": ["KSI-IAM-APM"]},
        "coverage": "full",
    }
    (tmp_path / "iam.yaml").write_text(yaml.safe_dump(r))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--out", str(tmp_path / "out"), "--rules", str(tmp_path / "iam.yaml")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 1
    assert "not_in_aws_pack" in proc.stderr


def test_declared_exception_is_allowed_and_surfaced(tmp_path):
    """The escape must be a stated reason, and it must reach the report --
    an unverifiable rule that looks verified is the thing to avoid.

    Only two rules still qualify; the multi-pack index verified the other 22.
    """
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/crypto.yaml")]) == 0
    md = (tmp_path / "out/800-53r5-CRYPTO.coverage.md").read_text()
    assert "Not verifiable against AWS's published pack" in md
    assert "sqs-queue-encrypted" in md


# --- CRYPTO: Guard policies, which take no InputParameters -------------------

CRYPTO = yaml.safe_load((ROOT / "rules/crypto.yaml").read_text())


def crypto(): return copy.deepcopy(CRYPTO)


def test_guard_rule_renders_as_custom_policy_with_substituted_text():
    """CUSTOM_POLICY rules do NOT accept InputParameters, so the ODP value has to
    be baked into the policy text at generation time."""
    t, _, _ = generate.render_pack(cat(), crypto(), generate.resolve(cat(), ov(), None), "moderate")
    src = t["Resources"]["KmsKeyRotationPeriod"]["Properties"]["Source"]
    assert src["Owner"] == "CUSTOM_POLICY"
    assert "InputParameters" not in t["Resources"]["KmsKeyRotationPeriod"]["Properties"]
    text = src["CustomPolicyDetails"]["PolicyText"]
    assert "365" in text and "{{" not in text


def test_guard_rule_contributes_traceability_with_provenance():
    _, trace, _ = generate.render_pack(cat(), crypto(), generate.resolve(cat(), ov(), None), "moderate")
    rows = [r for r in trace if r["rule"] == "kms-key-rotation-period"]
    assert rows and all(r["parameter"].startswith("guard:") for r in rows)
    assert all(r["assigned_by"] for r in rows)


def test_unsubstituted_guard_token_refused(tmp_path):
    """The one that matters most. Guard does NOT error on a live placeholder --
    it evaluates the literal text and reports a verdict nobody should trust."""
    import shutil, subprocess
    shutil.copytree(ROOT / "guard", tmp_path / "guard")
    p = tmp_path / "guard/kms-key-rotation-period.guard"
    p.write_text(p.read_text() + "\n# stray {{UnboundThreshold}}\n")
    c = crypto()
    c["rules"]["kms-key-rotation-period"]["policy"] = "kms-key-rotation-period.guard"
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules/crypto.yaml").write_text(yaml.safe_dump(c))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "generate.py"), "--overlay", str(ROOT / "overlays/vanilla.yaml"),
         "--catalog", str(ROOT / "odp/catalog.yaml"),
         "--rules", str(tmp_path / "rules/crypto.yaml"), "--out", str(tmp_path / "out")],
        capture_output=True, text=True, cwd=tmp_path)
    assert proc.returncode == 1
    assert "unsubstituted token" in proc.stderr


def test_declared_token_missing_from_policy_refused():
    c = crypto()
    c["rules"]["kms-key-rotation-period"]["tokens"]["Ghost"] = "key_rotation_period_days"
    with pytest.raises(GenerationError, match="no such placeholder"):
        generate.render_pack(cat(), c, generate.resolve(cat(), ov(), None), "moderate")


def test_kms_guard_scopes_to_rotatable_keys_only():
    """Issue #4: AWS-managed, asymmetric and imported keys CANNOT rotate. Including
    them produces permanent unfixable non-compliance -- noise that trains people to
    ignore the pack."""
    text = (ROOT / "guard/kms-key-rotation-period.guard").read_text()
    assert 'KeyManager == "CUSTOMER"' in text
    assert 'KeySpec == "SYMMETRIC_DEFAULT"' in text
    assert 'Origin == "AWS_KMS"' in text


def test_sse_s3_vacuity_is_documented_in_the_rendered_description():
    """Issue #4: carrying s3-bucket-server-side-encryption-enabled as SC-28
    evidence is the kind of thing an assessor should catch."""
    t, _, _ = generate.render_pack(cat(), crypto(), generate.resolve(cat(), ov(), None), "moderate")
    d = t["Resources"]["S3BucketServerSideEncryptionEnabled"]["Properties"]["Description"]
    assert "VACUOUS" in d.upper()
    assert "[coverage: supporting]" in d


def test_guard_rule_out_of_baseline_is_excluded_not_fatal():
    """sc-8.1 is Moderate+. A Guard rule binding it took the FATAL path while
    managed rules took the exclusion path, which made a Low pack containing any
    Guard rule ungeneratable -- the same bug the exclusion branch fixed once."""
    t, _, excluded = generate.render_pack(
        cat(), crypto(), generate.resolve(cat(), ov(), None), "low")
    names = {e["rule"] for e in excluded}
    assert "elb-minimum-tls-policy" in names
    assert "ElbMinimumTlsPolicy" not in t["Resources"]
    # the KMS guard binds sc-12, which IS in Low, so it must still render
    assert "KmsKeyRotationPeriod" in t["Resources"]


# --- LOG: literals, and the recorder that cannot check itself ----------------

LOG = yaml.safe_load((ROOT / "rules/log.yaml").read_text())


def log_(): return copy.deepcopy(LOG)


def test_literal_parameter_is_not_recorded_as_a_tenant_decision(tmp_path):
    """alarmActionRequired=true is what the rule MEANS, not something a tenant
    tailors. Recording it as an ODP value would put a fixed assertion in the
    provenance column beside real governance decisions."""
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/log.yaml")]) == 0
    tags = json.loads((tmp_path / "out/800-53r5-LOG.evidence-tags.json").read_text())
    r = next(x for x in tags["rules"] if x["rule"] == "cloudwatch-alarm-action-check")
    assert all(m["assigned_by"] == "rule-literal" for m in r["measured_against"].values())
    assert all(m["odp"] is None for m in r["measured_against"].values())


def test_literal_only_rule_still_appears_in_traceability():
    """Found by this test: a rule whose parameters are ALL literals HAS
    parameters, binds no ODP, and so emitted nothing at all -- it vanished from
    traceability and the pack under-reported its own coverage. The fallback now
    tests what was emitted, not what was declared."""
    _, trace, _ = generate.render_pack(cat(), log_(), generate.resolve(cat(), ov(), None), "moderate")
    for name in ("cloudwatch-alarm-action-check", "redshift-cluster-configuration-check"):
        rows = [r for r in trace if r["rule"] == name]
        assert rows, f"{name} contributed no traceability rows"
        # It crosswalks to controls, but claims no ODP and no provenance.
        assert all(not r["odp"] and not r["assigned_by"] for r in rows)


def test_log_pack_does_not_try_to_check_the_recorder_from_inside_itself():
    """Circular: if recording is off, the rule that would report that fact does
    not run. Issue #5 says assert recorder state out of band."""
    names = set(LOG["rules"])
    assert not {n for n in names if "configuration-recorder" in n or "recorder" in n}
    assert "recorder" in LOG["__doc__"] if "__doc__" in LOG else True
    text = (ROOT / "rules/log.yaml").read_text()
    assert "RECORDER CANNOT CHECK ITSELF" in text


def test_log_coverage_report_carries_the_cost_warning(tmp_path):
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/log.yaml")]) == 0
    md = (tmp_path / "out/800-53r5-LOG.coverage.md").read_text()
    assert "model cost on one account" in md.lower()
    assert "KSI-MLA-ALA" in md            # log-access authorisation, not modeled


def test_every_overlay_covers_every_odp():
    """A pristine reference a consumer copies must show every knob. Falling
    through to a catalog default is legal but invisible in the file they edit."""
    declared = set(CATALOG["odps"])
    for name in ("vanilla.yaml", "vanilla-low.yaml", "vanilla-high.yaml"):
        o = yaml.safe_load((ROOT / "overlays" / name).read_text())
        assert {p["param_id"] for p in o["parameters"]} == declared, name


# --- VCM: evidence-only ODPs, and the absent-not-failing trap ----------------

VCM = yaml.safe_load((ROOT / "rules/vcm.yaml").read_text())


def test_evidence_only_odp_cannot_be_bound_to_a_rule_parameter():
    """Binding one would make an unenforceable value look enforced, which is the
    single thing this catalog most exists to prevent."""
    c = cat()
    v = copy.deepcopy(VCM)
    v["rules"]["ec2-managedinstance-patch-compliance-status-check"]["parameters"] = {
        "someParam": {"odp": "critical_patch_window_days"}}
    with pytest.raises(GenerationError, match="evidence_only"):
        generate.render_pack(c, v, generate.resolve(c, ov(), None), "moderate")


def test_evidence_only_odp_appears_in_evidence_named_as_unenforced(tmp_path):
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/vcm.yaml")]) == 0
    tags = json.loads((tmp_path / "out/800-53r5-VCM.evidence-tags.json").read_text())
    eo = {e["odp"]: e for e in tags["evidence_only_odps"]}
    assert "critical_patch_window_days" in eo
    e = eo["critical_patch_window_days"]
    assert e["value"] and e["assigned_by"] and e["control"] == "si-2"
    # The reason must travel with it -- an unexplained unenforceable ODP is
    # indistinguishable from one somebody forgot to wire up.
    assert "no aws config managed rule" in e["why_unenforced"].lower()


def test_evidence_only_reason_is_required_not_a_bare_flag():
    """Checked by the lint, asserted here so the requirement is visible."""
    assert isinstance(CATALOG["odps"]["critical_patch_window_days"]["evidence_only"], str)
    assert len(CATALOG["odps"]["critical_patch_window_days"]["evidence_only"]) > 80


def test_vcm_carries_the_absent_not_failing_warning(tmp_path):
    """The worst false assurance in the programme: an unregistered instance is
    ABSENT from managedinstance results, not non-compliant."""
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/vcm.yaml")]) == 0
    md = (tmp_path / "out/800-53r5-VCM.coverage.md").read_text()
    assert "ABSENT from the results" in md
    assert "Declared but NOT ENFORCED" in md
    t = yaml.safe_load((tmp_path / "out/800-53r5-VCM.yaml").read_text())
    d = t["Resources"]["Ec2InstanceManagedBySystemsManager"]["Properties"]["Description"]
    assert "ABSENT" in d           # the gap-making rule says so on the rule itself


# --- RPL: the duration pair, and plan-vs-coverage ---------------------------

RPL = yaml.safe_load((ROOT / "rules/rpl.yaml").read_text())


def test_duration_odp_drives_both_facets_from_one_source():
    """Issue #7: requiredFrequencyValue and requiredFrequencyUnit disagreeing
    silently changes the meaning of the check by a factor of 24. Modelling them
    as one duration makes disagreement structurally impossible."""
    t, _, _ = generate.render_pack(cat(), copy.deepcopy(RPL),
                                   generate.resolve(cat(), ov(), None), "moderate")
    p = t["Parameters"]
    base = "BackupPlanMinFrequencyAndMinRetentionCheckParamRequiredFrequency"
    assert p[base + "Value"]["Default"] == "24"
    assert p[base + "Unit"]["Default"] == "hours"


def test_duration_odp_rejects_a_bad_unit():
    o = ov()
    for e in o["parameters"]:
        if e["param_id"] == "backup_minimum_frequency":
            e["value"] = {"value": 24, "unit": "fortnights"}
    with pytest.raises(GenerationError, match="is not one of"):
        generate.resolve(cat(), o, None)


def test_duration_odp_rejects_a_scalar():
    o = ov()
    for e in o["parameters"]:
        if e["param_id"] == "backup_minimum_frequency":
            e["value"] = 24
    with pytest.raises(GenerationError, match="expected a mapping"):
        generate.resolve(cat(), o, None)


def test_rpl_carries_both_plan_and_coverage_rules():
    """A perfectly compliant plan protecting ZERO resources passes the plan rule.
    Without the *-in-backup-plan rules the pack certifies an empty promise."""
    names = set(RPL["rules"])
    assert "backup-plan-min-frequency-and-min-retention-check" in names
    assert {"ebs-in-backup-plan", "efs-in-backup-plan",
            "dynamodb-in-backup-plan", "rds-in-backup-plan"} <= names


def test_versioning_is_not_claimed_as_a_backup():
    """It appears under CP-9 in many published crosswalks and does not belong."""
    r = RPL["rules"]["s3-bucket-versioning-enabled"]
    assert r["coverage"] == "supporting"
    assert "NOT A BACKUP" in r["coverage_note"].upper()


def test_si_13_is_claimed_by_no_catalog():
    """si-13 resolves in NO Rev 5 baseline. Anything crosswalked to it would
    claim coverage of a control the baseline never asks for (correction on #7)."""
    for f in (ROOT / "rules").glob("*.yaml"):
        doc = yaml.safe_load(f.read_text())
        for name, rule in doc["rules"].items():
            assert "si-13" not in rule["controls"].get("nist_800_53_r5", []), f"{f.name}:{name}"


def test_rto_is_evidence_only_not_inferred_from_backup_frequency():
    o = CATALOG["odps"]["recovery_time_objective_hours"]
    assert isinstance(o.get("evidence_only"), str)
    assert "proxy" in o["evidence_only"].lower()


# --- #26 crosswalk, and the two AMI allow-lists ------------------------------

def test_ami_tag_pattern_rejects_the_malformations_aws_ignores():
    """AWS takes amisByTagKeyAndValue as ONE comma-separated string. A stray
    comma or a space does not error -- AWS ignores the malformed entry, so the
    allow-list is silently SMALLER than it reads and more AMIs pass."""
    for bad in (["golden:approved,extra"], ["has space:v"], [" leading:v"], ["trailing,"]):
        o = ov()
        for e in o["parameters"]:
            if e["param_id"] == "approved_ami_tag_pairs":
                e["value"] = bad
        with pytest.raises(GenerationError, match="does not match the required shape"):
            generate.resolve(cat(), o, None)


def test_ami_tag_pattern_accepts_real_shapes():
    for good in (["golden-image:approved"], ["Compliance:PCI-DSS", "team:platform"], ["just-a-key"]):
        o = ov()
        for e in o["parameters"]:
            if e["param_id"] == "approved_ami_tag_pairs":
                e["value"] = good
        generate.resolve(cat(), o, None)


def test_ami_id_pattern_rejects_a_malformed_id():
    o = ov()
    for e in o["parameters"]:
        if e["param_id"] == "approved_ami_ids":
            e["value"] = ["ami-nothex!!", "i-0123456789abcdef0"]
    with pytest.raises(GenerationError, match="does not match the required shape"):
        generate.resolve(cat(), o, None)


def test_ami_id_odp_records_that_it_is_not_region_portable():
    """The first ODP in the catalog that cannot travel between Regions in one
    overlay -- it breaks the one-overlay-many-Regions model the rest assumes."""
    raw = (ROOT / "odp/catalog.yaml").read_text()
    assert "CANNOT BE REGION-PORTABLE" in raw


def test_crosswalk_dispositions_cover_every_gap_control_with_a_reason():
    d = yaml.safe_load((ROOT / "docs/dev/crosswalk-dispositions.yaml").read_text())["dispositions"]
    assert len(d) == 94
    assert all(v["d"] in ("claim", "no-signal", "gov") for v in d.values())
    assert all(v.get("why") for v in d.values()), "every disposition needs a stated reason"
    # a claim must name the rules that justify it
    assert all(v.get("rules") for v in d.values() if v["d"] == "claim")


def test_claimed_controls_actually_reached_the_catalogs():
    d = yaml.safe_load((ROOT / "docs/dev/crosswalk-dispositions.yaml").read_text())["dispositions"]
    # A rule can appear in two catalogs (vpc-flow-logs-enabled is in NET and
    # LOG), so union rather than overwrite -- a flat dict silently keeps
    # whichever file was read last and asserts against the wrong copy.
    built: dict[str, set] = {}
    for f in (ROOT / "rules").glob("*.yaml"):
        for name, r in yaml.safe_load(f.read_text())["rules"].items():
            built.setdefault(name, set()).update(r["controls"].get("nist_800_53_r5", []))
    for ctrl, v in d.items():
        if v["d"] != "claim":
            continue
        for rule in v["rules"]:
            assert ctrl in built[rule], f"{rule} does not claim {ctrl}"


# --- Phase 4: deployment inputs and the recorder preflight -------------------

import importlib.util as _ilu


def _load(mod: str):
    spec = _ilu.spec_from_file_location(mod, ROOT / f"tools/{mod}.py")
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


GOOD_INPUTS = {
    "packs": ["IAM", "NET"], "accounts": ["123456789012"],
    "regions": ["us-east-1", "us-west-2"], "global_resource_region": "us-east-1",
    "mode": "single-account", "excluded_accounts": [],
    "delivery": {"pack_bucket": "b", "evidence_bucket": "e", "evidence_prefix": ""},
    "overlay": "overlays/vanilla.yaml", "baseline": "moderate",
    "safety": {"require_recorder_preflight": True, "delete_removed_packs": False},
}


def test_inputs_template_does_not_validate():
    """It is a TEMPLATE. If it validated as-is, someone would deploy it, and
    every environment value in it is deliberately empty."""
    v = _load("validate_inputs")
    tmpl = yaml.safe_load((ROOT / "inputs.template.yml").read_text())
    assert v.validate(tmpl), "the template must not be deployable"


def test_good_inputs_validate():
    assert _load("validate_inputs").validate(copy.deepcopy(GOOD_INPUTS)) == []


@pytest.mark.parametrize("name,mutate,expect", [
    ("iam without global region", lambda c: c.update(global_resource_region=""), "global_resource_region"),
    ("global region not targeted", lambda c: c.update(global_resource_region="eu-west-1"), "not in `regions`"),
    ("malformed account", lambda c: c.update(accounts=["12345"]), "12-digit account id"),
    ("ou id in single-account", lambda c: c.update(accounts=["ou-abcd-12345678"]), "12-digit account id"),
    ("account id in org mode", lambda c: c.update(mode="organization"), "organizational unit id"),
    ("bogus region", lambda c: c.update(regions=["narnia"]), "reports a CLEAN result"),
    ("unknown pack", lambda c: c.update(packs=["QUANTUM"]), "not a built pack"),
    ("baseline mismatch", lambda c: c.update(baseline="low"), "render smaller than intended"),
    ("no evidence bucket", lambda c: c["delivery"].update(evidence_bucket=""), "no safe default"),
    ("preflight disabled", lambda c: c["safety"].update(require_recorder_preflight=False), "reads as 'not failing'"),
    ("overlay missing", lambda c: c.update(overlay="overlays/nope.yaml"), "does not exist"),
])
def test_inputs_validator_refusals(name, mutate, expect):
    c = copy.deepcopy(GOOD_INPUTS)
    mutate(c)
    errs = _load("validate_inputs").validate(c)
    assert errs, name
    assert any(expect in e for e in errs), f"{name}: {errs}"


def test_preflight_derives_required_resource_types_from_the_catalogs():
    p = _load("preflight")
    want = p.required_resource_types(["IAM", "NET"])
    assert set(want) == {"IAM", "NET"}
    assert "AWS::EC2::SecurityGroup" in want["NET"]
    # The account pseudo-type is not a recorded resource and must never be asserted.
    assert not any("AWS::::Account" in t for t in want.values())


def test_preflight_refuses_when_the_recorder_is_absent(monkeypatch):
    """The failure the epic calls the silent killer: rules deployed onto a
    recorder that captures nothing report INSUFFICIENT_DATA, which reads as
    'not failing'."""
    p = _load("preflight")
    monkeypatch.setattr(p, "_aws", lambda *a, **k: {"ConfigurationRecorders": []})
    problems = p.check_region("us-east-1", {"AWS::EC2::Instance"}, None, False)
    assert problems and "no AWS Config recorder" in problems[0]


def test_preflight_refuses_a_recorder_that_is_not_recording(monkeypatch):
    p = _load("preflight")
    def fake(args, region, profile):
        if args[1] == "describe-configuration-recorders":
            return {"ConfigurationRecorders": [{"recordingGroup": {"allSupported": True}}]}
        if args[1] == "describe-configuration-recorder-status":
            return {"ConfigurationRecordersStatus": [{"recording": False}]}
        return {"DeliveryChannels": [{"name": "default"}]}
    monkeypatch.setattr(p, "_aws", fake)
    problems = p.check_region("us-east-1", set(), None, False)
    assert any("NOT RECORDING" in x for x in problems)


def test_preflight_refuses_a_missing_resource_type(monkeypatch):
    p = _load("preflight")
    def fake(args, region, profile):
        if args[1] == "describe-configuration-recorders":
            return {"ConfigurationRecorders": [{"recordingGroup": {
                "allSupported": False, "resourceTypes": ["AWS::S3::Bucket"]}}]}
        if args[1] == "describe-configuration-recorder-status":
            return {"ConfigurationRecordersStatus": [{"recording": True}]}
        return {"DeliveryChannels": [{"name": "default"}]}
    monkeypatch.setattr(p, "_aws", fake)
    problems = p.check_region("us-east-1", {"AWS::EC2::Instance"}, None, False)
    assert any("does not capture" in x for x in problems)


def test_preflight_refuses_an_excluded_resource_type(monkeypatch):
    """sparc-iac's own recorder uses EXCLUSION_BY_RESOURCE_TYPES, so this is the
    shape a real estate hits, not a hypothetical."""
    p = _load("preflight")
    def fake(args, region, profile):
        if args[1] == "describe-configuration-recorders":
            return {"ConfigurationRecorders": [{"recordingGroup": {
                "allSupported": False,
                "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"},
                "exclusionByResourceTypes": {"resourceTypes": ["AWS::EC2::Instance"]}}}]}
        if args[1] == "describe-configuration-recorder-status":
            return {"ConfigurationRecordersStatus": [{"recording": True}]}
        return {"DeliveryChannels": [{"name": "default"}]}
    monkeypatch.setattr(p, "_aws", fake)
    problems = p.check_region("us-east-1", {"AWS::EC2::Instance"}, None, False)
    assert any("EXCLUDES" in x for x in problems)


def test_preflight_refuses_global_resources_recorded_in_the_wrong_place(monkeypatch):
    p = _load("preflight")
    def fake(args, region, profile):
        if args[1] == "describe-configuration-recorders":
            return {"ConfigurationRecorders": [{"recordingGroup": {
                "allSupported": False, "resourceTypes": [],
                "includeGlobalResourceTypes": False}}]}
        if args[1] == "describe-configuration-recorder-status":
            return {"ConfigurationRecordersStatus": [{"recording": True}]}
        return {"DeliveryChannels": [{"name": "default"}]}
    monkeypatch.setattr(p, "_aws", fake)
    problems = p.check_region("us-east-1", set(), None, expect_global=True)
    assert any("global resource types" in x for x in problems)


def test_preflight_passes_a_correctly_configured_region(monkeypatch):
    p = _load("preflight")
    def fake(args, region, profile):
        if args[1] == "describe-configuration-recorders":
            return {"ConfigurationRecorders": [{"recordingGroup": {"allSupported": True}}]}
        if args[1] == "describe-configuration-recorder-status":
            return {"ConfigurationRecordersStatus": [{"recording": True}]}
        return {"DeliveryChannels": [{"name": "default"}]}
    monkeypatch.setattr(p, "_aws", fake)
    assert p.check_region("us-east-1", {"AWS::EC2::Instance"}, None, True) == []


# --- GOV: evidence for controls AWS Config cannot see ------------------------

def _gov():
    return _load("gov_evidence")


GOV_ODPS = {
    "policy_review_interval_days": 365,
    "procedure_review_interval_days": 365,
    "approved_policy_approver_roles": ["ciso", "iso", "isso", "authorizing-official",
                                       "system-owner"],
}


def test_gov_emits_zero_config_rules():
    """GOV is a non-Config producer BY DESIGN. If a rules/gov.yaml ever appears,
    the whole premise -- that ~120 controls have no resource signal -- has been
    quietly abandoned."""
    assert not (ROOT / "rules/gov.yaml").exists()


def test_existence_alone_never_satisfies_a_control():
    """'The policy file exists' is theater. It is emitted so its weakness is
    visible, and it is labelled -- but a document that exists and fails
    everything else is FAILED, not passed."""
    g = _gov()
    controls = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2026, 9, 8))
    bad = next(c for c in controls if c["id"] == "gov-au-1")
    existence = next(r for r in bad["results"] if "exists" in r["code_desc"])
    assert existence["status"] == "passed"
    assert "WEAK EVIDENCE" in existence["message"]
    assert bad["status"] == "failed", "existence must not carry a control on its own"


def test_the_three_real_checks_all_fire():
    g = _gov()
    controls = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2026, 9, 8))
    bad = next(c for c in controls if c["id"] == "gov-au-1")
    msgs = " ".join(r.get("message", "") for r in bad["results"] if r["status"] == "failed")
    assert "exceeding the organization-defined interval" in msgs   # review recency
    assert "is not one of" in msgs                                  # approver authority
    assert "SSP cites" in msgs                                      # version reconciliation


def test_a_compliant_artifact_passes_all_four():
    g = _gov()
    controls = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2026, 9, 8))
    good = next(c for c in controls if c["id"] == "gov-ac-1")
    assert good["status"] == "passed"
    assert all(r["status"] == "passed" for r in good["results"])


def test_review_recency_is_evaluated_against_TODAY_not_a_commit():
    """The reason this producer runs on a timer. Nothing changes in the artifact
    when it goes stale -- only the date does."""
    g = _gov()
    fresh = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2026, 3, 20))
    stale = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2027, 12, 1))
    ac_fresh = next(c for c in fresh if c["id"] == "gov-ac-1")
    ac_stale = next(c for c in stale if c["id"] == "gov-ac-1")
    assert ac_fresh["status"] == "passed"
    assert ac_stale["status"] == "failed", "the same file must fail once the interval lapses"


def test_missing_front_matter_fails_rather_than_skipping(tmp_path):
    (tmp_path / "broken.md").write_text("no front matter here\n")
    controls = _gov().evaluate(tmp_path, GOV_ODPS, today=date(2026, 9, 8))
    assert controls[0]["results"][0]["status"] == "failed", \
        "a skip would read as 'nothing to check here'"


def test_inventory_reconciliation_skips_rather_than_passes_with_no_input():
    """An absent input must never read as a clean result."""
    c = _gov().inventory_reconciliation(None, None)
    assert c["status"] == "skipped"
    assert "NOT as passed" in c["results"][0]["message"]


def test_inventory_reconciliation_finds_shadow_resources(tmp_path):
    """The check that earns its place: shadow resources are invisible to every
    conformance pack, because a pack only evaluates what the recorder knows."""
    iac = tmp_path / "iac.json"; iac.write_text(json.dumps(["a", "b"]))
    rec = tmp_path / "rec.json"; rec.write_text(json.dumps(["a", "SHADOW"]))
    c = _gov().inventory_reconciliation(iac, rec)
    assert c["status"] == "failed"
    msgs = " ".join(r.get("message", "") for r in c["results"])
    assert "SHADOW" in msgs                      # recorded but undeclared
    assert "not recorded" in msgs                # declared but absent


def test_gov_control_ids_use_the_shared_normalizer():
    """If GOV emits AC-1 and a pack emits ac-2 the Heimdall rollup fragments --
    and a fragmented rollup looks like partial coverage, not like a defect."""
    g = _gov()
    controls = g.evaluate(ROOT / "gov/artifacts", GOV_ODPS, today=date(2026, 9, 8))
    for c in controls:
        for n in c["tags"].get("nist", []):
            assert normalize_control_id(n) == n.lower()

"""Generator tests, weighted toward the failures that matter.

A conformance pack does not crash when it is wrong. It deploys, evaluates, and
reports a clean result against a threshold nobody chose. So most of what is
tested here is that the generator REFUSES -- a guard that has never been shown to
fail is not a guard.

    python3 -m pytest tests/test_generate.py -q
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import generate  # noqa: E402
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
        built = set(yaml.safe_load(cat.read_text())["rules"])
        if missing := cands - built:
            shortfalls[dom] = sorted(missing)
    assert started, "no rule catalogs found at all"
    assert not shortfalls, (
        "domain catalogs do not cover every candidate their issue names: "
        + "; ".join(f"{d} missing {len(m)} ({', '.join(m[:5])}...)"
                    for d, m in shortfalls.items())
    )


# --- verification against AWS's own published pack ---------------------------

def test_aws_pack_loads_and_indexes_both_ways():
    from tools import aws_pack
    p = aws_pack.load()
    assert len(p.rules_by_name) == 130          # exactly the per-pack service cap
    r = p.get("iam-password-policy")
    assert r.identifier == "IAM_PASSWORD_POLICY"
    assert "MinimumPasswordLength" in r.parameters


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
    an unverifiable rule that looks verified is the thing to avoid."""
    assert _run_cli(tmp_path, ["--rules", str(ROOT / "rules/net.yaml")]) == 0
    md = (tmp_path / "out/800-53r5-NET.coverage.md").read_text()
    assert "Not verifiable against AWS's published pack" in md
    assert "cloudfront-associated-with-waf" in md


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

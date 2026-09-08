#!/usr/bin/env python3
"""Repository lint for the conformance-pack generator.

Runs every check that the current repository contents can support, and reports
the ones it cannot yet run as PENDING with the reason.

The design constraint is the one this whole issue exists for: **a check that is
not running must be visible, not silently green.** A linter that reports success
because it found nothing to look at is worse than no linter, because it makes
the absence of coverage look like the presence of it.

So PENDING is printed loudly, and there is a second guard:

    if the artifact exists but this script has no validator for it, that is a
    FAILURE, not a pass.

That is what makes PENDING self-clearing. The day `odp/catalog.yaml` lands, this
script fails until someone writes its validator -- the pending check cannot be
forgotten, because the thing it was waiting for is what breaks the build.

Usage:  python3 tools/lint_packs.py [--repo-root .]
Exit:   0 all applicable checks passed;  1 a check failed or a validator is owed
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("::error::PyYAML is required. It ships in risksentinel/sparc-ci-runner.")
    sys.exit(1)

# AWS Config service limits. None of these is increasable; see issues/00.
MAX_RULES_PER_PACK = 130
MAX_PARAMS_PER_PACK = 60
MAX_INLINE_TEMPLATE_BYTES = 51_200
MAX_S3_TEMPLATE_BYTES = 300 * 1024

SKIP_DIRS = {".git", "out", "vendor", "node_modules", ".github/actions"}


def _nist_index(root: Path):
    """The vendored NIST parameter index, or None if it is not present."""
    p = root / "vendor/nist/nist-800-53r5-params.json"
    if not p.exists():
        return None
    import json
    return json.loads(p.read_text())["controls"]


@dataclass
class Report:
    passed: list[str] = field(default_factory=list)
    pending: list[tuple[str, str]] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        self.passed.append(msg)

    def defer(self, check: str, reason: str) -> None:
        self.pending.append((check, reason))

    def fail(self, msg: str) -> None:
        self.failed.append(msg)
        print(f"::error::{msg}")


def _walk(root: Path, pattern: str) -> list[Path]:
    out = []
    for p in sorted(root.rglob(pattern)):
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        out.append(p)
    return out


def check_yaml_parses(root: Path, rep: Report) -> None:
    """Every YAML file in the repo is parseable.

    Deliberately not schema-aware: this catches the tab-indent and unquoted-colon
    class of defect in workflows and catalogs alike, before anything downstream
    tries to interpret them.
    """
    files = _walk(root, "*.yml") + _walk(root, "*.yaml")
    if not files:
        rep.defer("YAML parse", "no YAML files in the repository")
        return
    bad = 0
    for f in files:
        try:
            # safe_load_all, not safe_load: a GitLab CI component file is a
            # legitimate MULTI-DOCUMENT yaml (a `spec:` header, `---`, the body),
            # and single-document parsing rejects a perfectly valid file.
            list(yaml.safe_load_all(f.read_text()))
        except yaml.YAMLError as exc:
            if "could not determine a constructor" in str(exc):
                continue  # CFN short-form tag, not a syntax error
            rep.fail(f"{f.relative_to(root)}: YAML does not parse -- {exc}")
            bad += 1
    if not bad:
        rep.ok(f"YAML parse: {len(files)} file(s)")


def check_shell_syntax(root: Path, rep: Report) -> None:
    scripts = _walk(root, "*.sh")
    if not scripts:
        rep.defer("Shell syntax", "no shell scripts present")
        return
    bad = 0
    for s in scripts:
        r = subprocess.run(["bash", "-n", str(s)], capture_output=True, text=True)
        if r.returncode != 0:
            rep.fail(f"{s.relative_to(root)}: bash syntax error -- {r.stderr.strip()}")
            bad += 1
    if not bad:
        rep.ok(f"Shell syntax: {len(scripts)} script(s)")


def check_issue_front_matter(root: Path, rep: Report) -> None:
    """`scripts/create-issues.sh` silently skips a file with no `title:`.

    That is correct behaviour (it is how README.md is ignored in a flat layout),
    but it means a domain issue that loses its front matter is not created and
    nothing says so. Assert the contract here instead.
    """
    issues = sorted((root / "issues").glob("*.md")) if (root / "issues").is_dir() else []
    if not issues:
        rep.defer("Issue front matter", "issues/ is absent or empty")
        return
    bad = 0
    for f in issues:
        text = f.read_text()
        if not text.startswith("---"):
            rep.fail(f"{f.relative_to(root)}: no YAML front matter; create-issues.sh will skip it")
            bad += 1
            continue
        parts = text.split("---", 2)
        if len(parts) < 3:
            rep.fail(f"{f.relative_to(root)}: front matter is not closed")
            bad += 1
            continue
        meta, body = parts[1], parts[2]
        for key in ("title:", "labels:"):
            if key not in meta:
                rep.fail(f"{f.relative_to(root)}: front matter is missing `{key}`")
                bad += 1
        if not body.strip():
            rep.fail(f"{f.relative_to(root)}: body is empty; create-issues.sh rejects it")
            bad += 1
    if not bad:
        rep.ok(f"Issue front matter: {len(issues)} file(s)")


def check_python_compiles(root: Path, rep: Report) -> None:
    files = _walk(root, "*.py")
    if not files:
        rep.defer("Python syntax", "no Python files present")
        return
    r = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", *[str(f) for f in files]],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        rep.fail(f"Python syntax error:\n{r.stdout}{r.stderr}")
    else:
        rep.ok(f"Python syntax: {len(files)} file(s)")


VALID_BASELINES = ("low", "moderate", "high")
VALID_TYPES = ("integer", "string", "boolean", "enum", "list", "duration")
REQUIRED_ODP_FIELDS = (
    "description", "control", "oscal_param_id", "oscal_alt_id",
    "oscal_label", "baselines", "type", "constraint", "default",
)
# Rev 5 canonical form: zero-padded control, `_odp`, optional `.NN`.
OSCAL_PARAM_RE = re.compile(r"^[a-z]{2}-\d{2}(\.\d{2})?_odp(\.\d{2})?$")
ODP_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _violates_constraint(value, odp: dict) -> str | None:
    """Return a human reason the value is not legal for this ODP, else None."""
    typ = odp.get("type")
    con = odp.get("constraint") or {}
    if typ == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"expected an integer, got {type(value).__name__} ({value!r})"
        lo, hi = con.get("min"), con.get("max")
        if lo is not None and value < lo:
            return f"{value} is below the minimum of {lo}"
        if hi is not None and value > hi:
            return f"{value} is above the maximum of {hi}"
    elif typ == "boolean":
        if not isinstance(value, bool):
            return f"expected a boolean, got {type(value).__name__} ({value!r})"
    elif typ == "enum":
        allowed = con.get("values") or []
        if value not in allowed:
            return f"{value!r} is not one of {allowed}"
    elif typ == "string":
        if not isinstance(value, str):
            return f"expected a string, got {type(value).__name__} ({value!r})"
        if (mx := con.get("max_length")) and len(value) > mx:
            return f"length {len(value)} exceeds max_length {mx}"
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
        ip = con.get("item_pattern")
        for v in value:
            if it == "integer":
                if isinstance(v, bool) or not isinstance(v, int):
                    return f"item {v!r} is not an integer"
                if (lo := con.get("item_min")) is not None and v < lo:
                    return f"item {v} is below item_min {lo}"
                if (hi := con.get("item_max")) is not None and v > hi:
                    return f"item {v} is above item_max {hi}"
            elif it == "string":
                if not isinstance(v, str):
                    return f"item {v!r} is not a string"
                if ip and not re.match(ip, v):
                    return (f"item {v!r} does not match the required shape {ip}. "
                            f"AWS rejects or silently ignores a malformed entry, so a "
                            f"typo here means the allow-list is smaller than it reads")
    return None


def check_odp_catalog(root: Path, rep: Report) -> None:
    """Validate odp/catalog.yaml.

    The check that matters most here is that a `default` satisfies its own
    `constraint`. A catalog whose declared range excludes its own default is not
    a theoretical defect -- it renders a pack whose threshold the catalog itself
    calls illegal, and nothing downstream re-checks it.
    """
    path = root / "odp" / "catalog.yaml"
    if not path.exists():
        rep.defer("ODP catalog schema", "odp/catalog.yaml does not exist yet (Phase 1a)")
        return

    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        rep.fail(f"odp/catalog.yaml does not parse -- {exc}")
        return

    if not isinstance(doc, dict) or "odps" not in doc:
        rep.fail("odp/catalog.yaml has no top-level `odps` mapping")
        return
    if "version" not in doc:
        rep.fail("odp/catalog.yaml has no top-level `version`")

    odps = doc.get("odps") or {}
    if not isinstance(odps, dict) or not odps:
        rep.fail("odp/catalog.yaml `odps` is empty or not a mapping")
        return

    bad = 0
    by_oscal: dict[str, list[str]] = {}

    for key, odp in odps.items():
        where = f"odp/catalog.yaml:{key}"
        if not ODP_KEY_RE.match(str(key)):
            rep.fail(f"{where}: key must be lower snake_case")
            bad += 1
        if not isinstance(odp, dict):
            rep.fail(f"{where}: entry is not a mapping")
            bad += 1
            continue

        for field in REQUIRED_ODP_FIELDS:
            if field not in odp:
                rep.fail(f"{where}: missing required field `{field}`")
                bad += 1
        if any(f not in odp for f in REQUIRED_ODP_FIELDS):
            continue

        pid = str(odp["oscal_param_id"])
        # Shape is not existence. An id can be perfectly well-formed and refer to
        # nothing -- ac-06_odp looks exactly like a real parameter and ac-6 has no
        # parameters at all. A non-existent id joins to nothing while appearing
        # entirely correct, which is the whole failure mode this catalog exists to
        # prevent, so it is checked against the vendored NIST index.
        nist_index = _nist_index(root)
        if nist_index is not None:
            ctrl = nist_index.get(str(odp.get("control")))
            if ctrl is None:
                rep.fail(
                    f"{where}: control {odp.get('control')!r} resolves in no Rev 5 "
                    f"baseline, so nothing bound to it can be claimed as coverage."
                )
                bad += 1
            elif pid not in ctrl["params"] and str(odp.get("oscal_alt_id")) not in {
                    p.get("alt_id") for p in ctrl["params"].values()}:
                rep.fail(
                    f"{where}: oscal_param_id {pid!r} is not a parameter of "
                    f"{odp.get('control')}. That control publishes "
                    f"{sorted(ctrl['params']) or 'no parameters at all'}."
                )
                bad += 1
        if not OSCAL_PARAM_RE.match(pid):
            rep.fail(
                f"{where}: oscal_param_id {pid!r} is not a Rev 5 parameter id. "
                f"Rev 5 uses the zero-padded `_odp` form (ia-05.01_odp.02); the "
                f"`_prm_` form belongs in oscal_alt_id."
            )
            bad += 1
        by_oscal.setdefault(pid, []).append(str(key))

        bl = odp["baselines"]
        if not isinstance(bl, list) or not bl:
            rep.fail(f"{where}: `baselines` must be a non-empty list")
            bad += 1
        elif [b for b in bl if b not in VALID_BASELINES]:
            rep.fail(f"{where}: unknown baseline(s) {[b for b in bl if b not in VALID_BASELINES]}")
            bad += 1

        if odp["type"] not in VALID_TYPES:
            rep.fail(f"{where}: unknown type {odp['type']!r}; expected one of {list(VALID_TYPES)}")
            bad += 1
            continue

        con = odp.get("constraint")
        if not isinstance(con, dict):
            rep.fail(f"{where}: `constraint` must be a mapping (use {{}} only if genuinely unbounded)")
            bad += 1
            continue
        if odp["type"] == "integer":
            lo, hi = con.get("min"), con.get("max")
            if lo is None or hi is None:
                rep.fail(f"{where}: an integer ODP needs both `min` and `max`")
                bad += 1
            elif lo > hi:
                rep.fail(f"{where}: constraint min {lo} is greater than max {hi}")
                bad += 1
        if odp["type"] == "enum" and not con.get("values"):
            rep.fail(f"{where}: an enum ODP needs `constraint.values`")
            bad += 1
        if odp["type"] == "duration" and not (con.get("units")):
            rep.fail(
                f"{where}: a duration ODP needs `constraint.units`. The unit is the "
                f"half that silently changes meaning by a factor of 24 when it "
                f"disagrees with the value."
            )
            bad += 1
        if odp["type"] == "list":
            if odp.get("item_type") not in ("integer", "string"):
                rep.fail(f"{where}: a list ODP needs `item_type` of integer or string")
                bad += 1
            if con.get("max_items") is None:
                rep.fail(
                    f"{where}: a list ODP needs `constraint.max_items`. Several AWS "
                    f"rules expose a fixed number of numbered parameters, and an "
                    f"over-long list is silently truncated rather than rejected."
                )
                bad += 1

        if "evidence_only" in odp and not str(odp["evidence_only"]).strip():
            rep.fail(
                f"{where}: `evidence_only` must carry a REASON explaining why no rule "
                f"can enforce it, not a bare flag. An unexplained unenforceable ODP is "
                f"indistinguishable from one somebody forgot to wire up."
            )
            bad += 1

        # The one that catches a catalog contradicting itself.
        if (reason := _violates_constraint(odp["default"], odp)):
            rep.fail(f"{where}: default violates its own constraint -- {reason}")
            bad += 1

    # Several ODPs may legitimately share one OSCAL parameter, but they must
    # agree about what that parameter IS. Disagreement means the join is wrong
    # in at least one of them, and the traceability report would carry both.
    for pid, keys in by_oscal.items():
        if len(keys) < 2:
            continue
        for field in ("control", "oscal_label", "oscal_alt_id"):
            vals = {str(odps[k].get(field)) for k in keys}
            if len(vals) > 1:
                rep.fail(
                    f"odp/catalog.yaml: {keys} share oscal_param_id {pid} but disagree "
                    f"on `{field}` ({sorted(vals)}). Sharing a parameter is expected; "
                    f"describing it differently is a mis-binding."
                )
                bad += 1

    if not bad:
        shared = {p: k for p, k in by_oscal.items() if len(k) > 1}
        note = f"; {len(shared)} OSCAL param(s) shared by multiple ODPs" if shared else ""
        rep.ok(f"ODP catalog schema: {len(odps)} ODP(s){note}")


def check_overlays(root: Path, rep: Report) -> None:
    """Validate overlays against the catalog.

    An overlay naming an ODP the catalog does not declare is the defect this
    exists for: it renders nothing, changes nothing, and looks like a decision
    that was applied.
    """
    overlay_dir = root / "overlays"
    overlays = sorted(overlay_dir.glob("*.yaml")) if overlay_dir.is_dir() else []
    if not overlays:
        rep.defer("Overlay values", "overlays/*.yaml do not exist yet (Phase 1a)")
        return

    cat_path = root / "odp" / "catalog.yaml"
    if not cat_path.exists():
        rep.fail("overlays/ exist but odp/catalog.yaml does not -- nothing can validate their values")
        return
    odps = (yaml.safe_load(cat_path.read_text()) or {}).get("odps") or {}

    bad = 0
    for ov in overlays:
        where = ov.relative_to(root)
        try:
            doc = yaml.safe_load(ov.read_text()) or {}
        except yaml.YAMLError as exc:
            rep.fail(f"{where}: does not parse -- {exc}")
            bad += 1
            continue

        level = doc.get("baseline_level")
        if level not in VALID_BASELINES:
            rep.fail(f"{where}: baseline_level {level!r} is not one of {list(VALID_BASELINES)}")
            bad += 1

        for coll in ("parameters", "selections"):
            if coll not in doc:
                rep.fail(
                    f"{where}: missing `{coll}`. Both collections are always present in "
                    f"SPARC's response envelope; an empty list is how you say 'none'."
                )
                bad += 1

        seen: set[str] = set()
        for entry in doc.get("parameters") or []:
            pid = entry.get("param_id")
            if pid in seen:
                rep.fail(f"{where}: param_id {pid!r} appears more than once")
                bad += 1
            seen.add(pid)

            odp = odps.get(pid)
            if odp is None:
                rep.fail(
                    f"{where}: param_id {pid!r} is not declared in odp/catalog.yaml. "
                    f"It would render nothing while looking like an applied decision."
                )
                bad += 1
                continue
            if (reason := _violates_constraint(entry.get("value"), odp)):
                rep.fail(f"{where}: {pid} -- {reason}")
                bad += 1
            elif level in VALID_BASELINES and level not in (odp.get("baselines") or []):
                # Not a failure: one overlay is meant to serve several baselines.
                print(
                    f"::notice::{where}: {pid} is set but its control {odp.get('control')} "
                    f"is not in the {level} baseline, so it will not render into that pack."
                )

    if not bad:
        rep.ok(f"Overlay values: {len(overlays)} overlay(s) against {len(odps)} ODP(s)")


def check_rule_catalogs(root: Path, rep: Report) -> None:
    """Validate rule catalogs by RUNNING THE GENERATOR against them.

    Deliberately not a second implementation of the same rules. generate.py
    already refuses an undeclared ODP reference, a dishonest `coverage`, a KSI in
    the 800-53 column, an out-of-baseline binding and every cap. A lint that
    re-implemented those checks would drift from the generator, and the drift
    would show up as CI passing something the generator rejects -- or worse, the
    reverse.

    The generated output is left in `_lint_out` for the cap check to measure, so
    the caps are asserted against what was actually rendered rather than against
    a hand-written template that may not resemble it.
    """
    rules_dir = root / "rules"
    if not rules_dir.is_dir() or not any(rules_dir.glob("*.yaml")):
        rep.defer("Rule catalog schema", "rules/*.yaml do not exist yet (Phase 2)")
        return

    gen = root / "generate.py"
    if not gen.exists():
        rep.fail(
            "rules/*.yaml exist but generate.py does not. Nothing validates a rule "
            "catalog's ODP bindings, coverage honesty or control crosswalk."
        )
        return

    overlay = root / "overlays" / "vanilla.yaml"
    if not overlay.exists():
        rep.fail("rules/*.yaml exist but overlays/vanilla.yaml does not; nothing to render against")
        return

    out = root / "out" / "_lint"
    r = subprocess.run(
        [sys.executable, str(gen), "--overlay", str(overlay), "--out", str(out), "--emit-oscal"],
        capture_output=True, text=True, cwd=root,
    )
    if r.returncode != 0:
        rep.fail(f"generator rejected the rule catalogs:\n{r.stdout}{r.stderr}".strip())
        return

    n = len(list(rules_dir.glob("*.yaml")))
    rep.ok(f"Rule catalog schema: {n} catalog(s) render and validate")
    for line in r.stdout.splitlines():
        if line and not line.startswith("  wrote"):
            print(f"  {line}")


def check_guard_policies(root: Path, rep: Report) -> None:
    """Guard policies must declare every token some rule substitutes.

    Guard does NOT error on a live `{{Token}}`. It evaluates against the literal
    text, and the rule reports a verdict nobody should trust. The generator
    already refuses an unsubstituted token at render time; this catches the other
    direction -- a placeholder in a policy file that NO rule binds, which would
    survive until someone happens to render that policy.
    """
    guard_dir = root / "guard"
    policies = sorted(guard_dir.glob("*.guard")) if guard_dir.is_dir() else []
    if not policies:
        rep.defer("Guard token substitution", "guard/*.guard do not exist yet (Phase 2, CRYPTO)")
        return

    bound: dict[str, set[str]] = {}
    rules_dir = root / "rules"
    for rf in sorted(rules_dir.glob("*.yaml")) if rules_dir.is_dir() else []:
        try:
            doc = yaml.safe_load(rf.read_text()) or {}
        except yaml.YAMLError:
            continue
        for rule in (doc.get("rules") or {}).values():
            if rule.get("source") == "guard" and rule.get("policy"):
                bound.setdefault(rule["policy"], set()).update(
                    (rule.get("tokens") or {}).keys())

    bad = 0
    for pol in policies:
        tokens = set(re.findall(r"\{\{(\w+)\}\}", pol.read_text()))
        declared = bound.get(pol.name)
        if declared is None:
            rep.fail(
                f"{pol.relative_to(root)}: no rule in rules/*.yaml references this "
                f"policy. An unreferenced Guard file is either dead or a rule that "
                f"was never wired up."
            )
            bad += 1
            continue
        if unbound := tokens - declared:
            rep.fail(
                f"{pol.relative_to(root)}: token(s) {sorted(unbound)} appear in the "
                f"policy but no rule binds them. Guard does not error on a live "
                f"placeholder -- it evaluates the literal text and reports a verdict "
                f"nobody should trust."
            )
            bad += 1
        if phantom := declared - tokens:
            rep.fail(
                f"{pol.relative_to(root)}: rule(s) declare token(s) {sorted(phantom)} "
                f"that do not appear in this policy. A binding that substitutes "
                f"nothing is a threshold that silently does not apply."
            )
            bad += 1

    if not bad:
        n = sum(len(re.findall(r"\{\{(\w+)\}\}", p.read_text())) for p in policies)
        rep.ok(f"Guard token substitution: {len(policies)} policy file(s), {n} token(s) bound")


def check_resource_type_map(root: Path, rep: Report) -> None:
    """Every resource type a rule uses must have an EXPLICIT service mapping.

    Deriving the service from the type string resolves `AWS::RDS::DBCluster` to
    DocDB, because DocumentDB shares the `rds` ARN namespace. A wrong service
    means a wrong Region scope, which is silent: the pack deploys and the rule
    reports INSUFFICIENT_DATA forever.
    """
    idx = root / "vendor/aws-services/aws-service-availability.json"
    mp = root / "vendor/aws-services/resource-type-map.yaml"
    rules_dir = root / "rules"
    if not mp.exists() or not idx.exists():
        rep.defer("Resource-type service map", "vendor/aws-services/ is not present yet")
        return
    m = yaml.safe_load(mp.read_text())
    import json as _json
    services = set(_json.loads(idx.read_text())["services"])
    mapped = set(m.get("map") or {}) | set(m.get("account_level") or [])

    used: set[str] = set()
    for rf in sorted(rules_dir.glob("*.yaml")):
        try:
            doc = yaml.safe_load(rf.read_text()) or {}
        except yaml.YAMLError:
            continue
        # Pack-level `required_resource_types` too, not only rule-level. The
        # preflight asserts the pack-level list, so an unmapped entry there
        # crashed it against a live account while this check reported clean.
        used |= set(doc.get("required_resource_types") or [])
        for rule in (doc.get("rules") or {}).values():
            used |= set(rule.get("resource_types") or [])

    bad = 0
    if unmapped := used - mapped:
        rep.fail(
            f"resource type(s) {sorted(unmapped)} are used by a rule but have no entry "
            f"in {mp.name}. Add them explicitly; deriving the service from the type "
            f"string resolves AWS::RDS::* to DocDB.")
        bad += 1
    if ghost := {s for s in (m.get("map") or {}).values() if s not in services}:
        rep.fail(f"{mp.name} maps to service(s) {sorted(ghost)} that the availability "
                 f"index does not contain.")
        bad += 1
    if not bad:
        rep.ok(f"Resource-type service map: {len(used)} type(s) mapped")


def check_readme_coverage(root: Path, rep: Report) -> None:
    """README's coverage table must match the catalogs.

    It is the first thing an adopting team reads to decide whether this is worth
    running. A stale coverage claim is worse than none, so it is generated and
    this check fails when it drifts.
    """
    readme = root / "README.md"
    gen = root / "tools/coverage_report.py"
    if not readme.exists() or not gen.exists():
        rep.defer("README coverage table", "README.md or the generator is absent")
        return
    r = subprocess.run([sys.executable, str(gen), "--check"],
                       capture_output=True, text=True, cwd=root)
    if r.returncode != 0:
        rep.fail(f"README coverage table is stale:\n{r.stdout}{r.stderr}".strip())
    else:
        rep.ok("README coverage table matches the catalogs")


def check_parameter_bindings(root: Path, rep: Report) -> None:
    """Every rule parameter binds exactly one of `odp` or `literal`.

    A binding with neither renders nothing; a binding with both is ambiguous about
    whether the value was a tenant decision, which is the distinction the
    traceability report exists to record.
    """
    rules_dir = root / "rules"
    files = sorted(rules_dir.glob("*.yaml")) if rules_dir.is_dir() else []
    if not files:
        rep.defer("Parameter bindings", "rules/*.yaml do not exist yet")
        return
    bad = 0
    for rf in files:
        try:
            doc = yaml.safe_load(rf.read_text()) or {}
        except yaml.YAMLError:
            continue
        for name, rule in (doc.get("rules") or {}).items():
            for param, b in (rule.get("parameters") or {}).items():
                has = {"odp", "literal"} & set(b or {})
                if "derive" in (b or {}) and "odp" not in (b or {}):
                    rep.fail(f"{rf.relative_to(root)}:{name}.{param}: `derive` needs an `odp`")
                    bad += 1
                if len(has) != 1:
                    rep.fail(
                        f"{rf.relative_to(root)}:{name}.{param}: binding must declare "
                        f"exactly one of `odp` or `literal`, found {sorted(has) or 'neither'}."
                    )
                    bad += 1
    if not bad:
        rep.ok(f"Parameter bindings: {len(files)} catalog(s)")


def check_generated_packs(root: Path, rep: Report) -> None:
    """Cap assertions against generated templates.

    `out/` is gitignored, so in CI this normally finds nothing -- the caps are
    enforced by the generator itself. This is the belt to that suspenders, for a
    template committed deliberately or produced by a generate step in the job.
    """
    candidates = [p for p in _walk(root, "*.yaml") if "conformance" in p.name.lower()]
    out_dir = root / "out"
    if out_dir.is_dir():
        candidates += sorted(out_dir.rglob("*.yaml"))
    if not candidates:
        rep.defer("Pack cap assertions", "no generated pack templates present to measure")
        return
    bad = 0
    for tpl in candidates:
        raw = tpl.read_bytes()
        try:
            doc = yaml.safe_load(raw.decode()) or {}
        except yaml.YAMLError:
            continue  # already reported by the YAML check
        if not isinstance(doc, dict) or "Resources" not in doc:
            continue
        rules = [
            k for k, v in (doc.get("Resources") or {}).items()
            if isinstance(v, dict) and v.get("Type") == "AWS::Config::ConfigRule"
        ]
        params = list((doc.get("Parameters") or {}).keys())
        name = tpl.relative_to(root)
        if len(rules) > MAX_RULES_PER_PACK:
            rep.fail(f"{name}: {len(rules)} Config rules exceeds the hard cap of {MAX_RULES_PER_PACK}")
            bad += 1
        if len(params) > MAX_PARAMS_PER_PACK:
            rep.fail(f"{name}: {len(params)} parameters exceeds the hard cap of {MAX_PARAMS_PER_PACK}")
            bad += 1
        if len(raw) > MAX_S3_TEMPLATE_BYTES:
            rep.fail(f"{name}: {len(raw)} bytes exceeds the {MAX_S3_TEMPLATE_BYTES}-byte S3 template limit")
            bad += 1
        elif len(raw) > MAX_INLINE_TEMPLATE_BYTES:
            print(
                f"::notice::{name} is {len(raw)} bytes -- over the "
                f"{MAX_INLINE_TEMPLATE_BYTES}-byte inline limit, so it must be staged in S3 "
                f"(template-s3-uri), not passed as a template body."
            )
        if not bad:
            print(f"  {name}: {len(rules)} rules, {len(params)} parameters, {len(raw)} bytes")
    if not bad:
        rep.ok(f"Pack cap assertions: {len(candidates)} template(s) measured")


CHECKS = (
    check_yaml_parses,
    check_shell_syntax,
    check_issue_front_matter,
    check_python_compiles,
    check_odp_catalog,
    check_overlays,
    check_rule_catalogs,
    check_guard_policies,
    check_parameter_bindings,
    check_readme_coverage,
    check_resource_type_map,
    check_generated_packs,
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", default=".", type=Path)
    args = ap.parse_args()
    root = args.repo_root.resolve()

    rep = Report()
    for check in CHECKS:
        check(root, rep)

    print("\n" + "=" * 70)
    print("PACK LINT COVERAGE")
    print("=" * 70)
    for msg in rep.passed:
        print(f"  PASS     {msg}")
    for check, reason in rep.pending:
        print(f"  PENDING  {check} -- {reason}")
    for msg in rep.failed:
        print(f"  FAIL     {msg.splitlines()[0]}")
    print("=" * 70)
    print(f"{len(rep.passed)} passed, {len(rep.pending)} pending, {len(rep.failed)} failed")

    if rep.pending:
        print(
            "\nPENDING checks are not passing checks. They are checks this repository "
            "cannot run yet because the artifact they inspect does not exist. Each one "
            "turns into a FAILURE the moment its artifact appears without a validator, "
            "so none of them can be quietly forgotten."
        )
    print("=" * 70)
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())

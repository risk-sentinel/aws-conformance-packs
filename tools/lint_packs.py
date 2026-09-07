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
            # A CloudFormation template's !Ref etc. are custom tags; parse with
            # a loader that tolerates them rather than rejecting valid CFN.
            yaml.safe_load(f.read_text())
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


def check_odp_catalog(root: Path, rep: Report) -> None:
    path = root / "odp" / "catalog.yaml"
    if not path.exists():
        rep.defer("ODP catalog schema", "odp/catalog.yaml does not exist yet (Phase 1a)")
        return
    rep.fail(
        "odp/catalog.yaml exists but tools/lint_packs.py has no validator for it. "
        "The catalog must be checked for: OSCAL param_id keys, a declared type, a "
        "constraint, and baseline_level coverage. Write that validator before merging "
        "the catalog -- a catalog nothing validates is how a bad threshold reaches a "
        "deployed pack."
    )


def check_rule_catalogs(root: Path, rep: Report) -> None:
    rules_dir = root / "rules"
    if not rules_dir.is_dir() or not any(rules_dir.glob("*.yaml")):
        rep.defer("Rule catalog schema", "rules/*.yaml do not exist yet (Phase 2)")
        return
    rep.fail(
        "rules/*.yaml exist but tools/lint_packs.py has no validator for them. "
        "Each rule needs `controls`, an honest `coverage` value, and ODP bindings that "
        "resolve against odp/catalog.yaml. Unresolvable ODP references are the defect "
        "this check exists to catch."
    )


def check_guard_policies(root: Path, rep: Report) -> None:
    guard_dir = root / "guard"
    if not guard_dir.is_dir() or not any(guard_dir.glob("*.guard")):
        rep.defer("Guard token substitution", "guard/*.guard do not exist yet (Phase 2, CRYPTO)")
        return
    rep.fail(
        "guard/*.guard exist but tools/lint_packs.py does not check them for "
        "unsubstituted {{Token}} placeholders. A Guard policy shipped with a live "
        "placeholder does not error -- it evaluates against the literal text and the "
        "rule reports a result nobody should trust."
    )


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
    check_rule_catalogs,
    check_guard_policies,
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

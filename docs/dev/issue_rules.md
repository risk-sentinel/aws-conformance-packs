# SPARC-Validate Issue Process Rules

Standard workflow for every issue in the sparc-validate repository.
These rules are **mandatory** — no exceptions without explicit owner approval.

---

## Hard Guardrails

- **Never push directly to `main`** — all changes go through feature/bug branches
- **Never merge PRs** — only the repository owner merges
- **Always plan before implementing** — get approval before writing code
- **Never use `brew`** — find alternatives or ask the user
- **Never modify CI workflows without explicit approval**
- **Never suppress a scanner finding without explicit approval** — see [Suppressing scanner findings](#suppressing-scanner-findings)
- **Never put account-specific identifiers in commit / PR / issue messages** — no account numbers, ARNs, ECR/registry URIs (they embed the account #), resource IDs (`sg-…`, `vol-…`, `db-…`), or regions in narrative text. Reference abstractly ("the scanner role", "the prod account", "the deployed region") or by secret/variable name (`AWS_ROLE_ARN`, `ECR_REGISTRY`). Git history + GitHub text are lower-trust than the code. (Code/config that legitimately needs a literal value is a separate concern.)
- **Always update compliance artifacts** when adding or modifying InSpec controls

---

## Suppressing scanner findings

**Every suppression requires explicit owner approval, before it is committed.**

A suppression is a decision that a reported risk will not be fixed. That is a
risk-acceptance decision, and risk acceptance belongs to the owner — not to
whoever happened to be looking at a red check. The person suppressing is always
the person most motivated to make the red thing go away, which is exactly why
they should not be the one deciding.

This applies to **any scanner**, in **any repository in the estate**. The act is
the same wherever it happens; only the syntax changes.

### What counts as a suppression

Not an exhaustive list. If the effect is *a finding stops being reported*, the
rule applies.

| Scanner | Mechanism |
|---|---|
| SonarCloud / SonarQube | `# NOSONAR`, `// NOSONAR`, "Won't fix" / "False positive" in the UI, `sonar.issue.ignore.*` |
| CodeQL / code scanning | Dismissing an alert, `paths-ignore`, query filters, `// codeql[rule]` |
| Dependabot | Dismissing an alert, `ignore:` in `dependabot.yml` |
| Secret scanning | Dismissing an alert, `.trufflehog-exclude-paths`, `--exclude-paths`, allow-list entries |
| Grype / Trivy / Snyk | `.grype.yaml` / `.trivyignore` ignore entries, SCA allow-lists, `--severity` raised to hide a class |
| Checkov / tfsec | `# checkov:skip=`, `#tfsec:ignore:`, `--skip-check` |
| InSpec / CINC | A waiver file, `only_if` added to make a failing control not run, `impact 0.0` used to hide rather than to mark N/A |
| Any CI gate | `continue-on-error: true` on a check that was gating, removing a required status check, lowering a quality-gate threshold |

**Deleting or narrowing a test so it stops failing is a suppression too**, even
though no scanner is involved.

### The bar for approving one

Suppression is legitimate. It is the *unexamined* suppression that is not. A
request should carry:

1. **What the finding says**, quoted — rule ID, severity, file and line.
2. **Why it is wrong or accepted.** "False positive" is a claim, not a reason;
   say what the analyser cannot see. If it is a real risk being accepted, say
   what compensates for it.
3. **What was tried first.** Fixing the code is the default. Reaching for a
   suppression before attempting a fix is the failure mode this rule exists to
   catch.
4. **Scope and lifetime.** One line, or the whole directory? Permanent, or until
   a named issue closes?

### Fix first, and prove the constraint

Two findings on `dev-sec-ops-baseline` PR #23 show both outcomes.

CodeQL flagged `rb/clear-text-storage-sensitive-data` on a test that proved a
secret was stripped and then wrote the derived document to disk. Dismissing it
was available and would have been wrong: the finding was correct in shape, and
the fix — export from input that never held a credential — was better code.

Sonar's duplicate-literal rule on four `tag layer:` values genuinely cannot be
satisfied: InSpec's `TagCollector` walks the AST before evaluation, so a tag
value must be a literal node and both a constant and a method call crash
`cinc-auditor check`. That was **verified against the pinned image**, not
asserted from memory, and the verification is what made it a suppression worth
approving rather than a guess.

If you believe a rule cannot be satisfied, demonstrate it. An untested "this
would break" is not a reason.

### How to record one

- **Prefer in-code suppression over the scanner's UI.** A `# NOSONAR` with the
  reason beside it travels with the file, survives a project re-key, and is
  visible in review. A "won't fix" clicked in a dashboard is invisible to
  everyone reading the code and is lost when the project is recreated.
- **The reason goes next to the suppression**, not only in the commit message.
- **Platform alert dismissals are the exception** — dismiss those in the
  platform *with a reason*, because the platform records who decided and when,
  which an ignore-file cannot. `dev-sec-ops-baseline`'s
  `devsecops-dismissals-accountable` control asserts that reason and owner are
  present, and the dashboard bridge carries them into the HDF as Not Applicable
  rather than dropping the finding.
- **Never suppress silently in a large PR.** Call it out in the PR body so it is
  reviewed as a decision rather than skimmed as noise.

### Why this is stricter here than elsewhere

These repositories produce FedRAMP evidence. A suppressed finding does not just
disappear from a dashboard — it changes what the evidence package asserts. An
assessor asking "who accepted this, and on what basis" needs an answer that is
not "a scanner was quiet that day".

---

## Workflow Steps

1. **Pull from Main** unless otherwise noted
2. **Assign the issue** to me
3. **Review the issue** and updated notes/comments
4. **Start a fresh branch** — `feature/` or `bug/` prefix with the issue
   number in the branch name (e.g., `feature/1_inspec_profiles`)
5. **Create a plan** — get approval before writing code
6. **Implement the approved plan**
7. **Troubleshoot any issues**
8. **Update project documentation:**
   - `docs/dev/Implementation_plan.md` — mark issue complete, update phase status
   - `docs/dev/Developer_Collision_Avoidance_Plan.md` — update file lists, status
   - Regression testing — validate InSpec profiles execute without errors
9. **Compliance artifact review** — if the issue adds or modifies InSpec
   controls that map to NIST controls:
   - Ensure InSpec control `tag` metadata includes correct NIST control IDs
   - Verify HDF output converts cleanly via `hdf_to_oscal.py`
   - Update NIST control coverage table in Implementation_plan.md
10. **Run validation before commit:**
    - `inspec check profiles/<profile_name>` — syntax validation
    - `inspec exec profiles/<profile_name> --reporter json` — if test
      environment is available
    - Verify all profile `inspec.yml` metadata is complete (name, title,
      version, maintainer, summary, supports)
11. **Commit / push changes**
    - Reference the issue in all commit messages
12. **Wait for user testing**
    - Functional testing against dev/staging AWS environment
    - Review HDF output in Heimdall
13. **Create a PR**
    - Reference the issue so it will auto-close on merge
    - Wait for the PR to be merged by the owner before moving forward

---

## InSpec Profile Standards

### Profile Structure

Every profile must follow this structure:

```text
profiles/<profile-name>/
  inspec.yml          # Metadata + dependencies
  controls/           # Control files (.rb)
  inputs.yml          # Configurable parameters
  README.md           # Profile documentation
```

### Control Tagging

All InSpec controls must include NIST control ID tags:

```ruby
control 'sparc-ecs-001' do
  title 'ECS tasks use awsvpc network mode'
  desc 'Ensures network isolation per NIST SC-7'
  tag nist: ['SC-7', 'CM-6']
  tag severity: 'high'
  # ...
end
```

### HDF Output

All profiles must produce valid HDF (Heimdall Data Format) output that
can be consumed by sparc-iac's `hdf_to_oscal.py` converter.

---

## Cross-Repository Dependencies

| Repository | Dependency | Direction |
|------------|-----------|-----------|
| **sparc-iac** | Consumes HDF artifacts from sparc-validate | sparc-validate -> sparc-iac |
| **sparc-iac** | Provides AWS Config evaluations for #2 | sparc-iac -> sparc-validate |
| **sparc** | Provides API endpoints for #3 (API testing tool) | sparc -> sparc-validate |

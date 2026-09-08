# AWS Conformance Packs — Implementation Plan

Structured, prioritized roadmap for `risk-sentinel/aws-conformance-packs`.

This repo generates **domain-split AWS Config conformance packs** for NIST SP
800-53 Rev 5 and FedRAMP 20x from one portable rule catalog plus a
per-organization ODP overlay. It is a *generator and a deployment pattern*, not a
profile: there are no InSpec controls here. Evidence leaves this repo as Config
rule evaluations, which `risk-sentinel/aws-config` converts to HDF.

**Last updated:** 2026-09-08 (**CRYPTO complete — the first Guard-bearing pack.** Three
domains done: IAM 25, NET 34, CRYPTO 31 = 90 rules, and the lint now reports **zero
pending checks** for the first time. Two CRYPTO thresholds have no managed-rule
parameter anywhere — KMS rotation *period* (the managed rule is boolean) and the TLS
floor — so both are `CUSTOM_POLICY` Guard rules whose values are substituted into
policy text at generation time. That is a real operational difference: changing either
ODP means regenerate + redeploy, not a stack parameter update. The KMS policy is scoped
to symmetric customer-managed keys with AWS-generated material, because AWS-managed,
asymmetric and imported keys cannot rotate at all and including them would produce
permanent unfixable non-compliance — noise that trains people to ignore the pack.
Rendered size is 21,650 bytes, comfortably inside the 51,200-byte inline limit, so the
S3-staging threshold is not yet reached. Next: LOG, VCM, RPL.)

---

## Guiding Principles

- **Portability is the product.** The rule catalogs carry no organization values
  and no organization control names. A new tenant is a new overlay, never a
  catalog fork. Any change that puts an agency threshold or an agency-specific
  control label into `rules/` or `odp/catalog.yaml` breaks the premise.
- **Two forges, one repo.** A consumer must get a working pipeline on GitHub *or*
  GitLab by cloning and editing one file. Follow the estate pattern:
  `.github/workflows/` + `ci/gitlab/` + a root `.gitlab-ci.yml` that is inert on
  GitHub. Each repo carries its own copy — see
  [`ci-templates.md` reasoning](#why-templates-are-copied-not-shared).
- **`inputs.yml` is the consumer contract.** Which packs, which accounts, which
  regions — the same split as an InSpec profile's `inputs.yml` /
  `inputs.template.yml`. Nothing about a consumer's environment gets a default.
- **The ODP schema is copied from SPARC, not invented.** `GET /api/v1/profile_documents/:slug/parameters`
  already resolves OSCAL parameters per baseline level (Low / Moderate / High).
  An overlay is a **local file** using its field names and `param_id`
  vocabulary, so it round-trips through the API without a translation layer —
  but generation never calls it.
- **Generation fails rather than deploying a wrong threshold.** The generator is
  also the validator; every cap and constraint is a non-zero exit.
- **Honest coverage or none.** `INSUFFICIENT_DATA` is not compliance, and a
  coverage percentage whose denominator is the catalog rather than the baseline
  is a number that misleads. Both are stated in every report.
- **Leverage what exists.** `sparc-iac` already deploys a conformance pack;
  `aws-config` already converts Config evaluations to HDF. This repo supplies the
  pack and the parameterization, not a new evidence pipeline.

---

## Issue Process

See **[`docs/dev/issue_rules.md`](issue_rules.md)** for the complete mandatory
workflow and hard guardrails. Two apply with particular force here:

- **Never put account-specific identifiers in commit / PR / issue text.** This
  repo's whole subject matter is account ids, regions and ARNs. Keep them in
  `inputs.yml` and CI variables; reference them abstractly in prose.
- **Never suppress a scanner finding without owner approval.** These packs
  produce FedRAMP evidence; a suppressed finding changes what the package
  asserts.

### Delivering the whole issue

A first pass at NET built **8 of the 18 candidate rules issue #3 names**, against
an estimate of 20–30, and the PR said `Closes #3`. Nothing was wrong with the 8;
what was wrong is that stopping there and closing the issue let the status table
redefine the target as "8 built" rather than record a shortfall.

Scaling an issue down is the owner's call. If a candidate is deliberately not
built, say which and why in the PR — an omission with a stated reason is a
decision, an omission without one is invisible.

`tests/test_generate.py::test_every_candidate_rule_named_in_the_issue_is_built`
now asserts this for NET, so the next silent shortfall fails the build.

### PR ceremony

**Every PR updates this file.** The plan is the repository's memory of what is
done and what is next; one updated only when somebody remembers goes stale
silently, and a stale roadmap is worse than none because it is read as current.

So it is enforced rather than encouraged. The `Implementation plan updated` step
in `pack-lint.yml` fails any PR that changes files outside `docs/` without also
changing `docs/dev/Implementation_plan.md`. Docs-only PRs are exempt — they are
the record.

The waiver requires a reason, in the PR body:

    Plan-Update: not-required — <reason>

Same principle as suppressions above: the act is legitimate, and it is the
*unexamined* one that is not. `.github/pull_request_template.md` carries the
checklist.

---

## Status snapshot

> **Updated 2026-09-07.** Every row is verified against the repo and the GitHub
> API as of that date, not projected.

| Bucket | Current state |
|---|---|
| Tracking issues | **9 filed** — #1 epic, #2–#8 domains, **#9 Phase 0** (active) |
| Generator (`generate.py`) | **Built** (#13) — resolves, renders, validates, emits 5 artifacts. 22 tests |
| ODP catalog (`odp/catalog.yaml`) | **12 ODPs** — every `oscal_param_id` now checked for existence against the vendored NIST index |
| Rule catalogs (`rules/<domain>.yaml`) | **2 / 6** — `iam.yaml` (7 rules, partial; #2 open) and `net.yaml` (18 rules, #3). 25 rules total |
| Guard policies (`guard/`) | **2** — KMS rotation period and the ELB TLS floor. Values bake at generation time |
| Overlays (`overlays/`) | **3** — `vanilla.yaml` (moderate), `vanilla-low.yaml`, `vanilla-high.yaml`. All three generate; Low records 2 exclusions |
| Repo CI | **5 workflows.** secret-scan (+ fixture canary), pack-lint, CodeQL (python), 2 HDF emitters |
| Branch protection | **Active ruleset** (id 22464078) — 4 required contexts, strict policy, PR + CODEOWNERS review, no deletion, no force-push. Admin bypass retained for the solo-owner case |
| Secret-scan fixture canary | **Green** — proves the scanner still fires |
| GitLab pipeline | **Absent** |
| Deployment `inputs.yml` contract | **Not designed** |
| Reference pack available to mine | `sparc-iac` `AWS/ECS/modules/aws_config/` — 107 rules, awslabs NIST r5 pack trimmed for a Fargate boundary |
| Evidence path | `risk-sentinel/aws-config` reusable workflow already fetches Config evaluations → HDF. Emit grant filed as **sparc-iac#701**; workflows degrade to build artifacts until it lands |
| Highest-priority next work | **Phase 2 — all six domains**, now that KSI ids resolve against a vendored snapshot and the generator enforces them. Open: SonarCloud onboarding for the 5th required context |

---

## Phase 0 — Repo trustworthiness ([#9](https://github.com/risk-sentinel/aws-conformance-packs/issues/9) — COMPLETE)

**Goal:** this repo meets the same bar as the 14 profile repos before it emits
anything anyone relies on. Nothing in Phase 1+ starts until the ruleset is on.

Approved by the owner 2026-09-07; landed via PR #10.

### Outcome

Five workflows on `main`; ruleset `main` (id 22464078) active with
`strict_required_status_checks_policy: true` and four required contexts:
`Verified secrets gate`, `Fixture detection (proves scanner works)`,
`Pack lint + template validate`, `Analyze (python)`.

**Three things worth carrying forward:**

1. **Admin bypass means "no direct push to main" is not literally true.** The
   ruleset objects — a push is answered with *"Cannot force-push to this branch"*
   and *"Changes must be made through a pull request"* — and then the
   `RepositoryRole` bypass lets an admin through anyway. That is the estate's
   deliberate solo-owner configuration, not a misconfiguration, but the guardrail
   is a convention for the owner and an enforced rule for everyone else. Worth
   knowing before relying on it.
2. **`Analyze (actions)` would not stick.** It reported once during setup, but the
   code-scanning API keeps resolving the language list back to `["python"]`. It is
   deliberately **not** a required context — requiring one that reports
   inconsistently blocks every PR. Retry later; the loss is workflow-injection
   scanning, which is small.
3. **SonarCloud is not onboarded.** `SonarQube HDF emit` fails at *Resolve and
   verify the SonarQube project key*, which is the workflow behaving correctly:
   it verifies the key exists before fetching, because an unknown key returns
   nothing and converts into a valid, EMPTY, clean-looking report. Once the
   project is registered and `SONAR_TOKEN` set, add `SonarCloud Code Analysis`
   as the fifth required context.

Copy the pattern from `stig-aws-ecr-baseline`, which is the estate's pilot repo.
Adapt language: that repo is Ruby/InSpec, this one is Python/YAML/CloudFormation.

### Workflows to land

| File | Source to copy | Adaptation needed |
|---|---|---|
| `.github/workflows/secret-scan.yml` | `stig-aws-ecr-baseline` | None — copy verbatim. Two jobs: `Verified secrets gate` (hard gate, `--only-verified`, fixture excluded) and `Fixture detection (proves scanner works)` (soft canary asserting the scanner still fires) |
| `.github/workflows/pack-lint.yml` | `profile-lint.yml`, restructured | **This is the new one.** Replaces InSpec lint with: `python -m compileall` / `ruff` on the generator, YAML schema validation of `odp/catalog.yaml` + `rules/*.yaml`, `cfn-lint` on every generated template, and the cap assertions (≤130 rules, ≤60 parameters, template size). Until the generator exists it lints what is there and asserts nothing falsely |
| `.github/workflows/codeql.yml` | estate default | Language `python` (the profile repos use `ruby`) |
| `.github/workflows/secret-scan-hdf-emit.yml` | `stig-aws-ecr-baseline` | Caller to `risk-sentinel/dev-sec-ops-baseline/.github/workflows/secret-scan-hdf.yml` pinned at a SHA. Change the emit-ARN secret name to this repo's |
| `.github/workflows/sonarqube-hdf-emit.yml` | `stig-aws-ecr-baseline` | Self-contained; change `REPO_SLUG` |
| `.github/CODEOWNERS` | `stig-aws-ecr-baseline` | `* @sm00thindian @clem-field` |
| `.trufflehog-exclude-paths` | `stig-aws-ecr-baseline` | Add `tests/trufflehog-fixture` |
| `tests/trufflehog-fixture/` | `stig-aws-ecr-baseline` | Synthetic AKIA key + README explaining it is deliberate |
| `.sonarcloud.properties` | `stig-aws-ecr-baseline` | Python source paths |

### Branch ruleset

Match the profile-repo ruleset exactly in shape, with the status-check contexts
retargeted. The profile repos run `enforcement: active`, bypass limited to
`RepositoryRole` (the solo-owner admin case), and:

- `deletion` and `non_fast_forward` blocked
- `pull_request`: 1 approving review, `dismiss_stale_reviews_on_push: true`,
  `require_code_owner_review: true`
- `required_status_checks` with `strict_required_status_checks_policy: true`

Required contexts here (the profile repos' five, with the two Ruby ones swapped):

| Profile-repo context | This repo |
|---|---|
| `Verified secrets gate` | same |
| `Fixture detection (proves scanner works)` | same |
| `SonarCloud Code Analysis` | same |
| `InSpec validate + Ruby syntax` | → **`Pack lint + template validate`** |
| `Analyze (ruby)` | → **`Analyze (python)`** |

**Sequencing trap:** a required context that has never reported blocks every PR
forever. Land the workflows on `main` first so each context registers, *then*
apply the ruleset. This is why Phase 0 is the one arc that legitimately touches
`main` directly — and it needs explicit owner approval per the guardrails, since
it is CI work.

**Acceptance:** a PR with a synthetic secret is blocked; a PR with the fixture
untouched is green; direct push to `main` is refused; the ruleset returns 5
required contexts from the API.

---

## Phase 1 — ODP catalog + generator skeleton

**Goal:** one governance decision lives in one place, and a bad value fails the
build instead of deploying.

### 1a — ODP catalog + vanilla overlay ([#11](https://github.com/risk-sentinel/aws-conformance-packs/issues/11))

**What the OSCAL catalogs actually said.** Derived from the Rev 5 resolved
baselines rather than assumed, and all three findings changed the schema:

1. **Rev 5 ids are `ia-05.01_odp.02`, not `ia-5.1_prm_2`.** The `_prm_` form
   survives as an `alt-identifier` prop on each parameter — and it is the form
   SPARC's ODP import fixture uses. The catalog carries **both**, so a value
   joins from either direction with no lookup table maintained elsewhere.
2. **An AWS rule parameter is not 1:1 with an ODP.** `ia-05.01_odp.02` is a
   single free-text ODP — *"authenticator composition and complexity rules are
   defined"*. Minimum length, maximum age and reuse prevention are three AWS
   knobs expressing that one ODP. `ia-05_odp.01` — *"time period for changing or
   refreshing authenticators **by authenticator type**"* — likewise covers both
   access-key and Secrets Manager rotation; its own wording anticipates
   different values per type. **This is why the catalog is keyed by our name and
   joins to OSCAL.** Keying on OSCAL ids cannot represent it at all.
3. **Baseline membership differs and is load-bearing.** Low resolves 149
   controls, Moderate 287, High 370, and `ac-2.3` is absent from Low entirely.
   An ODP bound to a control outside the target baseline must not render — it
   would measure something the baseline never asked for and report it as
   coverage. A value set for an out-of-baseline ODP is a **notice**, not an
   error: one overlay is meant to serve several baselines.

**Correction to issue #2.** It lists *Static key max age* and *Secret rotation
period* under `ia-5.1`. Both are semantically `ia-5` (`ia-05_odp.01`,
authenticator refresh period); `ia-5.1` is specifically password composition.
Bound to `ia-5` in the catalog.

### 1a reference — the SPARC schema being matched

SPARC's baseline-parameters API is the schema of record. Verified surface:

```
GET  /api/v1/profile_documents/:slug/parameters          # schema for a baseline
PUT  /api/v1/profile_documents/:slug/parameters          # bulk update
GET  /api/v1/profile_documents/:slug/parameters/export   # json | yaml | xml
POST /api/v1/profile_documents/:slug/parameters/import/preview
POST /api/v1/profile_documents/:slug/parameters/import/confirm
```

Response envelope carries `baseline`, **`baseline_level`** (Low / Moderate /
High), `version`, `profile_id`, `profile_slug`, `parameters[]`, `selections[]`.

| Entity | Fields |
|---|---|
| parameter | `param_id`, `control_id`, `control_title`, `label`, `description`, `type`, `constraint`, `current_value`, `value` |
| selection | `select_id`, `control_id`, `control_title`, `label`, `description`, `how_many`, `choices`, `choice_details`, `depends_on`, `selected` |

The bulk-import file shape (SPARC's `spec/fixtures/files/odp/sample_odp.yaml`) is
what an overlay should be able to produce verbatim:

```yaml
parameters:
  - param_id: ac-1_prm_1
    value: ISSO and System Administrators
selections:
  - select_id: ac-2_prm_1
    selected: [removes, disables]
```

**Design consequences for `odp/catalog.yaml`:**

- Key ODPs by **OSCAL `param_id`** (`ia-5.1_prm_1`), not a local name. That is
  the join to the API, to `--set-parameters-from`, and to the resolved profiles.
- Carry `baseline_level` so one catalog serves Low / Moderate / High rather than
  three forks.
- **Model `selections` as first-class**, not as an enum string. A `how-many`
  selection with `depends_on` references is common in 800-53 and collapsing it
  loses the round-trip.
- `constraint` is the build-time gate. Range, enum, and list-capacity live here.

**Decided 2026-09-07 (owner):** the overlay is a **local file the user fills
out**, in the same shape SPARC's export/import uses. The generator never calls
the SPARC API. Two reasons: pack generation must not depend on a running SPARC
instance — that would make the build unusable for the outside consumers this
repo exists to serve — and a file is reviewable in a PR, which an API read is
not.

Consistency with SPARC is the point of copying the shape, not an accident of it:

- The overlay's `parameters[]` / `selections[]` entries use SPARC's field names
  and `param_id` vocabulary verbatim.
- A SPARC `GET .../parameters/export` (JSON or YAML) is therefore a **valid
  overlay** with no translation, and an overlay is valid input to
  `POST .../parameters/import/{preview,confirm}`. The round-trip works in both
  directions for anyone who has SPARC; nothing requires it.
- `--set-parameters-from` stays as the OSCAL-resolved-profile path.

### Vanilla defaults ship first

`overlays/vanilla.yaml` is the starting overlay, and it is deliberately
unremarkable: values a reader recognizes on sight, so the mechanism is what they
have to learn rather than the numbers. The awslabs NIST r5 pack values that
`sparc-iac` already deploys are the natural anchor — password minimum length 14,
maximum age 90, reuse prevention 24, access-key rotation 90, certificate
expiry 90.

Vanilla is a teaching default, not a recommendation. Two guardrails keep that
distinction from eroding:

- Every vanilla value carries a comment naming the control and ODP it satisfies,
  so a consumer changing it knows what they are changing.
- The traceability CSV records `assigned_by: vanilla-default` — an unchanged
  default is visibly a default, never mistaken for an organizational decision.

Same pristine-reference / consumer-copy split used elsewhere in the estate:
`overlays/vanilla.yaml` is regenerated when the pattern changes; the consumer's
own overlay is theirs and is never overwritten.

### 1b — Generator and validators ([#13](https://github.com/risk-sentinel/aws-conformance-packs/issues/13) — COMPLETE)

`generate.py` renders and validates. Non-zero exit on: out-of-range values,
undeclared ODP references, enum violations, port lists exceeding a rule's
capacity, unsubstituted Guard tokens, >130 rules/pack, >60 parameters/pack,
template size overrun.

Resolution precedence is **overlay → OSCAL `set-parameter` → catalog default**,
with the winning source recorded per value as `assigned_by` in the traceability
CSV. That provenance column is what an assessor asks for.

### 1c — Emitters ([#13](https://github.com/risk-sentinel/aws-conformance-packs/issues/13) — COMPLETE)

`<pack>.yaml`, `<pack>.traceability.csv`, `<pack>.evidence-tags.json`,
`<pack>.coverage.md`, and `<pack>.oscal-set-params.json` under `--emit-oscal`.
Evidence tags pair the control id with **the ODP value the check measured
against** — that pairing is the defensible part.

### 1d — Control-id normalization, shared ([#13](https://github.com/risk-sentinel/aws-conformance-packs/issues/13) — COMPLETE)

One function, used by the pack generator and the GOV producer both. If GOV emits
`AC-1` and a pack emits `ac-2`, the Heimdall rollup fragments (issue #8 calls
this out explicitly).

**Delivered.** `generate.py --overlay overlays/vanilla.yaml --emit-oscal` renders
`800-53r5-IAM` — 7 rules, 7 parameters, 7,501 bytes, 13 traceability rows — and
every listed failure mode exits non-zero, each negative-controlled.

Three decisions worth carrying into Phase 2:

- **The rendered CloudFormation copies the awslabs shape** —
  `Parameter(Default)` + `Condition(not-empty)` + `Fn::If → Ref | AWS::NoValue`.
  Not invented: it is what the packs `sparc-iac` already deploys look like, and
  it preserves a real behaviour a bare `Ref` would lose — passing `''` at deploy
  time falls back to the managed rule's own built-in default.
- **`coverage_note` is rendered into the deployed rule `Description`.** A caveat
  that lives only in the catalog is a caveat nobody reads; an operator looking at
  the Config console sees the Identity Center limit on `iam-password-policy`
  there. `partial` or `supporting` without a note is a build failure — an
  unexplained partial is indistinguishable from an overstated `full`.
- **The lint runs the generator rather than re-checking it.** A second
  implementation would drift, and the drift presents as CI passing something the
  generator rejects, or the reverse.

---

## Provenance — vendored, version-stamped, derived ([#15](https://github.com/risk-sentinel/aws-conformance-packs/issues/15))

`vendor/fedramp/` carries a pinned snapshot of FedRAMP's machine-readable
Consolidated Rules, with a `PROVENANCE.md` recording source, upstream commit,
version and SHA-256.

**Why pinned rather than fetched.** 20x keeps changing until High locks around
**2027-02**. Generating against a live fetch would let a pack's crosswalk change
silently between two runs of the same command, and produce evidence that cannot
say what it was assessed against.

**What FedRAMP maintains so we do not.** Each indicator carries its own
`controls[]` array of 800-53 ids — **373 mappings**. This repo consumes that
crosswalk and does not own its accuracy.

**AWS's own pack is vendored as a verification source.**
`vendor/aws/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml` is AWS's
published mapping of managed rules to Rev 5 — **130 rules, exactly the per-pack
cap**, which independently confirms that a complete build cannot be one pack.

A managed rule's `SourceIdentifier` and parameter names are asserted from
documentation unless something checks them, and a wrong one **does not fail at
generation** — it fails at `put-conformance-pack`, or it deploys and reports
`INSUFFICIENT_DATA` forever, which reads as "not failing". The generator now
refuses an identifier or parameter name AWS does not publish.

**21 of our first 25 rules verified clean** — identifiers and every parameter
name correct. The other four are real rules absent from that pack; each now
carries `not_in_aws_pack:` with a stated reason, and they are listed in the
coverage report under *Not verifiable against AWS's published pack* so an
unverifiable rule never looks verified. It is a superset in one direction and a
subset in the other — 58 of AWS's rules are for services our issues never name,
and 25 of our candidates are newer than that pack — which is why the check has a
declared escape rather than being absolute.

**Derived, not transcribed.** `vendor/nist/nist-800-53r5-params.json` is a 226 KB
index built by `tools/build_nist_index.py` from the three Rev 5 resolved
baselines — 370 controls, 767 parameters, each with its canonical `_odp` id, its
`_prm_` alt-identifier, its guidelines prose and **which baselines it resolves
in**. `tools/odp_lookup.py` emits catalog-ready stubs from it. Neither tool
guesses `type`, `constraint` or `default`: those are judgement calls about a
specific AWS rule parameter, and a tool that filled them in would manufacture the
unreviewed assertion the catalog exists to prevent. What they remove is the
transcription step, which is where a wrong param id gets in — and a wrong id
joins to nothing while looking entirely correct.

**Baseline exclusions are recorded, never silent.** A rule binding a control
outside the target baseline is skipped and listed in the coverage report with its
reason. It used to be fatal, which meant a Low pack could not be built at all
from a catalog containing any Moderate-only rule — not a safety property, just an
unbuildable baseline.

**Two enforcement rules, and the second is the one a shape check cannot do:**

1. every `ksi:` entry must **exist** in the snapshot — kills stale ids, and names
   real successors in the failure message while refusing to pretend the re-key is
   1:1, because it is not;
2. every `ksi:` entry must **claim at least one of the rule's own controls** —
   kills a plausible-looking but wrong assignment, which is coverage asserted
   that FedRAMP does not assert.

**The lesson worth keeping.** The stale ids came from transcribing a rendered
documentation page. Values copied from HTML cannot detect drift, because nothing
compares them to anything. `sync_fedramp.py --check` runs weekly and on demand.

---

## Phase 2 — Domain packs

One issue per pack. **Work one pack per issue** (epic #1). Each domain issue
already carries its scope, candidate managed rules, ODP bindings, gotchas and
acceptance criteria — those are the requirements, not the README's estimate
table.

| Issue | Pack | Est. rules | ODPs | Why this order |
|---|---|---|---|---|
| [#2](https://github.com/risk-sentinel/aws-conformance-packs/issues/2) | **IAM** | 25–35 | 7 | Highest ODP density in the program — it exercises the catalog hardest and shakes out the schema first. Region-pinning for global resources is a pattern every later pack inherits |
| [#3](https://github.com/risk-sentinel/aws-conformance-packs/issues/3) | **NET** | **18 built** | 4 | **DONE.** Port-list capacity proved the `list` type and the slot cap. Domain caveat: Config evaluates boundary components as objects, not reachability |
| [#4](https://github.com/risk-sentinel/aws-conformance-packs/issues/4) | **CRYPTO** | **31 built** | 4 | **DONE.** First Guard-heavy pack. KMS rotation period and min-TLS have no managed-rule parameter, so this is where `CUSTOM_POLICY` token substitution and the S3-hosted-template threshold get proven |
| [#5](https://github.com/risk-sentinel/aws-conformance-packs/issues/5) | **LOG** | 30–40 | 3 | Largest rule count and where Config cost explodes — model the bill before org rollout |
| [#6](https://github.com/risk-sentinel/aws-conformance-packs/issues/6) | **VCM** | 25–35 | 3 | First `evidence_only_odps` user |
| [#7](https://github.com/risk-sentinel/aws-conformance-packs/issues/7) | **RPL** | 12–18 | 3 | Smallest; the `*-in-backup-plan` coverage trap is the lesson |

**Cross-cutting per pack (from epic #1, non-negotiable):**

- A **recorder-prerequisite check** asserting the pack's resource types are
  actually being recorded. Without it, `INSUFFICIENT_DATA` reads as "not
  failing" on every dashboard.
- Both crosswalks populated — 800-53r5 **and** 20x KSI.
- `coverage` accurate per rule (`full` / `partial` / `supporting`). Several
  issues name specific rules whose apparent coverage is overstated; those
  caveats belong in the **rendered rule description**, not only in the issue.

**Mine the existing pack first.** `sparc-iac`'s
`sparc-ecs-nist-800-53-rev5-conformance-pack.yaml` is 107 rules derived from the
awslabs NIST r5 pack and already trimmed for a real boundary. It is the fastest
source of correct rule identifiers and parameter names — and its trimming
rationale (remove rules for undeployed services to kill `INSUFFICIENT_DATA`
noise) is the same judgement each domain catalog has to make.

---

## Phase 3 — GOV: the non-Config evidence producer ([#8](https://github.com/risk-sentinel/aws-conformance-packs/issues/8))

Labelled `needs-design` and it genuinely is. **Zero Config rules by design** —
~120 Moderate controls have no resource-configuration signal, and this is what
keeps the program's coverage numbers honest rather than closing the gap with
more rules that measure nothing.

Design decisions still open:

- Artifact repo layout (one document per control family; front matter carrying
  review date, approver, version).
- Scheduled evaluation, not commit-triggered — a policy that went stale under a
  12-month ODP fails only if something evaluates it on a timer.
- The **IaC-vs-recorded inventory reconciliation** for KSI-PIY-01 is the
  valuable check and the hard one. It diffs IaC-declared resources against
  Config's recorded inventory, which catches shadow resources no pack will ever
  see.
- Dated requirements snapshot — FedRAMP-specific items move faster than 800-53.

Do not start this before Phase 1d lands: it shares the control-id normalizer.

---

## Phase 4 — Deployment portability (the ultimate goal)

**Goal:** someone outside this org clones the repo, edits one file, and their
pipeline deploys the packs they chose into their accounts and regions.

### 4a — The `inputs.yml` contract

Same split as an InSpec profile: `inputs.template.yml` is the pristine
reference, `inputs.yml` is the consumer's and is never overwritten.

Shape to design (sketch, not settled):

```yaml
packs: [IAM, NET, CRYPTO]        # which packs. No default
accounts: []                     # account ids or org-unit ids. No default
regions: []                      # No default — a wrong region reports clean
global_resource_region: ""       # where IAM is recorded. Required if IAM selected
delivery:
  pack_bucket: ""                # templates >50KB must be staged in S3
  evidence_bucket: ""
mode: single-account | organization
overlay: overlays/mine.yml
```

**Nothing gets a default.** A defaulted region reads an empty account and
reports a clean result; a defaulted bucket files evidence under someone else's
label. Both are worse than a failed pipeline. The estate's `ci-templates.md`
states this as policy and the templates enforce it.

### 4b — GitHub path

A deploy workflow that reads `inputs.yml`, stages templates to the pack bucket,
and calls `put-conformance-pack` / `put-organization-conformance-pack`.
Credentials via OIDC from the **caller's** role, following the `aws-config`
model: this repo defines the workflow and holds no role and no credentials.

`put-conformance-pack` is create-or-update, so update in place. **Deleting a pack
destroys its evaluation history** — prefer update when evidence continuity
matters.

### 4c — GitLab path

Root `.gitlab-ci.yml` (inert on GitHub) + `ci/gitlab/` job definitions +
`.gitlab-variables.yml` / `.gitlab-variables-example.yml`. Include GitLab's
built-in Secret Detection / SAST templates so a fresh clone gets a real result
with zero configuration, and carry a `pipeline-coverage` job that states which
optional jobs did and did not run — so green never quietly means "assessed
nothing".

### 4d — Terraform module (optional consumer path)

`sparc-iac`'s `modules/aws_config/` is the working reference: `conformance.tf`
uses `aws_config_conformance_pack` with `template_body = file(...)` and
`depends_on` the recorder status. Note it uses an **inline** template — fine at
~28 KB, but this program's Guard-bearing packs will cross the 51,200-byte inline
cap and need `template_s3_uri`.

**Recorder prerequisites are the module's real job.** The pack is the easy part;
the recorder, its resource-type scope, global-resource recording in exactly one
region, the delivery channel, and `AWSServiceRoleForConfigConforms` in member
accounts are what actually gate whether anything evaluates.

### Why templates are copied, not shared

A **public** repository cannot call a workflow from a **private** or **internal**
one — the run fails with 0 jobs and no logs. So each repo carries its own full
copy. Deliberately not DRY: a consumer cloning this repo gets a working pipeline
with no dependency they cannot satisfy.

---

## Phase 5 — Evidence and cross-repo integration

The Config-evaluations-to-HDF path **already exists** and needs no new code
here. `risk-sentinel/aws-config` is a `workflow_call` reusable workflow that, per
region: assumes the caller's role via OIDC, runs `hdf fetch aws-config`
(primary), cross-checks with `saf convert aws_config2hdf`, stamps workload and
target into `passthrough` via `saf supplement`, validates, and uploads
per-region artifacts normalized to the legacy `profiles[].controls[]` schema so
they drop into the existing `hdf_to_oscal.py` pipeline.

Work required here is the join, not the pipeline:

- Emit `<pack>.evidence-tags.json` in a shape the HDF enrichment can consume.
- Keep control ids identical across packs and the GOV producer.
- Confirm pack rule names survive into the fetched HDF as stable identifiers —
  **re-splitting packs later renames rules and breaks evidence continuity**, so
  this needs verifying before the first outward-facing report, not after.

---

## Cross-Repository Integration

| Repository | Dependency | Direction |
|---|---|---|
| **sparc** | Baseline-parameters API is the ODP schema of record (Low / Moderate / High) | sparc → aws-conformance-packs |
| **sparc-iac** | Reference conformance-pack deployment + recorder/delivery Terraform; evidence emit grant tracked as [sparc-iac#701](https://github.com/risk-sentinel/sparc-iac/issues/701) | sparc-iac → aws-conformance-packs |
| **aws-config** | Reusable workflow converting Config evaluations to HDF | aws-config → aws-conformance-packs |
| **dev-sec-ops-baseline** | Reusable secret-scan HDF emit workflow | dev-sec-ops-baseline → aws-conformance-packs |
| **stig-aws-ecr-baseline** | CI + branch-protection pattern to replicate (estate pilot) | pattern source |
| **sparc-validate** | Consumes HDF evidence into the OSCAL/ATO pipeline | aws-conformance-packs → sparc-validate |

---

## Critical path

```
Phase 0 (CI + ruleset)
  └─► Phase 1a (ODP schema from SPARC)      ← blocks every catalog
        └─► Phase 1b/1c (generator + emitters)
              ├─► Phase 2 #2 IAM            ← proves ODP density
              │     └─► #3 NET → #4 CRYPTO  ← CRYPTO proves Guard + S3 templates
              │           └─► #5 LOG → #6 VCM → #7 RPL
              ├─► Phase 1d (control-id normalizer)
              │     └─► Phase 3 #8 GOV
              └─► Phase 4 (inputs.yml + two-forge deploy)
                    └─► Phase 5 (evidence join)
```

Three things gate more than they look like they do:

1. **The ODP schema decision (1a).** Every catalog keys off it. Changing
   `param_id` vocabulary later rewrites every rule file.
2. **The pack split.** Settled in epic #1 and should stay settled — re-splitting
   renames rules and breaks historical evidence continuity.
3. **Guard in CRYPTO (#4).** It is where token substitution, the inline-template
   size cap, and the "Guard-bound ODPs cannot be tuned at deploy time" constraint
   all become real. Learning that in the largest pack instead would be expensive.

---

## Summary

The repo has its requirements written down and nothing built. The near-term
sequence is: **make the repo trustworthy (Phase 0), settle the ODP schema
against SPARC's API (1a), build the generator (1b–1d), then work the domain
issues in ODP-density order.** Portability is not a later phase to bolt on —
`inputs.yml`, the two-forge pipeline split, and "no defaults for consumer
environment values" are constraints on how Phases 1 and 2 are written.

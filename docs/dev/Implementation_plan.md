# AWS Conformance Packs — Implementation Plan

Structured, prioritized roadmap for `risk-sentinel/aws-conformance-packs`.

This repo generates **domain-split AWS Config conformance packs** for NIST SP
800-53 Rev 5 and FedRAMP 20x from one portable rule catalog plus a
per-organization ODP overlay. It is a *generator and a deployment pattern*, not a
profile: there are no InSpec controls here. Evidence leaves this repo as Config
rule evaluations, which `risk-sentinel/aws-config` converts to HDF.

**Last updated:** 2026-09-07 (**Repo is design-stage.** `README.md` specifies the
target system; none of it is built. Issues [#1](https://github.com/risk-sentinel/aws-conformance-packs/issues/1)–[#8](https://github.com/risk-sentinel/aws-conformance-packs/issues/8)
were created 2026-09-07 from `issues/*.md` via `scripts/create-issues.sh` and
carry the real per-domain requirements. The repo is **public**, has **no
`.github/` directory, no CI, and no branch ruleset** — verified 2026-09-07
against the GitHub API. Phase 0 closes that before any pack work starts, because
a generator that emits compliance artifacts from an unprotected, unscanned repo
produces evidence nobody should accept.)

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

---

## Status snapshot

> **Updated 2026-09-07.** Every row is verified against the repo and the GitHub
> API as of that date, not projected.

| Bucket | Current state |
|---|---|
| Tracking issues | **9 filed** — #1 epic, #2–#8 domains, **#9 Phase 0** (active) |
| Generator (`generate.py`) | **Not started** — does not exist |
| ODP catalog (`odp/catalog.yaml`) | **Not started** — schema settled: SPARC's parameter shape, as a local file |
| Rule catalogs (`rules/<domain>.yaml`) | **0 / 6** |
| Guard policies (`guard/`) | **Not started** |
| Overlays (`overlays/`) | **0** — `overlays/vanilla.yaml` is the first deliverable of Phase 1a |
| Repo CI | **0 workflows.** No `.github/` directory exists |
| Branch protection | **None.** No ruleset, no classic protection |
| Secret-scan fixture canary | **Absent** |
| GitLab pipeline | **Absent** |
| Deployment `inputs.yml` contract | **Not designed** |
| Reference pack available to mine | `sparc-iac` `AWS/ECS/modules/aws_config/` — 107 rules, awslabs NIST r5 pack trimmed for a Fargate boundary |
| Evidence path | `risk-sentinel/aws-config` reusable workflow already fetches Config evaluations → HDF. **No work needed here beyond calling it** |
| Highest-priority next work | **#9 Phase 0** — scanning + branch protection (in flight), then **Phase 1a** ODP catalog + vanilla overlay |

---

## Phase 0 — Repo trustworthiness ([#9](https://github.com/risk-sentinel/aws-conformance-packs/issues/9) — ACTIVE)

**Goal:** this repo meets the same bar as the 14 profile repos before it emits
anything anyone relies on. Nothing in Phase 1+ starts until the ruleset is on.

Approved by the owner 2026-09-07; tracked as #9 on branch
`feature/9_ci_branch_protection`.

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

### 1a — Copy the SPARC ODP schema (blocks everything else)

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

### 1b — Generator and validators

`generate.py` renders and validates. Non-zero exit on: out-of-range values,
undeclared ODP references, enum violations, port lists exceeding a rule's
capacity, unsubstituted Guard tokens, >130 rules/pack, >60 parameters/pack,
template size overrun.

Resolution precedence is **overlay → OSCAL `set-parameter` → catalog default**,
with the winning source recorded per value as `assigned_by` in the traceability
CSV. That provenance column is what an assessor asks for.

### 1c — Emitters

`<pack>.yaml`, `<pack>.traceability.csv`, `<pack>.evidence-tags.json`,
`<pack>.coverage.md`, and `<pack>.oscal-set-params.json` under `--emit-oscal`.
Evidence tags pair the control id with **the ODP value the check measured
against** — that pairing is the defensible part.

### 1d — Control-id normalization, shared

One function, used by the pack generator and the GOV producer both. If GOV emits
`AC-1` and a pack emits `ac-2`, the Heimdall rollup fragments (issue #8 calls
this out explicitly).

**Acceptance:** `generate.py --overlay overlays/example-agency.yaml` renders one
pack end-to-end and every listed failure mode exits non-zero in CI.

---

## Phase 2 — Domain packs

One issue per pack. **Work one pack per issue** (epic #1). Each domain issue
already carries its scope, candidate managed rules, ODP bindings, gotchas and
acceptance criteria — those are the requirements, not the README's estimate
table.

| Issue | Pack | Est. rules | ODPs | Why this order |
|---|---|---|---|---|
| [#2](https://github.com/risk-sentinel/aws-conformance-packs/issues/2) | **IAM** | 25–35 | 7 | Highest ODP density in the program — it exercises the catalog hardest and shakes out the schema first. Region-pinning for global resources is a pattern every later pack inherits |
| [#3](https://github.com/risk-sentinel/aws-conformance-packs/issues/3) | **NET** | 20–30 | 3 | Port-list capacity is the first real `constraint` test (>5 ports must move to Guard) |
| [#4](https://github.com/risk-sentinel/aws-conformance-packs/issues/4) | **CRYPTO** | 25–35 | 4 | **First Guard-heavy pack.** KMS rotation period and min-TLS have no managed-rule parameter, so this is where `CUSTOM_POLICY` token substitution and the S3-hosted-template threshold get proven |
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
| **sparc-iac** | Reference conformance-pack deployment + recorder/delivery Terraform | sparc-iac → aws-conformance-packs |
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

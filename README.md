# aws-conformance-packs

Domain-split AWS Config conformance packs for NIST SP 800-53 Rev 5 and FedRAMP
20x, generated from a portable rule catalog plus a per-organization ODP overlay.

One governance decision lives in one place. The rule catalogs carry no
organization values and no organization control names, so the same catalogs
serve any tenant — only the overlay changes.

## Why the packs are split by domain

A hard service quota, not a preference:

**Verified against AWS documentation on 2026-09-08**, not carried from memory.
Sources: the AWS Config *Service Limits* page, and the `PutConformancePack` /
`PutOrganizationConformancePack` API references. All six were correct.

| Limit | Value | Increasable | Source |
| --- | --- | --- | --- |
| Config rules per conformance pack | **130** | **No** | Service Limits |
| Config rules per **organization** conformance pack | **130** | **No** | Service Limits |
| `ConformancePackInputParameter` items per pack | **60** | **No** | API reference |
| Config rules per Region per account | **1000** | **No** | Service Limits |
| Conformance packs per account / per organization | **50 / 50** | **No** | Service Limits |
| Inline `TemplateBody` | **51,200 bytes** | — | API reference |
| `TemplateS3Uri` template | **300 KB** | — | API reference |

The Service Limits page says quotas "can be increased upon request" *unless noted
otherwise* — and every conformance-pack quota is explicitly marked **No**.

**The arithmetic that actually binds.** 50 packs × 130 rules is 6,500 and is
unreachable: rules in conformance packs count against the 1000-per-Region-per-account
limit, and AWS says so explicitly. So the real ceiling is about **seven full packs per
Region per account**, not fifty. Organization deployment counts against the *child*
accounts' limit too.

**Three operational facts the same reading surfaced**, each now enforced:

- In **organization mode only**, the delivery bucket name must be prefixed
  `awsconfigconforms`. The single-account API has no such rule, so this fails
  only when you switch modes.
- `ExcludedAccounts` is capped at 1000 entries and must match `\d{12}` exactly.
  A malformed id makes AWS reject the whole call, so the pack deploys to
  *nobody* rather than to everyone-but-that-account.
- A staged template **must not be in an archived storage class**. A lifecycle
  rule tiering the pack bucket to Glacier breaks the deploy with an error that
  does not mention storage class.

The 130-rule cap means a complete Rev 5 build is several packs no matter how the
work is organized. The 60-parameter cap is the ceiling on deploy-time ODP
tuning — past it, values are baked at generation time and a change requires
regenerate + redeploy rather than a stack parameter update.

## Layout

```
odp/catalog.yaml               ODP declarations: type, constraints, OSCAL param-id
rules/<domain>.yaml            rule -> ODP + control crosswalk, portable
guard/*.guard                  Guard policies where no managed rule exposes the knob
overlays/vanilla*.yaml         per-baseline reference values; copy, do not edit
gov/                           the non-Config evidence producer, and its artifacts
inputs.template.yml            deployment contract; copy to inputs.yml
generate.py                    renderer and validator
tools/                         generator, linters, preflight, evidence producers
tests/                         the test suite; every guard is negative-controlled
vendor/                        pinned upstream snapshots, each with PROVENANCE.md
  fedramp/                       FedRAMP machine-readable rules (KSI vocabulary)
  nist/                          derived NIST Rev 5 parameter index
  aws/                           managed-rule index from AWS's published packs
  aws-services/                  service availability and Region lists
scripts/                       deploy and issue-creation scripts
ci/gitlab/                     GitLab pipeline; .github/workflows/ for GitHub
out/                           generated packs and reports (git-ignored)
issues/                        domain issue bodies; see scripts/create-issues.sh
docs/dev/                      implementation plan, issue rules, dispositions
```

Everything under `vendor/` is **derived and pinned**, never hand-edited, and each
directory carries a `PROVENANCE.md` recording its source, version and digest. A
hand-edit there is how a parameter id that joins to nothing gets in.

## Generating a pack

```bash
pip install pyyaml
python3 generate.py --overlay overlays/vanilla.yaml --emit-oscal
```

Useful flags:

| Flag | Effect |
| --- | --- |
| `--baseline low\|moderate\|high` | override the overlay's own `baseline_level` |
| `--region <id>` | drop rules whose service does not exist there, recording why |
| `--inputs inputs.yml` | apply a boundary — rules for services you do not run are dropped, recording why |
| `--rules rules/iam.yaml` | render one domain instead of all six |
| `--set-parameters-from <f>` | drive values from an OSCAL resolved profile |
| `--emit-oscal` | also write the OSCAL `set-parameter` stub |

Per pack this emits:

| Artifact | Purpose |
| --- | --- |
| `<pack>.yaml` | the conformance pack template |
| `<pack>.traceability.csv` | rule ↔ control ↔ ODP, with `assigned_by` provenance |
| `<pack>.evidence-tags.json` | control ids **plus the ODP value each check measured against** |
| `<pack>.coverage.md` | coverage with its denominator stated, and every exclusion with its reason |
| `<pack>.oscal-set-params.json` | OSCAL `set-parameter` stub (with `--emit-oscal`) |

Values resolve **overlay → OSCAL `set-parameter` → catalog default**, and the
winning source is recorded per value in the traceability CSV. A catalog default
and an overlay value can be byte-identical; only that column distinguishes a
threshold somebody chose from one that merely rendered.

### The generator is also the validator

It fails rather than emitting a pack whose thresholds nobody chose. A wrong value
in a conformance pack does not crash — it deploys, evaluates, and reports a clean
result. Non-zero exit on:

- a value outside its declared constraint, from **any** source
- an undeclared ODP reference, or an `oscal_param_id` that is not a real parameter
  of its control
- a KSI that does not exist, or that claims none of the rule's own controls
- a managed rule identifier or parameter name AWS does not publish
- an unsubstituted `{{Guard}}` token — Guard does *not* error on a live
  placeholder; it evaluates the literal text
- more than 130 rules or 60 parameters per pack, or a template over the size limits

Exclusions are never silent. A rule dropped for a baseline, a Region or a
boundary is listed in that pack's `coverage.md` with **why** and **what it bound**.

## Deploying

```bash
cp inputs.template.yml inputs.yml     # then fill it in
python3 tools/validate_inputs.py      # refuses a file that would deploy wrong
python3 tools/preflight.py            # refuses a recorder that cannot evaluate
python3 generate.py --overlay overlays/vanilla.yaml
bash scripts/deploy-packs.sh
```

`inputs.yml` names the packs, accounts, Regions, buckets and overlay. **Nothing
that identifies your environment has a default.** A defaulted Region reads an
empty account and reports a clean result; a defaulted bucket files your evidence
under somebody else's label. Both are worse than a failed pipeline, because both
look like success.

Pipelines for both forges ship in the repo and are manual-only:
`.github/workflows/deploy.yml` and `ci/gitlab/deploy.yml`. Neither holds a role
or a credential — the OIDC token is minted as the caller, so a fork assumes
*your* role and nothing here needs a trust entry.

### The recorder preflight, and why it is not a Config rule

`tools/preflight.py` refuses to deploy when the AWS Config recorder is not
capturing what the selected packs need.

It cannot be a Config rule. A rule about the recorder, evaluated by the recorder,
is circular: if recording is off, the rule that would report that fact does not
run. So the assertion is made from outside, before anything deploys.

It asserts a recorder exists **and is recording**, captures the resource types
the selected packs declare, records global resources in exactly one Region with
the IAM pack pinned there, and has a delivery channel. It **refuses** rather than
warns — a warning is read once and scrolled past, and the pack stays deployed
either way.

### Two AWS behaviours the deploy respects

`put-conformance-pack` is **create-or-update**, so re-running updates in place
and evaluation history survives.

**Deleting a pack destroys its evaluation history.** Removing a pack from
`inputs.yml` therefore does *not* delete it — the orphan is reported and left
alone. Deletion is a deliberate manual act.

Templates over 51,200 bytes are staged to S3 automatically; smaller ones deploy
inline. The decision is made per pack from what actually rendered.

### Prerequisites, in order

1. Config recorder enabled and **recording** in every target Region
2. Global resource recording enabled in exactly one Region (IAM lives there)
3. Delivery channel and evidence bucket the service-linked role can write to
4. `AWSServiceRoleForConfigConforms` in member accounts, for organization mode

The preflight checks all four. It exists because a rule scoped to a resource type
the recorder is not capturing never evaluates — it reports `INSUFFICIENT_DATA`,
which most dashboards render as "not failing".

## What you get out of the gate

<!-- COVERAGE-TABLE:START -->

**157 rules across 6 packs, touching 70 distinct NIST SP 800-53 Rev 5 controls over 54 AWS resource types.**

What you get depends on what your boundary actually runs. This is keyed by
resource type for that reason — find the rows you have.

| If your boundary has | Rules | Controls touched | From packs |
| --- | ---: | ---: | --- |
| `AWS::::Account` | 10 | 24 | CRYPTO, IAM, LOG |
| `AWS::S3::Bucket` | 11 | 18 | CRYPTO, LOG, NET, RPL |
| `AWS::Redshift::Cluster` | 8 | 16 | CRYPTO, IAM, LOG, NET, RPL, VCM |
| `AWS::EC2::Instance` | 10 | 12 | IAM, NET, VCM |
| `AWS::IAM::User` | 10 | 11 | IAM |
| `AWS::RDS::DBInstance` | 9 | 11 | CRYPTO, IAM, LOG, NET, RPL |
| `AWS::ElasticLoadBalancingV2::LoadBalancer` | 5 | 11 | LOG, NET, RPL |
| `AWS::CloudTrail::Trail` | 4 | 11 | LOG |
| `AWS::EC2::VPC` | 2 | 9 | LOG, NET |
| `AWS::OpenSearch::Domain` | 5 | 8 | CRYPTO, LOG, NET |
| `AWS::EC2::Volume` | 4 | 8 | CRYPTO, NET, RPL, VCM |
| `AWS::Elasticsearch::Domain` | 4 | 8 | CRYPTO, LOG, NET |
| `AWS::ApiGateway::Stage` | 4 | 7 | CRYPTO, LOG, NET |
| `AWS::DynamoDB::Table` | 5 | 6 | CRYPTO, RPL |
| `AWS::ElasticLoadBalancing::LoadBalancer` | 3 | 6 | CRYPTO, NET, RPL |
| `AWS::Lambda::Function` | 3 | 6 | NET, RPL, VCM |
| `AWS::SecretsManager::Secret` | 5 | 5 | CRYPTO, IAM |
| `AWS::Backup::RecoveryPoint` | 2 | 4 | RPL |
| `AWS::ECR::Repository` | 2 | 4 | VCM |
| `AWS::ECS::TaskDefinition` | 2 | 4 | VCM |
| `AWS::Logs::LogGroup` | 2 | 4 | LOG |
| `AWS::SageMaker::NotebookInstance` | 2 | 4 | CRYPTO, NET |
| `AWS::CloudWatch::Alarm` | 1 | 4 | LOG |
| `AWS::EC2::SecurityGroup` | 4 | 3 | NET |
| `AWS::IAM::Policy` | 3 | 3 | IAM |
| _…and 29 further resource types_ | | | |

**Read the middle column carefully.** It counts distinct controls the rules
for that resource type *crosswalk to* — not controls *satisfied*. Most of
those crosswalks are `supporting`, and each pack's generated
`coverage.md` says which are which and what each rule cannot see.

**The column does not sum.** Controls overlap heavily between resource types;
adding it up double-counts badly.

**A rule with no in-scope resources reports `INSUFFICIENT_DATA`**, which most
dashboards render as "not failing". Rows you do not have are not silently
green — they are silently absent. The recorder preflight refuses to deploy a
pack whose resource types are not being recorded, for exactly this reason.

<!-- COVERAGE-TABLE:END -->

Generated by `tools/coverage_report.py`; CI fails if it drifts from the
catalogs, because a hand-maintained coverage claim is stale the day after it is
written.

## Pack registry

<!-- PACK-REGISTRY:START -->

| Pack | Rules | Controls touched | ODP-bound params | 20x indicators | Scope |
| --- | ---: | ---: | ---: | ---: | --- |
| **CRYPTO** | 31 | 11 | 4 | 3 | regional |
| **IAM** | 25 | 13 | 9 | 4 | global |
| **LOG** | 25 | 23 | 9 | 6 | regional |
| **NET** | 34 | 14 | 3 | 5 | regional |
| **RPL** | 25 | 6 | 4 | 2 | regional |
| **VCM** | 17 | 11 | 4 | 8 | regional |
| **GOV** | **0** | — | 7 | — | non-Config producer |

**157 Config rules across 6 deployable packs.** Every pack is under the hard 130-rule cap; all of them together are 157 of the 1000-per-Region-per-account ceiling.

GOV emits **zero Config rules by design** — roughly 120 Moderate controls have no
resource-configuration signal, and it evidences those against policy artifacts
instead. See `gov/README.md`.

Controls-touched **overlaps between packs and does not sum to a baseline**. It
counts controls a pack's rules crosswalk to, not controls satisfied — each pack's
generated `coverage.md` says which are `full`, `partial` or `supporting`, and what
each rule cannot see.

<!-- PACK-REGISTRY:END -->

Generated by `tools/coverage_report.py`; CI fails if it drifts. This table shipped
as planning **estimates** and stayed that way after the packs were built — it
claimed RPL was 12–18 rules when it is 25. An estimate left in place after the
thing exists is not an estimate any more.

### Reading these numbers honestly

**The Config-visible surface is a minority of a Moderate baseline.** GOV holds
about 120 controls with no resource-configuration signal at all — the `-1` policy
controls, training, personnel, planning, acquisition. Those are not a gap to close
with more Config rules.

**Controls-touched has a misleading denominator by default.** It counts controls
the catalogs reference, not the size of the baseline. Diff the catalogs against
your tailored profile before reporting anything outward.

**`INSUFFICIENT_DATA` is not compliance.** A rule with no in-scope resources
reports insufficient data, which most dashboards render as "not failing". The
recorder preflight refuses to deploy for exactly this reason.

**FedRAMP 20x indicator ids come from a pinned snapshot** in `vendor/fedramp/`,
version-stamped into every evidence file. 20x changes until High locks around
2027-02; `tools/sync_fedramp.py --check` runs weekly so drift is a failing job
rather than a question from an assessor.

## Working the issues

Domain issue bodies live in `issues/`. To create them with labels:

```bash
DRY_RUN=1 ./scripts/create-issues.sh                    # preview
REPO=clem-field/aws-conformance-packs ./scripts/create-issues.sh
```

The script creates the label set first, skips issues whose titles are already
open, and reads title/labels from each file's front matter.

Each domain issue carries its scope, candidate managed rules, ODP bindings, the
domain-specific gotchas found during research, and acceptance criteria. Work one
pack per issue; the epic tracks cross-cutting constraints.

## Contributing a rule

1. **Add the ODP to `odp/catalog.yaml`** if the knob is new. Key it by our name and
   join to OSCAL — several ODPs may share one `oscal_param_id`, which is the normal
   shape in IA and AC. The `oscal_param_id` must be a real parameter of its control:
   `ac-6` publishes none at all, and a well-formed id that refers to nothing joins to
   nothing while looking correct.
2. **Give it a constraint.** A bad value must fail the build rather than deploy. An
   integer needs `min` and `max`; a list needs `max_items`, and an `item_pattern`
   where the shape matters — AWS silently *ignores* a malformed `amisByTagKeyAndValue`
   entry, so the allow-list ends up smaller than it reads.
3. **Add the rule to the domain catalog** with `controls`, `coverage`, `resource_types`
   and its bindings. `partial` or `supporting` without a `coverage_note` is a build
   failure: an unexplained partial is indistinguishable from an overstated `full`.
4. **Say what the rule cannot see**, in the note. It renders into the deployed
   `Description`, which is the only field that travels — conformance-pack rules do not
   support tags, so an operator reading the Config console sees only that.
5. **Map the resource type** in `vendor/aws-services/resource-type-map.yaml`.
   Explicitly: a naive string match resolves `AWS::RDS::DBCluster` to **DocDB**, since
   DocumentDB shares the `rds` ARN namespace, and a wrong service means a wrong Region
   scope.
6. **If no managed rule exposes the knob**, either write a Guard policy in `guard/`
   with `{{Token}}` placeholders — remembering `CUSTOM_POLICY` rules take no
   `InputParameters`, so the value bakes at generation time and changing it means
   regenerate + redeploy — or declare the ODP `evidence_only` **with a reason**. Never
   let an unenforceable ODP look like a control.
7. **Regenerate and run the suite.** `python3 generate.py --overlay overlays/vanilla.yaml`,
   `python3 tools/lint_packs.py`, `python3 -m pytest tests/ -q`.

### The rule this repository is built around

**A guard that has never been shown to fail is not a guard.** Every check here was
negative-controlled — shown to reject the specific defect it exists to catch — before
it was trusted. Several caught real errors in the same change that introduced them,
including three invented OSCAL parameter ids and six mis-assigned FedRAMP indicators.

If you add a check, add the test that proves it fires.

## License

Apache-2.0

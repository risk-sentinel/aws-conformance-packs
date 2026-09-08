# aws-conformance-packs

Domain-split AWS Config conformance packs for NIST SP 800-53 Rev 5 and FedRAMP
20x, generated from a portable rule catalog plus a per-organization ODP overlay.

One governance decision lives in one place. The rule catalogs carry no
organization values and no organization control names, so the same catalogs
serve any tenant — only the overlay changes.

## Why the packs are split by domain

A hard service quota, not a preference:

| Limit | Value | Increasable |
| --- | --- | --- |
| Config rules per conformance pack | **130** | No |
| `ConformancePackInputParameter` items per pack | **60** | No |
| Config rules per Region per account | 1000 | No |
| Conformance packs per account / per organization | 50 / 50 | No |
| Inline template body | 51,200 bytes | — |
| Template from S3 | 300 KB | — |

The 130-rule cap means a complete Rev 5 build is several packs no matter how the
work is organized. The 60-parameter cap is the ceiling on deploy-time ODP
tuning — past it, values are baked at generation time and a change requires
regenerate + redeploy rather than a stack parameter update.

## Layout

```
odp/catalog.yaml              ODP declarations: type, default, constraints, OSCAL param-id
rules/<domain>.yaml           rule → ODP + control crosswalk, portable
guard/*.guard                 custom policies where managed rules expose no knob
overlays/<org>.yaml           per-org ODP values + control vocabulary aliases
oscal/                        resolved profiles for --set-parameters-from
generate.py                   renderer and validator
out/                          generated packs and reports (git-ignored)
issues/                       domain issue bodies; see scripts/create-issues.sh
```

## Generating a pack

```bash
pip install pyyaml
python3 generate.py --overlay overlays/example-agency.yaml --emit-oscal
```

Per framework this emits:

| Artifact | Purpose |
| --- | --- |
| `<pack>.yaml` | the conformance pack template |
| `<pack>.traceability.csv` | rule ↔ control ↔ ODP, with `assigned_by` provenance |
| `<pack>.evidence-tags.json` | HDF enrichment payload: control ids + the ODP value each check measured against |
| `<pack>.coverage.md` | automated vs documented coverage, with the denominator stated |
| `<pack>.oscal-set-params.json` | OSCAL `set-parameter` stub (with `--emit-oscal`) |

Values resolve **overlay → OSCAL `set-parameter` → catalog default**, and the
winning source is recorded per value in the traceability CSV. To drive the build
from a tailored profile instead of a hand-written overlay:

```bash
python3 generate.py --set-parameters-from oscal/agency-moderate-resolved.json
```

Generation fails rather than deploying a wrong threshold. Out-of-range values,
undeclared ODP references, enum violations, port lists exceeding a rule's
capacity, and unsubstituted Guard tokens all exit non-zero.

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

## Pack registry and estimated coverage

**These were planning estimates and are now measurements.** All six packs are
built. Rule counts below are what actually renders; the controls-touched columns
still overlap between packs and still do not sum to a baseline.

| Pack | Domain | 800-53r5 families | Controls touched (Mod) | Est. rules | Est. ODP params | 20x KSIs | Automated share |
| --- | --- | --- | --- | --- | --- | --- | --- |
| IAM | Identity & access | AC-2/3/5/6/17, IA-2/4/5/7/8 | ~35 | 25–35 | 7 | KSI-IAM-01…06 | high |
| NET | Network & boundary | SC-7(+), AC-4, AC-17, SC-5 | ~25 | 20–30 | 3 | KSI-CNA-01…07 | high |
| CRYPTO | Cryptography & data | SC-8/12/13/28, MP-5, SI-7 | ~20 | 25–35 | 4 | KSI-SVC-02/03/05/06 | high |
| LOG | Logging & audit | AU-2/3/4/6/9/11/12, SI-4, CA-7 | ~30 | 30–40 | 3 | KSI-MLA-01/02/06, CMT-01 | medium-high |
| VCM | Vuln & config mgmt | CM-2/3/6/7/8, SI-2, RA-5 | ~35 | 25–35 | 3 | KSI-SVC-01/07, MLA-03/04/05, CMT-02/03 | medium |
| RPL | Resilience & recovery | CP-9/10, SC-5, SI-13 | ~15 | 12–18 | 3 | KSI-RPL-01…04, CNA-06 | medium |
| GOV | Governance & policy | all `-1`, AT, PS, PL, PM, SA, SR | ~120 | **0** | 7 | KSI-PIY, CED, INR, TPR, CMT-04/05 | none via Config |

Totals: roughly 137–193 Config rules across six deployable packs, comfortably
under the 1000-per-Region limit and with every pack under the 130 cap.

### Reading these numbers honestly

**The Config-visible surface is roughly 40% of a Moderate baseline.** GOV holds
about 120 controls with no resource-configuration signal at all — the `-1` policy
controls, training, personnel, planning, acquisition. Those are not a gap to be
closed with more Config rules; they need a different evidence producer, which is
what the GOV issue specifies.

**Coverage percentages have a misleading denominator by default.** A generated
coverage report counts controls the catalog already references, not the size of
the baseline. A pack reporting 95% means the controls it models are automated,
not that the baseline is covered. Diff the catalog against the full tailored
profile before reporting anything outward.

**`INSUFFICIENT_DATA` is not compliance.** A rule with no in-scope resources
reports insufficient data, which most dashboards render as "not failing." Every
pack carries a recorder-prerequisite check for exactly this reason.

**FedRAMP 20x KSI ids track the published Phase One Low set.** Moderate adds
indicators not modeled here (KSI-CNA-08, KSI-MLA-08, KSI-SVC-08/09/10) and later
phases add themes. Re-sync against fedramp.gov before assessment use.

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

1. Add the ODP to `odp/catalog.yaml` if the knob is new — with constraints, so a
   bad value fails the build instead of deploying.
2. Add the rule to the domain catalog with `controls`, `coverage`, and parameter
   bindings. Be accurate on `coverage`; the traceability report is only worth
   reading if that field is honest.
3. If the managed rule exposes no parameter for the ODP, either write a Guard
   policy in `guard/` with `{{TokenName}}` placeholders, or mark the ODP
   `evidence_only_odps` so it appears in evidence and is visibly not enforced.
   Never let an unenforceable ODP look like a control.
4. Regenerate. Unsubstituted tokens, unknown ODP references, and cap violations
   fail loudly.

## License

Apache-2.0

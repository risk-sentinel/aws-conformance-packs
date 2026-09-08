# AWS managed-rule index — derived, vendored

A verification source, not a template to deploy.

| | |
| --- | --- |
| Upstream | https://github.com/awslabs/aws-config-rules |
| Path | `aws-config-conformance-packs/` |
| Upstream commit | `ee31337c020176eea9eb501cc54c05354a54d066` |
| Packs read | **123** |
| Rules indexed | **503** |
| Derived by | `tools/build_aws_index.py` |
| Derived on | 2026-09-08 |
| SHA-256 | `d4a201c400193ac120c2448558d5dab1fb9c75afd2528f2c1171c235cf0b5014` |

## Why an index of ALL packs, not one pack

This started as a copy of AWS's NIST 800-53 Rev 5 pack alone. That left **24 of
our 157 rules unverifiable** purely because that one pack does not happen to
carry them — not because anything was wrong with them.

Searching all 123 packs found 22 of the 24, **every identifier matching and every
parameter name confirmed**, including the ones carrying ODPs
(`requiredFrequencyValue`/`Unit`, `MinRetentionTime`, `daysHighSev`,
`AuthorizedVpcIds`, `runtime`, `amisByTagKeyAndValue`). Verification went from
**133/157 (84%) to 155/157 (98%)**.

A derived index rather than 123 raw packs: the packs total several megabytes and
nobody diffs that in review. The index carries rule name, identifier, parameter
names and the packs each was seen in — small, greppable, and rebuilt by a tool
that names its source.

## What "verified" does and does not mean

It confirms an identifier and parameter **names** exist as AWS publishes them.

It says **nothing** about whether the rule evaluates what our crosswalk claims.
That is what live evaluation is for, and no amount of index-checking substitutes
for it.

## Two upstream inconsistencies this surfaced

AWS's own packs disagree about two rules:

| rule | identifiers seen |
| --- | --- |
| `autoscaling-multiple-az` | `AUTOSCALING_MULTIPLE_AZ` (3 packs) vs `AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED` (1) — an upstream typo |
| `s3-bucket-cross-region-replication-enabled` | `S3_BUCKET_CROSS_REGION_REPLICATION_ENABLED` vs `S3_BUCKET_REPLICATION_ENABLED`, 1 each |

The index records **every** identifier seen and uses the majority, so a rule is
never rejected because one upstream pack has a typo — and the disagreement is
visible on the entry rather than resolved out of sight.

## Two things the build refuses

- **A partial index.** If any pack fails to read, the tool exits rather than
  writing a smaller index that would silently narrow verification while looking
  like a clean run. One pack uses CloudFormation short-form intrinsics
  (`!Not`, `!Equals`) that `yaml.safe_load` rejects outright; the loader
  tolerates them rather than losing the pack.
- **A non-string `SourceIdentifier`.** Those are intrinsics or `CUSTOM_POLICY`
  rules — not managed-rule identifiers, and coercing one to a string would make
  it look authoritative.

## Refreshing

```bash
python3 tools/build_aws_index.py     # rebuild from upstream
python3 tools/sync_aws_pack.py --check
```

Drift is worth watching in the unusual direction too: a rule **added** upstream
may mean an existing `not_in_aws_pack` declaration is stale and the rule can now
be verified properly.

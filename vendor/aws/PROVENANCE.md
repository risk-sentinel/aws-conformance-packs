# AWS Operational Best Practices for NIST 800-53 Rev 5 — vendored

AWS's own published conformance pack, vendored as a **verification source**, not
as a template to deploy.

| | |
| --- | --- |
| Source | https://github.com/awslabs/aws-config-rules |
| Path | `aws-config-conformance-packs/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml` |
| Upstream commit | `ee31337c020176eea9eb501cc54c05354a54d066` |
| Retrieved | 2026-09-08 |
| Rules | 130 |
| Parameters | 28 |
| SHA-256 | `a5a41d66ea28c3ef5915c8fa7933a795d6c4bafdb84ffdf10ef938eff4bf32e8` |

## What it is used for

A managed rule's `SourceIdentifier` and its parameter names are **asserted from
documentation** unless something checks them. A wrong identifier does not fail at
generation — it fails at `put-conformance-pack`, or worse it deploys and the rule
reports `INSUFFICIENT_DATA` forever, which dashboards render as "not failing".

This file is AWS's own mapping of managed rules to NIST 800-53 Rev 5, so it is
authoritative for both. The generator checks every managed rule in our catalogs
against it and refuses an identifier or parameter name it does not recognise,
unless the rule explicitly declares `not_in_aws_pack` with a reason.

## Why 130 rules matters

That is **exactly** the per-pack service cap. AWS ships this as one pack at the
limit, which independently confirms the premise this repository is built on: a
complete Rev 5 build cannot be one pack, so the split is a quota consequence
rather than a preference.

## What it is NOT

Not a rule catalog and not deployed. Our catalogs carry control crosswalks,
coverage honesty, ODP bindings and caveats that this file has none of. It is
consulted, never rendered.

Note also that it is a **superset in one direction and a subset in the other**:
58 of its rules are for services our domain issues do not name, and 25 of our
candidates do not appear in it at all — newer managed rules and Guard territory.
A rule absent from this file is therefore not necessarily wrong, which is why the
check has an explicit escape with a stated reason rather than being absolute.

## Refreshing

```bash
python3 tools/sync_aws_pack.py --check
```

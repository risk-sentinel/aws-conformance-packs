# AWS service availability — derived, vendored

| | |
| --- | --- |
| Upstream | https://github.com/awslabs/oscal-content-for-aws-services |
| Path | `component-definitions/` |
| Upstream commit | `4a1779ffb556c4ab8fb3dad94a19d4d198116803` |
| Services | **398** |
| Regions | **34** |
| Derived by | `tools/build_service_index.py` |
| Derived on | 2026-09-08 |
| SHA-256 | `17d4eadc22b78fc8dd8fb97e7a998dca02e8d9a752d5bd7a70a099e78e0d83aa` |

## What it carries, and why the two fields differ

`availability` is a **scope class** — `GLOBAL`, `REGIONAL`, `ZONAL`,
`SUBZONAL`. AWS publishes IAM and CloudFront as GLOBAL, which is why an IAM pack
must be pinned to the one Region recording global resources.

`regions` is the **actual availability list**. Bedrock exists in 15 Regions and
S3 in 34. No pack made that distinction before this index existed.

They answer different questions and are not interchangeable.

## What this replaced

`region_scope: global` in `rules/iam.yaml` was hand-asserted. AWS publishes the
same fact, so the generator now **derives** it and refuses a catalog that
declares `global` with no GLOBAL service in it. It immediately caught a real
inconsistency: `rules/net.yaml` declares `regional` while carrying
`AWS::CloudFront::Distribution`, which is GLOBAL.

## The resource-type join is explicit, and that is not fussiness

`vendor/aws-services/resource-type-map.yaml` maps each AWS Config resource type
to a service **by hand**. Deriving it from the type string produces silently
wrong answers:

    AWS::RDS::DBCluster  ->  DocDB

DocumentDB and Neptune share the `rds` ARN namespace. A wrong service means a
wrong availability class and a wrong Region list — so a pack scoped to Regions it
should not be, or excluded from Regions it should cover. Four cases here are
genuinely ambiguous and none is guessable: `AWS::RDS::*`,
`AWS::ApiGateway::Stage`, ELB v1 versus v2, and `AWS::SageMaker::*` (the
`SageMaker Runtime` entry publishes **no** Regions, so mapping to it would scope
every SageMaker rule out of everywhere).

`tools/lint_packs.py` fails when a resource type used by a rule has no entry.

## A deliberate asymmetry

A service publishing **no** Region list is treated as **available**, not
excluded. Absence of data is not evidence of absence, and excluding on it would
silently shrink a pack — the failure this repository is built to avoid.

## Refreshing

```bash
python3 tools/build_service_index.py
```

Refuses to write a partial index: an unreadable component definition is fatal,
because a shorter index would silently narrow Region scoping while looking clean.

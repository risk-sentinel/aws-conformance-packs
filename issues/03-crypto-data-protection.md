---
title: "Pack: Cryptography & Data Protection (CRYPTO)"
labels: pack, domain:crypto
---

## Scope

**800-53r5 families:** SC-8, SC-12, SC-13, SC-28, MP-5, SI-7 (partial)
**20x KSIs:** KSI-SVC-02, -03, -05, -06
**AWS services:** KMS, ACM, S3, EBS, RDS, EFS, DynamoDB, SNS, SQS, ELBv2
**Resource types:** `AWS::KMS::Key`, `AWS::ACM::Certificate`, `AWS::S3::Bucket`, `AWS::EC2::Volume`, `AWS::RDS::DBInstance`, `AWS::EFS::FileSystem`, `AWS::ElasticLoadBalancingV2::Listener`

**Estimated rules:** 25–35 · **Controls touched (Moderate):** ~20

## Candidate managed rules

`encrypted-volumes`, `ec2-ebs-encryption-by-default`,
`s3-bucket-server-side-encryption-enabled`, `s3-default-encryption-kms`,
`s3-bucket-ssl-requests-only`, `rds-storage-encrypted`,
`rds-snapshot-encrypted`, `efs-encrypted-check`,
`dynamodb-table-encrypted-kms`, `sns-encrypted-kms`, `sqs-queue-encrypted`,
`cmk-backing-key-rotation-enabled`, `kms-cmk-not-scheduled-for-deletion`,
`acm-certificate-expiration-check`, `elb-tls-https-listeners-only`,
`redshift-require-tls-ssl`, `elasticsearch-node-to-node-encryption-check`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Cert expiry warning window | sc-12 | `acm-certificate-expiration-check.daysToExpiration` |
| Key rotation period | sc-12 | Guard (`RotationPeriodInDays`) — no managed rule param |
| Minimum TLS version | sc-8.1 | Guard (`SslPolicy` allowlist) — no managed rule param |
| Approved KMS key ARNs | sc-13 | `s3-default-encryption-kms.kmsKeyArns` |

## Gotchas

- **`s3-bucket-server-side-encryption-enabled` is now near-vacuous.** SSE-S3 has
  been on by default for all buckets since 2023, so the rule passes universally
  and evidences almost nothing. If the control intends CMK-managed encryption,
  use `s3-default-encryption-kms` with an approved-key-ARN ODP instead. Carrying
  the old rule as SC-28 evidence is the kind of thing an assessor should catch.
- **`encrypted-volumes` evaluates attached volumes.** Unattached volumes holding
  data are outside its scope and will not show as non-compliant.
- **KMS rotation Guard rule will false-positive** on asymmetric keys, keys with
  imported material, and AWS-managed keys — none of which support automatic
  rotation. Scope the Guard filter to symmetric customer-managed keys with
  `KeyManager == 'CUSTOMER'` or the pack generates permanent noise.
- **`cmk-backing-key-rotation-enabled` is boolean only.** Rotation *period*
  enforcement requires Guard, and Guard values are baked at generation time, so
  changing the period ODP means regenerate + redeploy, not a parameter update.
- **TLS floor enforcement checks the ELB security policy name, not negotiated
  ciphers.** A policy allowlist is a proxy; keep coverage `partial`.
- **SC-8 in transit is only partly visible.** Config sees listener config on
  managed load balancers. East-west traffic between compute, and anything
  terminating TLS inside a container, is invisible. Do not claim SC-8 coverage
  on the strength of listener rules alone.

## Acceptance criteria

- [ ] SSE-S3 vacuity documented; CMK rule used where the control means CMK
- [ ] KMS Guard scoped to rotatable symmetric CMKs, verified against a test key
- [ ] TLS policy allowlist derived from the ODP, not hardcoded in the `.guard`
- [ ] Regenerate-on-change noted for all Guard-bound ODPs in this pack

---
title: "Pack: Resilience & Recovery (RPL)"
labels: pack, domain:rpl
---

## Scope

**800-53r5 families:** CP (9, 10), SC-5 (partial), SI-13
**20x KSIs:** KSI-RPL-01 … KSI-RPL-04; KSI-CNA-06
**AWS services:** AWS Backup, RDS, DynamoDB, EFS, S3, Auto Scaling, ELB
**Resource types:** `AWS::Backup::BackupPlan`, `::BackupSelection`, `::RecoveryPoint`, `AWS::RDS::DBInstance`, `AWS::DynamoDB::Table`, `AWS::AutoScaling::AutoScalingGroup`

**Estimated rules:** 12–18 · **Controls touched (Moderate):** ~15

## Candidate managed rules

`backup-plan-min-frequency-and-min-retention-check`,
`backup-recovery-point-minimum-retention-check`,
`backup-recovery-point-encrypted`, `backup-recovery-point-manual-deletion-disabled`,
`db-instance-backup-enabled`, `rds-instance-deletion-protection-enabled`,
`rds-multi-az-support`, `dynamodb-pitr-enabled`, `dynamodb-in-backup-plan`,
`ebs-in-backup-plan`, `efs-in-backup-plan`, `rds-in-backup-plan`,
`s3-bucket-versioning-enabled`, `s3-bucket-replication-enabled`,
`elb-cross-zone-load-balancing-enabled`, `autoscaling-multiple-az`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Minimum backup retention | cp-9 | `backup-plan-min-frequency-and-min-retention-check.requiredRetentionDays` |
| Minimum backup frequency | cp-9 | `.requiredFrequencyValue` + `.requiredFrequencyUnit` |
| Recovery point retention | cp-9 | `backup-recovery-point-minimum-retention-check.requiredRetentionDays` |
| RPO / RTO | cp-10 | **no enforcement point** — attestation |

## Gotchas

- **`backup-plan-min-frequency-and-min-retention-check` evaluates the plan, not
  its coverage.** A perfectly compliant plan protecting zero resources passes.
  The `*-in-backup-plan` rules are the ones that matter for coverage — include
  them or the pack certifies an empty promise.
- **`requiredFrequencyUnit` is a picky string** (`hours` / `days`). A frequency
  ODP expressed in hours must render both the value and the matching unit; a
  mismatch silently changes the meaning of the check by a factor of 24. Validate
  the pair together in the generator, not independently.
- **RTO/RPO (KSI-RPL-01) have no configuration signal.** Backup frequency is a
  proxy for RPO at best and says nothing about RTO. Model as attestation and
  resist the temptation to map frequency rules to RPL-01.
- **KSI-RPL-04 (regularly test recovery) is a process artifact.** Restore-test
  evidence comes from the runbook/CI producer, not Config.
- **`s3-bucket-versioning-enabled` is not a backup.** It appears in many
  published crosswalks under CP-9; mark coverage `supporting` at most.

## Acceptance criteria

- [ ] `*-in-backup-plan` rules included alongside the plan-shape rules
- [ ] Frequency value + unit validated as a pair at generation time
- [ ] RPL-01 and RPL-04 modeled as attestation with the reason recorded
- [ ] Versioning rule marked `supporting`, not `full`, for CP-9

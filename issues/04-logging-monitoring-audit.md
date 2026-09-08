---
title: "Pack: Logging, Monitoring & Audit (LOG)"
labels: pack, domain:log
---

## Scope

**800-53r5 families:** AU (2, 3, 4, 6, 9, 11, 12), SI-4, CA-7
**20x KSIs:** KSI-MLA-01, -02, -06; KSI-CMT-01
**AWS services:** CloudTrail, CloudWatch Logs, Config, GuardDuty, Security Hub, VPC flow logs, S3 access logging
**Resource types:** `AWS::CloudTrail::Trail`, `AWS::Logs::LogGroup`, `AWS::S3::Bucket`, `AWS::Config::ConfigurationRecorder`

**Estimated rules:** 30–40 · **Controls touched (Moderate):** ~30

## Candidate managed rules

`cloud-trail-enabled`, `multi-region-cloudtrail-enabled`,
`cloudtrail-security-trail-enabled`, `cloud-trail-log-file-validation-enabled`,
`cloud-trail-encryption-enabled`, `cloud-trail-cloud-watch-logs-enabled`,
`cloudtrail-s3-dataevents-enabled`, `s3-bucket-logging-enabled`,
`cw-loggroup-retention-period-check`, `cloudwatch-log-group-encrypted`,
`guardduty-enabled-centralized`, `guardduty-non-archived-findings`,
`securityhub-enabled`, `vpc-flow-logs-enabled`, `elb-logging-enabled`,
`rds-logging-enabled`, `redshift-cluster-configuration-check`

**Reconciled from AWS's published pack (2026-09-08).** These are rules AWS's own
NIST 800-53 Rev 5 conformance pack maps to this domain that the original research
for this issue did not name. None is dropped for being irrelevant to a particular
boundary — that judgement belongs to the boundary, not the catalog, and is made at
pack-composition time with its reason recorded (see #20). Assignment rationale in
`docs/dev/rule-reconciliation.yaml`.

`api-gw-execution-logging-enabled`, `beanstalk-enhanced-health-reporting-enabled`, `cloudtrail-enabled`, `cloudwatch-alarm-action-check`, `elasticsearch-logs-to-cloudwatch`, `opensearch-logs-to-cloudwatch`, `rds-enhanced-monitoring-enabled`, `s3-event-notifications-enabled`, `wafv2-logging-enabled`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Audit record retention | au-11 | `cw-loggroup-retention-period-check.MinRetentionTime` |
| Finding age threshold | si-4 | `guardduty-non-archived-findings.daysLowSev/MediumSev/HighSev` |
| Log destination bucket | au-9 | `s3-bucket-logging-enabled.targetBucket` |

## Gotchas

- **`cw-loggroup-retention-period-check` evaluates every log group in the
  account**, including AWS-service-created ones. Lambda log groups default to
  never-expire, which reads as compliant against a minimum-retention check, while
  service log groups created with short defaults fail immediately. Expect a large
  day-one non-compliance count that is mostly not yours. Decide up front whether
  to scope by tag or accept the noise — do not quietly widen the ODP to make the
  number look better.
- **CloudTrail rules are account-level periodic evaluations.** They produce one
  result per account, not per trail resource, which distorts per-resource
  compliance percentages in aggregated views.
- **This is the expensive pack.** Config charges per rule evaluation and per
  configuration item; log groups and buckets churn. Model cost on one account
  before org rollout.
- **"Regularly review and audit logs" (KSI-MLA-02) is not the same as retaining
  them.** Retention rules evidence storage, not review. The review activity is a
  process artifact belonging to the GOV pack. Mapping retention rules to
  KSI-MLA-02 alone is the weakest link in the 20x crosswalk.
- **`securityhub-enabled` / `guardduty-enabled-centralized` check enablement, not
  that anything acts on findings.** SI-4 coverage stays `partial`.
- **Recorder self-reference.** A rule about the Config recorder evaluated by
  Config is circular; if recording is off, the rule reporting that fact does not
  run. Assert recorder state out of band (CLI check in CI), not from inside the
  pack.

## Acceptance criteria

- [ ] Log-group scoping decision documented (tag-scoped vs account-wide)
- [ ] Cost estimate for one representative account attached to this issue
- [ ] KSI-MLA-02 marked `partial` with the review-activity gap named
- [ ] Out-of-band recorder assertion in CI rather than as a pack rule

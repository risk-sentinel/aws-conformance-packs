---
title: "Pack: Vulnerability & Configuration Management (VCM)"
labels: pack, domain:vcm
---

## Scope

**800-53r5 families:** CM (2, 3, 6, 7, 8), SI-2, RA-5
**20x KSIs:** KSI-SVC-01, -07; KSI-MLA-03, -04, -05; KSI-CMT-02, -03
**AWS services:** SSM, Inspector, ECR, EC2, Lambda, ECS
**Resource types:** `AWS::SSM::PatchCompliance`, `::AssociationCompliance`, `AWS::EC2::Instance`, `AWS::ECR::Repository`, `AWS::Lambda::Function`

**Estimated rules:** 25–35 · **Controls touched (Moderate):** ~35

## Candidate managed rules

`ec2-managedinstance-patch-compliance-status-check`,
`ec2-managedinstance-association-compliance-status-check`,
`ec2-instance-managed-by-systems-manager`, `ec2-stopped-instance`,
`ec2-imdsv2-check`, `approved-amis-by-id`, `approved-amis-by-tag`,
`ecr-private-image-scanning-enabled`, `ecr-private-tag-immutability-enabled`,
`lambda-function-settings-check`, `ec2-instance-detailed-monitoring-enabled`,
`ec2-volume-inuse-check`, `restricted-common-ports` (shared with NET)

**Reconciled from AWS's published pack (2026-09-08).** These are rules AWS's own
NIST 800-53 Rev 5 conformance pack maps to this domain that the original research
for this issue did not name. None is dropped for being irrelevant to a particular
boundary — that judgement belongs to the boundary, not the catalog, and is made at
pack-composition time with its reason recorded (see #20). Assignment rationale in
`docs/dev/rule-reconciliation.yaml`.

`ebs-optimized-instance`, `ecs-containers-readonly-access`, `ecs-task-definition-user-for-host-mode-check`, `elastic-beanstalk-managed-updates-enabled`, `redshift-cluster-maintenancesettings-check`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Approved AMI ids / tag | cm-2 | `approved-amis-by-id.amiIds` / `approved-amis-by-tag.amisByTagKeyAndValue` |
| Stopped-instance threshold | cm-2 | `ec2-stopped-instance.AllowedDays` |
| Lambda runtime allowlist | cm-7 | `lambda-function-settings-check.runtime` |
| Critical patch window | si-2 | **evidence-only** — no managed rule parameter exists |

## Gotchas

- **Unmanaged instances vanish rather than fail.** `ec2-managedinstance-*` rules
  evaluate SSM-managed instances. An instance that never registered with SSM is
  simply absent from the results — not non-compliant. This is the worst
  false-assurance in the whole program: the least-managed hosts are the ones
  missing from the evidence. Pair with
  `ec2-instance-managed-by-systems-manager` and treat any gap between instance
  count and managed-instance count as a finding in its own right.
- **The patch rule reports SSM's compliance verdict, not your remediation
  window.** The SI-2 window ODP cannot be enforced here. Carry it as
  `evidence_only_odps` so it appears in evidence tags and is visibly *not*
  enforced, or drop it — do not let it look like a control.
- **`approved-amis-by-id` requires maintaining an AMI id list**, which goes stale
  every image build. Prefer the tag-based variant or the ODP becomes a
  maintenance treadmill that quietly gets ignored.
- **CM-3 (change control) is process, not configuration.** CloudTrail evidences
  that changes happened, never that they were authorized. KSI-CMT-03 (automated
  testing before deployment) is a pipeline property — evidence belongs in the
  CI/CD producer, not this pack.
- **RA-5 / KSI-MLA-04 (authenticated vulnerability scanning)** is Inspector's
  job. Inspector findings are not Config rule results; route through Security
  Hub → HDF instead of trying to force a Config rule.

## Acceptance criteria

- [ ] Instance-count vs managed-instance-count gap check implemented
- [ ] Patch-window ODP marked evidence-only in the catalog and in evidence tags
- [ ] Tag-based AMI approval preferred over id lists, with rationale recorded
- [ ] KSI-MLA-04 and KSI-CMT-03 routed to non-Config producers, documented

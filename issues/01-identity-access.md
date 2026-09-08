---
title: "Pack: Identity & Access (IAM)"
labels: pack, domain:iam
---

## Scope

**800-53r5 families:** AC (2, 3, 5, 6, 17), IA (2, 4, 5, 7, 8), partial AU-9
**20x KSIs:** KSI-IAM-AAM, KSI-IAM-APM, KSI-IAM-ELP, KSI-IAM-JIT
**AWS services:** IAM, Organizations, IAM Identity Center, STS, Secrets Manager
**Resource types:** `AWS::IAM::User`, `::Role`, `::Policy`, `::Group`, `AWS::SecretsManager::Secret`

**Estimated rules:** 25–35 · **Controls touched (Moderate):** ~35

## Candidate managed rules

`iam-password-policy`, `iam-user-mfa-enabled`, `mfa-enabled-for-iam-console-access`,
`root-account-mfa-enabled`, `root-account-hardware-mfa-enabled`,
`iam-user-unused-credentials-check`, `access-keys-rotated`,
`iam-policy-no-statements-with-admin-access`,
`iam-policy-no-statements-with-full-access`, `iam-user-no-policies-check`,
`iam-group-has-users-check`, `iam-root-access-key-check`,
`iam-customer-policy-blocked-kms-actions`, `iam-inline-policy-blocked-kms-actions`,
`secretsmanager-rotation-enabled-check`, `secretsmanager-scheduled-rotation-success-check`,
`secretsmanager-secret-periodic-rotation`, `secretsmanager-secret-unused`

**Reconciled from AWS's published pack (2026-09-08).** These are rules AWS's own
NIST 800-53 Rev 5 conformance pack maps to this domain that the original research
for this issue did not name. None is dropped for being irrelevant to a particular
boundary — that judgement belongs to the boundary, not the catalog, and is made at
pack-composition time with its reason recorded (see #20). Assignment rationale in
`docs/dev/rule-reconciliation.yaml`.

`account-part-of-organizations`, `codebuild-project-envvar-awscred-check`, `ec2-instance-profile-attached`, `iam-no-inline-policy-check`, `iam-user-group-membership-check`, `rds-instance-default-admin-check`, `redshift-default-admin-check`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Minimum password length | ia-5.1 | `iam-password-policy.MinimumPasswordLength` |
| Maximum password age | ia-5.1 | `iam-password-policy.MaxPasswordAge` |
| Password reuse generations | ia-5.1 | `iam-password-policy.PasswordReusePrevention` |
| Static key max age | ia-5.1 | `access-keys-rotated.maxAccessKeyAge` |
| Inactivity disable threshold | ac-2.3 | `iam-user-unused-credentials-check.maxCredentialUsageAge` |
| Secret rotation period | ia-5 | `secretsmanager-secret-periodic-rotation.maxDaysSinceRotation` |
| Unused secret threshold | ac-2.3 | `secretsmanager-secret-unused.unusedForDays` |

~7 bindable ODPs — the highest density of any domain.

## Gotchas

- **`iam-password-policy` evaluates the account-level IAM password policy only.**
  If the org authenticates via IAM Identity Center or an external IdP, this rule
  passes vacuously while the real password policy sits somewhere Config cannot
  see. The most common false-assurance in this domain — put the caveat in the
  rendered rule description, not just here.
- **Global resource recording.** IAM is global and recorded in one Region. Pin
  the pack Region-scoped or every other Region reports `INSUFFICIENT_DATA`.
- **Credential-report latency.** `iam-user-unused-credentials-check` and
  `access-keys-rotated` are periodic and derive from the IAM credential report,
  which regenerates roughly every four hours. Evidence lags reality.
- **Root-account rules evaluate once per account**, not per resource. In
  aggregated views this is a single finding for a whole account.
- **`iam-policy-no-statements-with-admin-access` covers customer-managed policies
  only.** `AdministratorAccess` attached directly to a principal is out of scope.
  Least-privilege claims resting on this rule alone are overstated — Guard rule
  needed if KSI-IAM-ELP is load-bearing.
- **MFA rules cannot see phishing resistance.** KSI-IAM-APM asks specifically for
  phishing-resistant methods; the managed rules only see that MFA exists. Mark
  coverage `partial` and say why.

## Acceptance criteria

- [ ] Catalog entry per rule with `controls`, `coverage`, ODP bindings
- [ ] Both crosswalks populated (800-53r5 + KSI)
- [ ] Identity Center caveat in the rendered rule description
- [ ] Pack pinned to the global-resource Region, documented in README
- [ ] Recorder prerequisite check for IAM resource types

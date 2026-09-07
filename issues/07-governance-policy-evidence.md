---
title: "Pack: Governance & Policy Evidence (GOV) — non-Config producer"
labels: pack, domain:gov, needs-design
---

## Scope

This one produces **no AWS Config rules**. It exists because roughly 120 of the
~287 controls in a Moderate baseline have no resource-configuration signal at
all, and pretending otherwise is what makes coverage numbers dishonest.

**800-53r5 families:** every `-1` policy/procedure control (AC-1, AU-1, CM-1,
CP-1, IA-1, IR-1, MA-1, MP-1, PE-1, PL-1, PS-1, RA-1, SA-1, SC-1, SI-1, SR-1),
plus AT, PS, PL, PM, SA, SR in bulk
**20x KSIs:** KSI-PIY-01…07, KSI-CED-01/02, KSI-INR-01…03, KSI-TPR-01…04,
KSI-CMT-04/05, KSI-RPL-01/04, KSI-MLA-02 (review activity)

**Controls touched (Moderate):** ~120 · **Config rules:** 0

## Approach

Treat policy artifacts as checkable objects in a repository. The checks are
mechanical once the artifacts live somewhere addressable:

- Does the policy document exist for this control family?
- Was it reviewed within the organization-defined interval?
- Is the approver of record present and appropriate?
- Is the version referenced by the SSP the version in the repo?
- For inventory (KSI-PIY-01): does the IaC-derived resource inventory reconcile
  against what Config actually recorded?

Emits HDF against the same control ids the Config packs use, so Heimdall shows
one coverage view across producers.

## ODPs in scope

| ODP | Control | Notes |
| --- | --- | --- |
| Policy review interval | `*-1` controls | The single highest-leverage ODP in the program — applies to ~16 controls |
| Procedure review interval | `*-1` controls | Often distinct from policy interval |
| Training frequency | at-2 | KSI-CED-01 |
| Role-based training frequency | at-3 | KSI-CED-02 |
| Incident reporting deadline | ir-6 | FedRAMP-specific; KSI-INR-01 |
| Recovery test interval | cp-4 | KSI-RPL-04 |
| Access review interval | ac-2 | Distinct from the inactivity ODP in the IAM pack |

## Gotchas

- **Do not let this become a checkbox producer.** "The policy file exists" is
  weak evidence. Review date, approver, and SSP-version reconciliation are what
  make it worth automating; existence alone is theater.
- **The reconciliation check is the valuable one.** KSI-PIY-01 asks for an
  up-to-date inventory. Diffing IaC-declared resources against Config's recorded
  inventory catches drift and shadow resources that no conformance pack will
  ever see — and it is genuinely hard to fake.
- **Review-interval ODPs go stale silently.** A policy reviewed 13 months ago
  under a 12-month ODP fails only if something evaluates it on a schedule. This
  producer must run on a timer, not only on commit.
- **Keep control ids identical to the Config packs.** If GOV emits `AC-1` and the
  IAM pack emits `ac-2`, the Heimdall rollup fragments. Normalize case and format
  in one place, shared with the pack generator.
- **This pack is where FedRAMP-specific requirements live** (incident reporting
  timelines, the 20x AFR-theme items). Those change with program guidance more
  often than 800-53 does — version the checks against a dated requirements
  snapshot.

## Acceptance criteria

- [ ] Artifact repo layout defined (one document per control family, front-matter
      with review date, approver, version)
- [ ] Scheduled evaluation, not commit-triggered only
- [ ] HDF output using the same normalized control ids as the Config packs
- [ ] IaC-vs-recorded inventory reconciliation implemented for KSI-PIY-01
- [ ] Requirements snapshot dated and versioned

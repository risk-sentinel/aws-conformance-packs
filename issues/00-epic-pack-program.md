---
title: "[EPIC] Domain-split conformance pack program — 800-53r5 + FedRAMP 20x"
labels: epic, planning
---

## Goal

Ship a set of AWS Config conformance packs covering the automatable surface of
NIST SP 800-53 Rev 5 (Moderate) and the FedRAMP 20x KSI set, generated from one
portable rule catalog plus one per-organization ODP overlay.

One pack per domain. Tracking issues: IAM, NET, CRYPTO, LOG, VCM, RPL, GOV.

## Why domain-split rather than one pack

Not a style choice — a service quota.

## Hard caps

| Limit | Value | Increasable |
| --- | --- | --- |
| Config rules per conformance pack | **130** | No |
| Config rules per Region per account | 1000 | No |
| Conformance packs per account | 50 | No |
| Conformance packs per organization | 50 | No |
| `ConformancePackInputParameter` items | **60** | No |
| Inline template body | 51,200 bytes | — |
| Template from S3 | 300 KB | — |

Source: AWS Config service limits; `PutOrganizationConformancePack` API reference.

Two consequences worth internalizing now:

1. **130 rules/pack** means a complete 800-53r5 build is 5–7 packs regardless of
   how the work is organized. Plan the split up front; re-splitting later renames
   rules and breaks historical evidence continuity.
2. **60 input parameters/pack** is the ceiling on deploy-time ODP tuning. Past
   60, values must be baked at generation time, which means a changed ODP needs
   regenerate + redeploy rather than a stack parameter update.

## Program-level gotchas

- **`INSUFFICIENT_DATA` is the silent killer.** A rule with no in-scope resources
  does not report non-compliant — it reports insufficient data, and most
  dashboards render that as "not failing." A control can look addressed when
  nothing was ever evaluated. Every pack needs a check asserting the expected
  resource types are actually being recorded.
- **Config recorder scope gates everything.** A rule scoped to a resource type
  the recorder isn't capturing never evaluates. Recorder configuration is a
  prerequisite artifact, not an implementation detail.
- **Global resources are recorded in one Region only.** IAM and other global
  types produce empty results in every other Region's deployment.
- **Pack rules count against the 1000/Region/account limit.** Seven packs
  averaging 30 rules is ~210 per account before anything else is deployed.
- **Config is point-in-time detective evaluation.** Drift between evaluations is
  invisible. Do not describe pack output as continuous validation.
- **Cost scales with configuration items and rule evaluations**, and the logging
  domain is where it explodes. Model the bill before org-wide rollout.
- **`CUSTOM_POLICY` (Guard) rules do not take `InputParameters`.** ODP values are
  substituted into policy text at generation time, and inline Guard text eats the
  51,200-byte template budget quickly — plan on S3-hosted templates for any pack
  with more than a couple of Guard rules.

## Definition of done

- [ ] Shared ODP catalog with constraints, defaults, OSCAL `param-id` joins
- [ ] Per-domain rule catalogs, portable (no org values, no org control names)
- [ ] Overlay-driven generation, precedence overlay → OSCAL → default
- [ ] CI failing on: >130 rules/pack, >60 params/pack, template size, unknown ODP
      refs, out-of-range values, unsubstituted Guard tokens
- [ ] Traceability CSV + HDF evidence tags per pack
- [ ] Coverage report with an honest denominator (catalog controls ≠ baseline)
- [ ] Recorder-prerequisite check per pack

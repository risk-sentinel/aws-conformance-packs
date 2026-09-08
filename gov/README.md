# GOV — the non-Config evidence producer

This directory produces **zero AWS Config rules**, by design.

Roughly 120 of the ~287 controls in a Moderate baseline have no
resource-configuration signal at all: the 18 `-1` policy controls, and the AT,
PS, PL, PM, SA and SR families in bulk. Pretending otherwise is what makes
coverage numbers dishonest, so those controls are evidenced here instead —
against **policy artifacts in a repository**, not against resources.

## The failure this must not become

**"The policy file exists" is not evidence.** A producer that checks for a
file's presence and reports PASS is compliance theater, and it is worse than no
producer because it occupies the slot where real evidence would go.

Four things make an artifact check worth automating, and only one of them is
existence:

| check | strength | why |
| --- | --- | --- |
| the document exists | **weak** | a precondition, not evidence |
| reviewed within the interval | **real** | a policy reviewed 13 months ago under a 12-month ODP is out of compliance and nothing else notices |
| approver of record, with an authorized role | **real** | distinguishes a reviewed policy from an edited file |
| version matches the version the SSP cites | **strongest** | catches the drift where the SSP describes a policy nobody is following |

Every check emitted from here carries its strength, and the existence check is
never reported as satisfying a control on its own.

## Artifact format

One markdown file per policy or procedure, with YAML front matter. Body is the
document; the front matter is what is evaluated.

```markdown
---
title: Access Control Policy
kind: policy                    # policy | procedure
controls: [ac-1]                # the control ids this artifact evidences
version: 2.1.0
reviewed: 2026-03-15            # last review date, ISO 8601
approved_by: A. Reviewer
approver_role: ciso             # must be in approved_policy_approver_roles
ssp_version: 2.1.0              # the version the SSP cites for this policy
---

The policy text.
```

Where the artifacts live is a **consumer decision**, set as
`gov.artifact_dir` in `inputs.yml`. A default would point at somebody else's
policies. `gov/artifacts/` here holds one worked example so the shape is
concrete, and it is deliberately not a template to ship as-is.

## Why it runs on a timer

A review interval expires by the passage of time, not by a commit. A policy
reviewed 13 months ago under a 12-month ODP is non-compliant today and nothing
in a commit-triggered pipeline will ever notice, because nothing changed.

So the GOV workflow runs on a schedule. Commit-triggered runs are a convenience;
the scheduled run is the control.

## The inventory reconciliation

`KSI-PIY-GIV` ("Generating Inventories") asks for an up-to-date inventory. The
check that earns its place is diffing what IaC declares against what AWS Config
actually recorded — it catches drift and shadow resources that **no conformance
pack will ever see**, and it is genuinely hard to fake.

That check needs a live account, so it is separate from the artifact checks and
reports NOT_APPLICABLE rather than passing when no inventory is supplied. An
absent input must never read as a clean result.

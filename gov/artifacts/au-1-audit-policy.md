---
title: Audit and Accountability Policy
kind: policy
controls: [au-1]
version: 1.4.0
reviewed: 2024-01-02
approved_by: B. Reviewer
approver_role: contractor
ssp_version: 1.3.0
---

# Audit and Accountability Policy

**A deliberately NON-COMPLIANT worked example.** It fails three checks at once,
so the producer's failure paths are exercised by something real rather than only
by synthetic fixtures:

- `reviewed` is well outside any sane review interval
- `approver_role` is not in the approved-approver list
- `ssp_version` (1.3.0) does not match `version` (1.4.0) — the SSP cites a
  version nobody is following, which is the drift the strongest check exists for

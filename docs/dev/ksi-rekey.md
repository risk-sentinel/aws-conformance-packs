# The KSI re-key: numbered → mnemonic

FedRAMP re-keyed the Key Security Indicators from numbered ids (`KSI-IAM-01`) to
mnemonics (`KSI-IAM-APM`). Every numbered id in this repo's issue files was
stale — **0 of 28 still existed**. This file records how each was mapped, so a
reviewer can check the judgement rather than take it on faith.

## How the mapping was made

**Not by position.** The re-key is not 1:1. Indicators were merged, split and
moved between families, so `-01` in the new scheme has no meaning. Each old id
was mapped by reading the *statement* of the indicator it described and finding
the published indicator that makes the same assertion. Where an old id had no
successor making that assertion, that is recorded as such rather than forced
onto the nearest-looking mnemonic.

Two independent checks then ran against the result:

- **Existence** — every id must appear in the vendored FedRAMP snapshot
  (`tests/test_ksi_ids_in_docs.py`). This is what caught the original 28.
- **Crosswalk intersection** — for ids attached to a rule, the indicator's own
  published `controls[]` must intersect the rule's 800-53 mappings
  (`generate.py`). An indicator that shares no control with the rule is a
  mis-assignment regardless of how plausible the name reads.

Pack issue files take their KSI list **from the rule catalog**, not from prose:
the catalog ids have passed both checks, so the issue's scope line is generated
from `rules/<domain>.yaml` rather than hand-maintained beside it.

## Mapping

| Retired | Now | Why |
| --- | --- | --- |
| `KSI-IAM-01` | `KSI-IAM-APM` | phishing-resistant MFA → Adopting Passwordless Methods |
| `KSI-IAM-02`, `-03` | `KSI-IAM-APM` | authenticator strength and rotation both fold into the passwordless indicator |
| `KSI-IAM-04` | `KSI-IAM-ELP` | least privilege → Ensuring Least Privilege |
| `KSI-IAM-05`, `-06` | `KSI-IAM-AAM` | account lifecycle and inactivity → Automating Account Management |
| `KSI-CNA-01` | `KSI-CNA-ULN` | logical network separation → Using Logical Networking |
| `KSI-CNA-02` | `KSI-CNA-RNT` | traffic restriction → Restricting Network Traffic |
| `KSI-CNA-03` | `KSI-CNA-DFP` | functionality and privileges → Defining Functionality and Privileges |
| `KSI-CNA-04` | `KSI-CNA-EIS` | immutable infrastructure → Enforcing Intended State |
| `KSI-CNA-05` | `KSI-CNA-RVP` | denial-of-service protection → Reviewing Protections (which claims `sc-5`) |
| `KSI-CNA-06` | `KSI-CNA-OFA` | availability → Optimizing for Availability |
| `KSI-CNA-07` | `KSI-CNA-MAT` | attack surface → Minimizing Attack Surface |
| `KSI-SVC-01` | `KSI-SVC-ACM` | configuration management → Automating Configuration Management |
| `KSI-SVC-02`, `-03` | `KSI-SVC-SIN` | encryption at rest and in transit → Securing Information |
| `KSI-SVC-04` | `KSI-SVC-PRR` | residual risk → Preventing Residual Risk |
| `KSI-SVC-05` | `KSI-SVC-ASM` | secret management → Automating Secret Management |
| `KSI-SVC-06` | `KSI-SVC-VCM` | communications validation → Validating Communications |
| `KSI-SVC-07` | `KSI-SVC-VRI` | resource integrity → Validating Resource Integrity |
| `KSI-CMT-01` | `KSI-CMT-LMC` | change logging → Logging Changes |
| `KSI-CMT-02` | `KSI-CMT-RMV` | redeploy over modify → Redeploying vs Modifying |
| `KSI-CMT-03` | `KSI-CMT-VTD` | automated pre-deploy testing → Validating Throughout Deployment |
| `KSI-CMT-04`, `-05` | `KSI-CMT-RVP` | change procedures → Reviewing Change Procedures |
| `KSI-MLA-01` | `KSI-MLA-LET` | audit event capture → Logging Event Types |
| `KSI-MLA-02` | `KSI-MLA-RVL` | log review → Reviewing Logs |
| `KSI-MLA-03` | `KSI-MLA-EVC` | configuration evaluation → Evaluating Configurations |
| `KSI-MLA-04` | `KSI-SCR-MON` | **family change.** Authenticated vulnerability scanning left MLA; it is now Monitoring Supply Chain Risk |
| `KSI-MLA-05` | `KSI-MLA-OSM` | SIEM capability → Operating SIEM Capability |
| `KSI-MLA-06` | `KSI-MLA-ALA` | log access authorisation → Authorizing Log Access |
| `KSI-PIY-01`, `-06`, `-07` | `KSI-PIY-GIV` | inventory → Generating Inventories |
| `KSI-PIY-02` | `KSI-PIY-RES` | executive support → Reviewing Executive Support |
| `KSI-PIY-03` | `KSI-PIY-RIS` | security investment → Reviewing Investments in Security |
| `KSI-PIY-04` | `KSI-PIY-RSD` | SDLC security → Reviewing Security in the SDLC |
| `KSI-PIY-05` | `KSI-PIY-RVD` | vulnerability disclosure → Reviewing Vulnerability Disclosures |
| `KSI-CED-01`, `-02` | `KSI-CED-RAT` | **merge.** CED now has a single indicator, Reviewing All Training; the general/role-based split is gone |
| `KSI-INR-01` | `KSI-INR-RIR` | incident reporting → Reviewing Incident Response Procedures |
| `KSI-INR-02` | `KSI-INR-RPI` | past incidents → Reviewing Past Incidents |
| `KSI-INR-03` | `KSI-INR-AAR` | after-action → Generating After Action Reports |
| `KSI-RPL-01` | `KSI-RPL-RRO` | recovery objectives → Reviewing Recovery Objectives |
| `KSI-RPL-02` | `KSI-RPL-ABO` | backups → Aligning Backups with Objectives |
| `KSI-RPL-03` | `KSI-RPL-ARP` | recovery plan → Aligning Recovery Plan |
| `KSI-RPL-04` | `KSI-RPL-TRC` | recovery testing → Testing Recovery Capabilities |
| `KSI-TPR-01`, `-03` | `KSI-SCR-MIT` | see below |
| `KSI-TPR-02`, `-04` | `KSI-SCR-MON` | see below |

## TPR is no longer a KSI family

This is the one mapping that is not a rename. **Third Party Resources ceased to
be a KSI family.** `TPR` survives as a *scoping definition* (`FRD-TPR`,
`MAS-CSO-TPR`) — vocabulary for describing what counts as a third-party
resource — and the assertions that used to live in `KSI-TPR-01..04` moved into
the Supply Chain Risk family, `KSI-SCR-*`.

So a document still citing `KSI-TPR-01` is not merely using an old id; it is
citing a requirement that no longer exists in the form it describes. Anything
mapped here to `KSI-SCR-MIT` / `KSI-SCR-MON` should be re-read against the SCR
statements rather than assumed to carry over unchanged.

## Drift

20x continues to move through 2027-02 before High is locked. The snapshot in
`vendor/fedramp/` is dated and carries its own `PROVENANCE.md`;
`tools/sync_fedramp.py` refreshes it, and the existence test above is what turns
the next re-key into a failing build rather than a silent lie in a scope
statement.

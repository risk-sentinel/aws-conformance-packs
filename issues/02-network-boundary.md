---
title: "Pack: Network & Boundary Protection (NET)"
labels: pack, domain:net
---

## Scope

**800-53r5 families:** SC-7 (+enhancements), AC-4, AC-17, SC-5
**20x KSIs:** KSI-CNA-MAT, KSI-CNA-RNT, KSI-CNA-RVP, KSI-CNA-ULN, KSI-IAM-ELP
**AWS services:** VPC, EC2 security groups, NACLs, ELBv2, API Gateway, CloudFront, WAF, Shield, Route 53
**Resource types:** `AWS::EC2::SecurityGroup`, `::NetworkAcl`, `::Subnet`, `::VPC`, `::EIP`, `AWS::ElasticLoadBalancingV2::LoadBalancer`, `AWS::ApiGateway::Stage`, `AWS::CloudFront::Distribution`

**Estimated rules:** 20–30 · **Controls touched (Moderate):** ~25

## Candidate managed rules

`restricted-common-ports` (`RESTRICTED_INCOMING_TRAFFIC`), `restricted-ssh`,
`vpc-default-security-group-closed`, `vpc-sg-open-only-to-authorized-ports`,
`vpc-flow-logs-enabled`, `subnet-auto-assign-public-ip-disabled`,
`ec2-instance-no-public-ip`, `rds-instance-public-access-check`,
`redshift-cluster-public-access-check`, `s3-bucket-public-read-prohibited`,
`s3-bucket-public-write-prohibited`, `s3-account-level-public-access-blocks-periodic`,
`elbv2-acm-certificate-required`, `alb-http-to-https-redirection-check`,
`alb-waf-enabled`, `api-gw-associated-with-waf`, `cloudfront-associated-with-waf`,
`internet-gateway-authorized-vpc-only`

**Reconciled from AWS's published pack (2026-09-08).** These are rules AWS's own
NIST 800-53 Rev 5 conformance pack maps to this domain that the original research
for this issue did not name. None is dropped for being irrelevant to a particular
boundary — that judgement belongs to the boundary, not the catalog, and is made at
pack-composition time with its reason recorded (see #20). Assignment rationale in
`docs/dev/rule-reconciliation.yaml`.

`autoscaling-launch-config-public-ip-disabled`, `dms-replication-not-public`, `ebs-snapshot-public-restorable-check`, `ec2-instances-in-vpc`, `elasticsearch-in-vpc-only`, `elb-acm-certificate-required`, `emr-master-no-public-ip`, `lambda-function-public-access-prohibited`, `no-unrestricted-route-to-igw`, `opensearch-in-vpc-only`, `rds-snapshots-public-prohibited`, `redshift-enhanced-vpc-routing-enabled`, `s3-bucket-level-public-access-prohibited`, `sagemaker-notebook-no-direct-internet-access`, `ssm-document-not-public`, `vpc-vpn-2-tunnels-up`

## ODPs in scope

| ODP | Control | Binds to |
| --- | --- | --- |
| Prohibited ingress ports | sc-7 | `restricted-common-ports.blockedPort1..5` |
| Authorized ports/ranges | sc-7 | `vpc-sg-open-only-to-authorized-ports.authorizedTcpPorts` |
| Authorized VPCs for IGW | sc-7 | `internet-gateway-authorized-vpc-only.AuthorizedVpcIds` |

## Gotchas

- **`RESTRICTED_INCOMING_TRAFFIC` takes at most five discrete ports**
  (`blockedPort1`–`blockedPort5`). A port list ODP longer than five silently
  loses entries unless the generator errors. Beyond five ports, move to Guard.
- **Security groups are evaluated as objects, not as reachability.** An unused SG
  with `0.0.0.0/0` fails while a genuinely exposed workload behind a compliant SG
  and an open ALB passes. This domain has the widest gap between rule verdict and
  actual boundary posture — say so in the coverage notes.
- **IPv6 is frequently missed.** Confirm per rule whether `::/0` is evaluated
  alongside `0.0.0.0/0`; several rules historically checked only IPv4.
- **`vpc-flow-logs-enabled` checks that flow logs exist, not their destination,
  retention, or completeness.** Pair with the LOG pack's retention ODP or the
  evidence overstates AU coverage.
- **KSI-CNA-RVP (denial of service protection) has no clean managed rule.** Shield
  Advanced subscription state isn't a Config resource. WAF association rules are
  the closest proxy and only cover ALB/API GW/CloudFront. Model as hybrid.
- **KSI-CNA-EIS (immutable infrastructure) is an architecture property**, not a
  resource attribute. Do not force a rule onto it; route to the VCM pack's
  change-management evidence or to attestation.

## Acceptance criteria

- [ ] Port-list ODP validated against the 5-item cap at generation time
- [ ] IPv6 coverage confirmed per rule and recorded in the catalog
- [ ] KSI-CNA-EIS and KSI-CNA-RVP explicitly modeled as hybrid or documented, not faked
- [ ] Reachability caveat in the pack coverage report

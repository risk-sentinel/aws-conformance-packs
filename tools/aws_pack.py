"""Read the vendored AWS conformance pack, as a verification source.

A managed rule's SourceIdentifier and its parameter names are asserted from
documentation unless something checks them. A wrong identifier does NOT fail at
generation -- it fails at put-conformance-pack, or worse it deploys and the rule
reports INSUFFICIENT_DATA forever, which most dashboards render as "not failing".

AWS publishes its own mapping of managed rules to NIST 800-53 Rev 5, so it is
authoritative for both the identifier and the parameter names. This reads it.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

PACK = (Path(__file__).resolve().parents[1]
        / "vendor/aws/Operational-Best-Practices-for-NIST-800-53-rev-5.yaml")


@dataclass(frozen=True)
class AwsRule:
    name: str                    # ConfigRuleName, e.g. iam-password-policy
    identifier: str              # SourceIdentifier, e.g. IAM_PASSWORD_POLICY
    parameters: frozenset[str]


@dataclass(frozen=True)
class AwsPack:
    rules_by_name: dict[str, AwsRule]
    rules_by_identifier: dict[str, AwsRule]

    def get(self, name: str, identifier: str | None = None) -> AwsRule | None:
        return self.rules_by_name.get(name) or (
            self.rules_by_identifier.get(identifier) if identifier else None)


@lru_cache(maxsize=1)
def load(path: Path | None = None) -> AwsPack:
    p = path or PACK
    if not p.exists():
        raise FileNotFoundError(
            f"{p} is missing. It is vendored deliberately -- see "
            f"vendor/aws/PROVENANCE.md. Without it, nothing checks that a managed "
            f"rule identifier or parameter name is real."
        )
    doc = yaml.safe_load(p.read_text())
    by_name: dict[str, AwsRule] = {}
    by_id: dict[str, AwsRule] = {}
    for res in (doc.get("Resources") or {}).values():
        if res.get("Type") != "AWS::Config::ConfigRule":
            continue
        props = res["Properties"]
        r = AwsRule(
            name=props["ConfigRuleName"],
            identifier=(props.get("Source") or {}).get("SourceIdentifier", ""),
            parameters=frozenset((props.get("InputParameters") or {}).keys()),
        )
        by_name[r.name] = r
        if r.identifier:
            by_id[r.identifier] = r
    return AwsPack(rules_by_name=by_name, rules_by_identifier=by_id)

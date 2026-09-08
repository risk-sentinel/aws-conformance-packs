"""Read the vendored AWS managed-rule index, as a verification source.

Derived from ALL of AWS's published conformance packs, not one of them. Checking
against a single pack left 24 real managed rules unverifiable purely because that
pack does not happen to carry them.

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

import json

INDEX = Path(__file__).resolve().parents[1] / "vendor/aws/aws-managed-rule-index.json"


@dataclass(frozen=True)
class AwsRule:
    name: str                    # ConfigRuleName, e.g. iam-password-policy
    identifier: str              # the identifier the most AWS packs agree on
    parameters: frozenset[str]   # union of parameter names seen in any pack
    packs: tuple[str, ...] = ()  # which packs it was seen in — traceable claim
    # AWS's own packs disagree about two rules. Every identifier seen is kept so
    # verification can accept any of them rather than rejecting a rule because
    # one upstream pack has a typo.
    alternates: frozenset[str] = frozenset()

    def accepts_identifier(self, ident: str) -> bool:
        return ident == self.identifier or ident in self.alternates


@dataclass(frozen=True)
class AwsPack:
    rules_by_name: dict[str, AwsRule]
    rules_by_identifier: dict[str, AwsRule]

    def get(self, name: str, identifier: str | None = None) -> AwsRule | None:
        return self.rules_by_name.get(name) or (
            self.rules_by_identifier.get(identifier) if identifier else None)


@lru_cache(maxsize=1)
def load(path: Path | None = None) -> AwsPack:
    p = path or INDEX
    if not p.exists():
        raise FileNotFoundError(
            f"{p} is missing. It is vendored deliberately -- see "
            f"vendor/aws/PROVENANCE.md. Without it, nothing checks that a managed "
            f"rule identifier or parameter name is real."
        )
    doc = json.loads(p.read_text())
    by_name: dict[str, AwsRule] = {}
    by_id: dict[str, AwsRule] = {}
    for name, e in (doc.get("rules") or {}).items():
        alts = set(e.get("conflicting_identifiers") or {}) - {e["identifier"]}
        r = AwsRule(name=name, identifier=e["identifier"],
                    parameters=frozenset(e.get("parameters") or []),
                    packs=tuple(e.get("packs") or []), alternates=frozenset(alts))
        by_name[name] = r
        for i in {r.identifier, *alts}:
            by_id.setdefault(i, r)
    return AwsPack(rules_by_name=by_name, rules_by_identifier=by_id)

"""Service availability: which Regions a rule's service actually exists in.

Derived from awslabs' OSCAL content for AWS services. Answers two different
questions that are easy to conflate:

    availability   a SCOPE CLASS -- GLOBAL, REGIONAL, ZONAL, SUBZONAL. IAM is
                   GLOBAL, which is why an IAM pack must be pinned to the one
                   Region recording global resources.

    regions        the actual availability LIST. Bedrock exists in 15 Regions
                   and S3 in 34, and no pack currently makes that distinction.

The resource-type join is explicit, never derived from the type string. See
vendor/aws-services/resource-type-map.yaml for why: `AWS::RDS::DBCluster`
resolves to DocDB under a naive match, because DocumentDB shares the `rds` ARN
namespace, and a wrong service means a wrong Region scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "vendor/aws-services/aws-service-availability.json"
MAP = ROOT / "vendor/aws-services/resource-type-map.yaml"


@dataclass(frozen=True)
class Service:
    service_id: str
    availability: str | None
    regions: frozenset[str]

    @property
    def is_global(self) -> bool:
        return self.availability == "GLOBAL"


@dataclass(frozen=True)
class Catalog:
    services: dict[str, Service]
    by_resource_type: dict[str, str]
    account_level: frozenset[str]
    all_regions: frozenset[str]

    def for_resource_type(self, rt: str) -> Service | None:
        """None for an account-level pseudo-type, which is never Region-scoped."""
        if rt in self.account_level:
            return None
        sid = self.by_resource_type.get(rt)
        if sid is None:
            raise KeyError(
                f"{rt} has no entry in {MAP.name}. Add one explicitly -- deriving it "
                f"from the type string resolves AWS::RDS::* to DocDB.")
        return self.services[sid]

    def unavailable_in(self, rt: str, region: str) -> bool:
        """True when this resource type's service does not exist in that Region."""
        svc = self.for_resource_type(rt)
        if svc is None or svc.is_global or not svc.regions:
            # Global services exist everywhere they matter, and a service
            # publishing no Region list is treated as available rather than
            # excluded -- absence of data is not evidence of absence, and
            # excluding on it would silently shrink a pack.
            return False
        return region not in svc.regions


@lru_cache(maxsize=1)
def load() -> Catalog:
    if not INDEX.exists() or not MAP.exists():
        raise FileNotFoundError(
            f"{INDEX.name} or {MAP.name} is missing; run tools/build_service_index.py")
    idx = json.loads(INDEX.read_text())
    m = yaml.safe_load(MAP.read_text())
    services = {
        sid: Service(sid, v.get("availability"), frozenset(v.get("regions") or []))
        for sid, v in idx["services"].items()
    }
    return Catalog(services=services, by_resource_type=dict(m["map"]),
                   account_level=frozenset(m.get("account_level") or []),
                   all_regions=frozenset(idx.get("regions") or []))

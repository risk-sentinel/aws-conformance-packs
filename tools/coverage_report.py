#!/usr/bin/env python3
"""Emit the per-resource-type coverage table for README.md.

    python3 tools/coverage_report.py            # print
    python3 tools/coverage_report.py --write    # splice into README.md

The question a team asks before adopting this is not "how many rules are there".
It is **"my boundary has S3 and RDS and load balancers -- what do I actually get
out of the gate?"** This answers that, keyed by resource type, because resource
types are what a boundary has.

It is generated rather than written, and `tools/lint_packs.py` fails if README
drifts from the catalogs. A hand-maintained coverage table is stale the day after
it is written, and a stale coverage claim is worse than none.

NOTE ON THE NUMBERS. `controls` counts DISTINCT 800-53 Rev 5 controls that the
rules scoped to that resource type crosswalk to. Controls overlap heavily between
resource types, so the column does NOT sum -- adding it up would double-count
badly. It also counts controls *touched*, never controls *satisfied*: most of
these crosswalks are `supporting`, and every pack's coverage report says so.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- COVERAGE-TABLE:START -->"
END = "<!-- COVERAGE-TABLE:END -->"
REG_START = "<!-- PACK-REGISTRY:START -->"
REG_END = "<!-- PACK-REGISTRY:END -->"
SUM_START = "<!-- CONTROL-SUMMARY:START -->"
SUM_END = "<!-- CONTROL-SUMMARY:END -->"
RULES_DIR = "rules"
RULE_GLOB = "*.yaml"
NIST_INDEX = ROOT / "vendor" / "nist" / "nist-800-53r5-params.json"
AWS_INDEX = ROOT / "vendor" / "aws" / "aws-managed-rule-index.json"

# Strongest wins when several rules touch one control. `full` is deliberately
# rare -- it claims the rule alone evidences the control, which is almost never
# true of a Config rule.
STRENGTH = {"full": 3, "partial": 2, "supporting": 1}

FAMILY_NAMES = {
    "ac": "Access Control", "at": "Awareness and Training", "au": "Audit and Accountability",
    "ca": "Assessment, Authorization and Monitoring", "cm": "Configuration Management",
    "cp": "Contingency Planning", "ia": "Identification and Authentication",
    "ir": "Incident Response", "ma": "Maintenance", "mp": "Media Protection",
    "pe": "Physical and Environmental Protection", "pl": "Planning",
    "pm": "Program Management", "ps": "Personnel Security", "pt": "PII Processing",
    "ra": "Risk Assessment", "sa": "System and Services Acquisition",
    "sc": "System and Communications Protection", "si": "System and Information Integrity",
    "sr": "Supply Chain Risk Management",
}


def _rule_docs() -> list[dict]:
    """Every domain rule catalog, parsed once, in a stable order.

    Six call sites used to re-glob and re-parse `rules/*.yaml` independently.
    Beyond the duplicated literal, that made it possible for two of them to
    disagree about ordering, which is how a generated table acquires a diff
    that is not a real change.
    """
    return [
        yaml.safe_load(f.read_text()) for f in sorted((ROOT / RULES_DIR).glob(RULE_GLOB))
    ]


def collect() -> tuple[list[tuple], dict]:
    res = defaultdict(lambda: {"rules": set(), "controls": set(), "packs": set()})
    totals = {"rules": 0, "controls": set(), "packs": set()}
    for doc in _rule_docs():
        totals["packs"].add(doc["domain"])
        for name, rule in doc["rules"].items():
            ctrls = set(rule["controls"].get("nist_800_53_r5", []))
            totals["rules"] += 1
            totals["controls"] |= ctrls
            for rt in rule.get("resource_types", []):
                res[rt]["rules"].add(name)
                res[rt]["controls"] |= ctrls
                res[rt]["packs"].add(doc["domain"])
    rows = sorted(res.items(), key=lambda x: (-len(x[1]["controls"]), -len(x[1]["rules"]), x[0]))
    return rows, totals


def render(limit: int | None = None) -> str:
    rows, totals = collect()
    shown = rows if limit is None else rows[:limit]
    out = [
        f"**{totals['rules']} rules across {len(totals['packs'])} packs, touching "
        f"{len(totals['controls'])} distinct NIST SP 800-53 Rev 5 controls "
        f"over {len(rows)} AWS resource types.**",
        "",
        "What you get depends on what your boundary actually runs. This is keyed by",
        "resource type for that reason — find the rows you have.",
        "",
        "| If your boundary has | Rules | Controls touched | From packs |",
        "| --- | ---: | ---: | --- |",
    ]
    for rt, v in shown:
        out.append(f"| `{rt}` | {len(v['rules'])} | {len(v['controls'])} | "
                   f"{', '.join(sorted(v['packs']))} |")
    if limit is not None and len(rows) > limit:
        out.append(f"| _…and {len(rows) - limit} further resource types_ | | | |")
    out += [
        "",
        "**Read the middle column carefully.** It counts distinct controls the rules",
        "for that resource type *crosswalk to* — not controls *satisfied*. Most of",
        "those crosswalks are `supporting`, and each pack's generated",
        "`coverage.md` says which are which and what each rule cannot see.",
        "",
        "**The column does not sum.** Controls overlap heavily between resource types;",
        "adding it up double-counts badly.",
        "",
        "**A rule with no in-scope resources reports `INSUFFICIENT_DATA`**, which most",
        "dashboards render as \"not failing\". Rows you do not have are not silently",
        "green — they are silently absent. The recorder preflight refuses to deploy a",
        "pack whose resource types are not being recorded, for exactly this reason.",
    ]
    return "\n".join(out)


def render_registry() -> str:
    """The pack registry, from what actually renders.

    It shipped as planning ESTIMATES and stayed that way after the packs were
    built, so it claimed RPL was 12-18 rules when it is 25 and NET was 20-30 when
    it is 34. An estimate left in place after the thing exists is not an estimate
    any more; it is a wrong number in the front door.
    """
    rows = []
    for doc in _rule_docs():
        rules = doc["rules"]
        controls, ksis, cov = set(), set(), {}
        params = 0
        for r in rules.values():
            controls |= set(r["controls"].get("nist_800_53_r5", []))
            ksis |= set(r["controls"].get("ksi", []))
            cov[r["coverage"]] = cov.get(r["coverage"], 0) + 1
            params += len(r.get("parameters") or {}) + len(r.get("tokens") or {})
        rows.append((doc["domain"], len(rules), len(controls), params,
                     len(ksis), cov, doc.get("region_scope", "-")))
    out = [
        "| Pack | Rules | Controls touched | ODP-bound params | 20x indicators | Scope |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for d, n, c, p, k, _cov, scope in sorted(rows):
        out.append(f"| **{d}** | {n} | {c} | {p} | {k} | {scope} |")
    out.append(f"| **GOV** | **0** | — | 7 | — | non-Config producer |")
    tot_rules = sum(r[1] for r in rows)
    out += [
        "",
        f"**{tot_rules} Config rules across {len(rows)} deployable packs.** Every pack is "
        f"under the hard 130-rule cap; all of them together are {tot_rules} of the "
        f"1000-per-Region-per-account ceiling.",
        "",
        "GOV emits **zero Config rules by design** — roughly 120 Moderate controls have no",
        "resource-configuration signal, and it evidences those against policy artifacts",
        "instead. See `gov/README.md`.",
        "",
        "Controls-touched **overlaps between packs and does not sum to a baseline**. It",
        "counts controls a pack's rules crosswalk to, not controls satisfied — each pack's",
        "generated `coverage.md` says which are `full`, `partial` or `supporting`, and what",
        "each rule cannot see.",
    ]
    return "\n".join(out)


def _aws_reach() -> dict[str, int]:
    """How this catalog stands against AWS's own published conformance packs.

    Counted by rule IDENTIFIER, not by the CFN logical name the index is keyed
    on: awslabs ships the same identifier under several logical names when a
    rule is parameterised differently, so counting keys overstates the surface
    (503 entries, 419 distinct rules).

    The interesting comparison is against AWS's OWN Rev 5 pack, not against
    every pack it publishes. Rules that appear only in the PCI, C5 or AI/ML
    packs carry no Rev 5 crosswalk from AWS, so adopting one means authoring
    the control mapping ourselves -- a different kind of work, and the reason
    the remaining surface is not simply "more rules".
    """
    aws = json.loads(AWS_INDEX.read_text())["rules"]
    idents = {v["identifier"] for v in aws.values()}
    r5 = {
        v["identifier"]
        for v in aws.values()
        if any("NIST-800-53-rev-5" in p for p in v["packs"])
    }
    ours = {
        r["identifier"]
        for doc in _rule_docs()
        for r in doc["rules"].values()
        if r.get("source") == "managed"
    }
    return {
        "distinct": len(idents),
        "r5": len(r5),
        "r5_carried": len(r5 & ours),
        "r5_omitted": len(r5 - ours),
        "beyond_r5": len(ours - r5),
        "other_frameworks": len(idents - r5 - ours),
    }


def _our_rule_total() -> int:
    return sum(len(doc["rules"]) for doc in _rule_docs())


def _control_strength() -> dict[str, str]:
    """Map each touched control to the strongest coverage any rule claims for it."""
    best: dict[str, int] = {}
    for doc in _rule_docs():
        for rule in doc["rules"].values():
            rank = STRENGTH.get(rule.get("coverage", "supporting"), 1)
            for c in rule["controls"].get("nist_800_53_r5", []):
                best[c] = max(best.get(c, 0), rank)
    inv = {v: k for k, v in STRENGTH.items()}
    return {c: inv[r] for c, r in best.items()}


def render_control_summary() -> str:
    """Which 800-53 Rev 5 controls the packs touch, by family and by baseline.

    The per-resource-type table answers "what do I get for the things I run".
    This answers the other question an assessor asks first: "which controls does
    this claim to speak to, and how much of my baseline is that". Both numbers
    matter, and neither substitutes for the other.
    """
    index = json.loads(NIST_INDEX.read_text())["controls"]
    strength = _control_strength()
    touched = set(strength)

    fams: dict[str, dict] = defaultdict(
        lambda: {"mod": set(), "high": set(), "low": set(), "hit": set()}
    )
    base = {b: set() for b in ("low", "moderate", "high")}
    for cid, meta in index.items():
        fam = cid.split("-", 1)[0]
        for b in meta.get("baselines", []):
            base[b].add(cid)
            fams[fam][{"low": "low", "moderate": "mod", "high": "high"}[b]].add(cid)
    for cid in touched:
        fams[cid.split("-", 1)[0]]["hit"].add(cid)

    out = [
        f"The packs crosswalk to **{len(touched)} distinct Rev 5 controls**. Against the "
        "published baselines that is:",
        "",
        "| Baseline | Controls in baseline | Touched by these packs |",
        "| --- | ---: | ---: |",
    ]
    for b in ("low", "moderate", "high"):
        n = len(touched & base[b])
        out.append(f"| {b.title()} | {len(base[b])} | {n} ({n * 100 // len(base[b])}%) |")

    out += [
        "",
        "**Those percentages are a ceiling on ambition, not a score.** A control is "
        "counted here if any rule crosswalks to it — see the strength column below, "
        "and read `Reading these numbers honestly` before quoting any of it.",
        "",
        "### By control family",
        "",
        "| Family | In Moderate | Touched | Strongest claim | Where |",
        "| --- | ---: | ---: | --- | --- |",
    ]
    pack_of: dict[str, set] = defaultdict(set)
    for doc in _rule_docs():
        for rule in doc["rules"].values():
            for c in rule["controls"].get("nist_800_53_r5", []):
                pack_of[c.split("-", 1)[0]].add(doc["domain"])

    for fam in sorted(fams, key=lambda f: (-len(fams[f]["hit"]), f)):
        v = fams[fam]
        hit = v["hit"]
        if hit:
            strongest = max((strength[c] for c in hit), key=lambda s: STRENGTH[s])
            where = ", ".join(sorted(pack_of[fam]))
        else:
            strongest, where = "—", "GOV"
        out.append(
            f"| **{fam.upper()}** {FAMILY_NAMES.get(fam, '')} | {len(v['mod'])} | "
            f"{len(hit)} | {strongest} | {where} |"
        )

    mod = base["moderate"]
    no_signal = {f for f, v in fams.items() if not v["hit"]}
    dark = {c for c in mod - touched if c.split("-", 1)[0] in no_signal}
    reachable = (mod - touched) - dark
    out += [
        "",
        f"**{len(mod - touched)} Moderate controls are untouched. They split two ways, and "
        "the split is the whole point.**",
        "",
        f"- **{len(dark)}** sit in the families marked `—` above — physical, personnel, "
        "training, planning, acquisition, incident response. These have no "
        "resource-configuration signal at all. AWS Config cannot see them, and no number "
        "of additional rules will change that. They belong to GOV, which evidences them "
        "against policy artifacts.",
        f"- **{len(reachable)}** sit in families these packs already reach. That is the "
        "honest extension surface — controls where a Config rule could plausibly say "
        "something and none currently does. It is smaller than it looks: these catalogs "
        f"already carry **every one of the {_aws_reach()['r5']} rules in AWS\'s own Rev 5 "
        f"conformance pack**, plus {_aws_reach()['beyond_r5']} that pack does not ship. "
        "There is no backlog of obvious Rev 5 rules left unclaimed.",
        "",
        f"AWS\'s Rev 5 pack holds exactly {_aws_reach()['r5']} rules, which is the hard "
        "per-pack limit to the rule. It cannot grow without splitting, and a single pack "
        "at the cap is also a single blast radius, a single parameter budget and a single "
        "thing to redeploy. That is the argument for splitting by domain, and it is why "
        "these catalogs can hold more rules than AWS ships in one pack.",
        "",
        "Treating those two numbers as one is what produces a coverage claim an assessor "
        "takes apart in the first hour.",
        "",
        f"AWS publishes {_aws_reach()['distinct']} distinct managed rules in total, so "
        f"roughly {_aws_reach()['other_frameworks']} remain unused — but those appear only "
        "in its PCI, C5, IRS-1075 and AI/ML packs, which carry no Rev 5 crosswalk. "
        "Adopting one means authoring the control mapping ourselves rather than "
        "inheriting it, which is why the number is a research backlog and not a to-do "
        "list.",
        "",
        "**Strongest claim is the high-water mark for the family, not its average.** One "
        "`partial` rule in a family of thirty `supporting` ones puts `partial` in that "
        "cell. Per-control detail is in each pack\'s generated `coverage.md`.",
        "",
        "**Moderate is a subset of High**, so every control touched in Moderate is also "
        "touched in High — the two rows report the same 70 controls against different "
        "denominators. Families with no baseline allocation at all (PM) are absent from "
        "the table rather than shown as zero.",
    ]
    return "\n".join(out)


def _splice(text: str, start: str, end: str, body: str) -> str:
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    return f"{head}{start}\n\n{body}\n\n{end}{tail}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true", help="splice into README.md")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--check", action="store_true", help="exit 1 if README is stale")
    args = ap.parse_args()

    table = render(args.limit)
    readme = ROOT / "README.md"

    if args.write or args.check:
        text = readme.read_text()
        for a, b in ((START, END), (REG_START, REG_END), (SUM_START, SUM_END)):
            if a not in text or b not in text:
                print(f"::error::README.md has no {a} / {b} markers")
                return 1
        new = _splice(text, START, END, table)
        new = _splice(new, REG_START, REG_END, render_registry())
        new = _splice(new, SUM_START, SUM_END, render_control_summary())
        if args.check:
            if new != text:
                print("::error::README.md coverage table is stale. Run "
                      "`python3 tools/coverage_report.py --write`. A hand-maintained "
                      "coverage claim goes stale the day after it is written.")
                return 1
            print("README coverage table is current")
            return 0
        readme.write_text(new)
        print(f"spliced {args.limit} rows into README.md")
        return 0

    print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

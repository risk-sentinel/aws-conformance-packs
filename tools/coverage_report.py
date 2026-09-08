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
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
START = "<!-- COVERAGE-TABLE:START -->"
END = "<!-- COVERAGE-TABLE:END -->"
REG_START = "<!-- PACK-REGISTRY:START -->"
REG_END = "<!-- PACK-REGISTRY:END -->"


def collect() -> tuple[list[tuple], dict]:
    res = defaultdict(lambda: {"rules": set(), "controls": set(), "packs": set()})
    totals = {"rules": 0, "controls": set(), "packs": set()}
    for f in sorted((ROOT / "rules").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
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
    for f in sorted((ROOT / "rules").glob("*.yaml")):
        doc = yaml.safe_load(f.read_text())
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
        for a, b in ((START, END), (REG_START, REG_END)):
            if a not in text or b not in text:
                print(f"::error::README.md has no {a} / {b} markers")
                return 1
        new = _splice(text, START, END, table)
        new = _splice(new, REG_START, REG_END, render_registry())
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

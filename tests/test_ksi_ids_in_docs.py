"""Narrative documents must name KSIs that FedRAMP actually publishes.

The generator already refuses an unknown KSI in a rule catalog. Nothing checked
the *prose*, and every issue file shipped with the pre-2025 numbered ids
(`KSI-IAM-01`) long after FedRAMP re-keyed the indicators to mnemonics. Stale
ids in an issue are worse than a typo: they are the scope statement a reviewer
reads to decide whether the pack covers what it claims.

Scope is deliberately narrow -- issues, docs and the README. Test fixtures and
source comments legitimately name retired ids as negative cases, and so does
`docs/dev/ksi-rekey.md`, whose whole subject is the retired ids; it is exempted
by name rather than by loosening the pattern.
"""

import re
from pathlib import Path

import pytest

from tools.fedramp import load

ROOT = Path(__file__).resolve().parent.parent
# The re-key ledger names every retired id on purpose -- that is its content.
EXEMPT = {ROOT / "docs" / "dev" / "ksi-rekey.md"}
NARRATIVE = sorted(
    p
    for p in [*ROOT.glob("issues/*.md"), *ROOT.glob("docs/**/*.md"), ROOT / "README.md"]
    if p not in EXEMPT
)
NUMBERED = re.compile(r"KSI-[A-Z]{3}-[0-9]{2}")
MNEMONIC = re.compile(r"KSI-[A-Z]{3}-[A-Z]{3}")


@pytest.mark.parametrize("path", NARRATIVE, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_retired_numbered_ksi_ids(path):
    hits = sorted(set(NUMBERED.findall(path.read_text())))
    assert not hits, (
        f"{path.relative_to(ROOT)} names retired numbered KSI ids {hits}. "
        "FedRAMP re-keyed indicators to mnemonics; the re-key is not 1:1, so "
        "map by the indicator's statement, not by position in the old numbering."
    )


@pytest.mark.parametrize("path", NARRATIVE, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_named_ksi_exists_in_the_snapshot(path):
    published = set(load().indicators)
    unknown = sorted(set(MNEMONIC.findall(path.read_text())) - published)
    assert not unknown, (
        f"{path.relative_to(ROOT)} names KSI ids absent from the vendored "
        f"FedRAMP snapshot: {unknown}"
    )


def test_the_rekey_ledger_is_exempt_but_still_id_checked():
    """The one exempted file must still only name ids that once or now exist."""
    ledger = ROOT / "docs" / "dev" / "ksi-rekey.md"
    assert ledger.exists() and ledger in EXEMPT
    assert ledger not in set(NARRATIVE)
    published = set(load().indicators)
    unknown = sorted(set(MNEMONIC.findall(ledger.read_text())) - published)
    assert not unknown, f"re-key ledger maps onto non-existent indicators: {unknown}"


def test_the_guard_would_catch_a_stale_id():
    """A check that cannot fail is not evidence."""
    assert NUMBERED.findall("routes through KSI-IAM-01 today") == ["KSI-IAM-01"]
    assert sorted(set(MNEMONIC.findall("KSI-TPR-XXX"))) == ["KSI-TPR-XXX"]
    assert "KSI-TPR-XXX" not in set(load().indicators)

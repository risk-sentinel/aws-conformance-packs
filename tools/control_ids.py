"""Control-id normalization, shared by the pack generator and the GOV producer.

There is exactly one of these functions in the repository, and that is the whole
point. Issue #8 states the failure directly: if GOV emits `AC-1` and a pack emits
`ac-2`, the Heimdall rollup fragments and one control appears as two. A rollup
that splits does not look broken -- it looks like partial coverage, which is the
worst way for a defect to present.

The same control is written at least four ways in the sources this repo joins:

    AC-2(3)          NIST publication style
    AC-2 (3)         same, spaced
    ac-02.03         OSCAL zero-padded
    ac-2.3           OSCAL compact

All four normalize to `ac-2.3`.
"""

from __future__ import annotations

import re

# AC-2(3) / AC-2 (3) / AC-2(3)(a) -> dotted
_ENHANCEMENT = re.compile(r"\s*\(\s*(\d+)\s*\)")
# Leading zeros in any dot-separated numeric segment: ac-02.03 -> ac-2.3
_PAD = re.compile(r"(?<=[-.])0+(\d)")
_SHAPE = re.compile(r"^[a-z]{2}-\d+(\.\d+)*$")


def normalize_control_id(raw: str) -> str:
    """Fold any recognized spelling of a control id onto the canonical form.

    >>> normalize_control_id("AC-2(3)")
    'ac-2.3'
    >>> normalize_control_id("ac-02.03")
    'ac-2.3'
    >>> normalize_control_id("IA-5")
    'ia-5'
    """
    if raw is None:
        raise ValueError("control id is None")
    s = str(raw).strip().lower()
    if not s:
        raise ValueError("control id is empty")
    s = _ENHANCEMENT.sub(r".\1", s)
    s = re.sub(r"\s+", "", s)
    s = _PAD.sub(r"\1", s)
    return s


def is_control_id(raw: str) -> bool:
    """True when the value normalizes to something shaped like a control id.

    Deliberately narrow. A KSI id (`KSI-IAM-01`) is NOT a control id, and quietly
    accepting one here would put it in the 800-53 column of the traceability
    report where it would be read as a control.
    """
    try:
        return bool(_SHAPE.match(normalize_control_id(raw)))
    except ValueError:
        return False


def control_family(raw: str) -> str:
    """The two-letter family: `ac-2.3` -> `ac`."""
    return normalize_control_id(raw).split("-", 1)[0]

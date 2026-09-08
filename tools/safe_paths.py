"""Validate paths and tokens taken from the command line.

Every tool here accepts paths as CLI arguments -- `--overlay`, `--rules`,
`--out`, `--artifact-dir` -- and several are passed through by CI from values in
`inputs.yml`. SonarCloud flagged 18 of them (`pythonsecurity:S8707`, `S8705`):
a caller supplying a crafted path escapes the file system boundary the tool was
assumed to work within, and a crafted `--profile` reaches a subprocess argv.

The exposure is modest -- these are operator tools, and our own workflows pass
fixed strings -- but "the caller is trusted" is the assumption every path
traversal rests on, and this repository refuses that reasoning everywhere else.
Fixing was cheaper than arguing, and `docs/dev/issue_rules.md` makes fixing the
default.

TWO CLASSES OF PATH, AND THEY NEED DIFFERENT RULES
--------------------------------------------------
`repo_asset` requires containment inside this repository. It is kept for paths
that genuinely cannot be anywhere else -- and, notably, that is almost none of
the CLI arguments. Making `--rules` and `--catalog` repo-contained broke seven
tests that render a catalog from a temporary directory, which is exactly the
legitimate use containment would have blocked for adopters too. A guard that
refuses valid work is one people learn to bypass; that lesson cost a round trip
in the recorder preflight and was not worth relearning here.

So every CLI path is a CONSUMER PATH: resolved, checked for null bytes and for
being the right kind of thing, and REPORTED AT ITS RESOLVED ABSOLUTE LOCATION so
a traversal is visible in the log rather than silent. Containment is not
enforced, because a consumer's overlay or policy repository is not in ours and
requiring otherwise would break the portability the whole design rests on.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Conservative: AWS profile names allow more, but nothing outside this set has a
# legitimate reason to appear in one, and it is the value that reaches an argv.
TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class UnsafePath(Exception):
    """A path or token that this tool declines to act on."""


def _base(p: Path | str, what: str) -> Path:
    s = str(p)
    if "\x00" in s:
        raise UnsafePath(f"{what} contains a null byte")
    if not s.strip():
        raise UnsafePath(f"{what} is empty")
    return Path(s).expanduser().resolve()


def repo_asset(p: Path | str, what: str, *, must_exist: bool = True) -> Path:
    """A path that must resolve INSIDE this repository."""
    r = _base(p, what)
    if not r.is_relative_to(ROOT):
        raise UnsafePath(
            f"{what} resolves to {r}, which is outside this repository. Files the "
            f"generator treats as its own assets must live in it; a path escaping "
            f"the repository is refused rather than read.")
    if must_exist and not r.exists():
        raise UnsafePath(f"{what} does not exist: {r}")
    return r


def consumer_file(p: Path | str, what: str, *, must_exist: bool = True) -> Path:
    """A path that may legitimately live outside the repository.

    Reported at its resolved absolute path so a traversal is visible in the log
    rather than silent. Containment is deliberately NOT enforced: a consumer's
    overlay or policy repository is not in ours, and requiring otherwise would
    break the portability this design rests on.
    """
    r = _base(p, what)
    if must_exist:
        if not r.exists():
            raise UnsafePath(f"{what} does not exist: {r}")
        if not r.is_file():
            raise UnsafePath(f"{what} is not a file: {r}")
    if not r.is_relative_to(ROOT):
        print(f"::notice::{what} resolves outside this repository: {r}", file=sys.stderr)
    return r


def consumer_dir(p: Path | str, what: str, *, must_exist: bool = True) -> Path:
    r = _base(p, what)
    if must_exist and not r.is_dir():
        raise UnsafePath(f"{what} is not a directory: {r}")
    if not r.is_relative_to(ROOT):
        print(f"::notice::{what} resolves outside this repository: {r}", file=sys.stderr)
    return r


def out_dir(p: Path | str, what: str = "--out") -> Path:
    """An output directory. Created if absent; refuses to write over a file."""
    r = _base(p, what)
    if r.exists() and not r.is_dir():
        raise UnsafePath(f"{what} exists and is not a directory: {r}")
    if not r.is_relative_to(ROOT):
        print(f"::notice::{what} resolves outside this repository: {r}", file=sys.stderr)
    return r


def token(value: str, what: str) -> str:
    """A value that reaches a subprocess argv.

    The call sites pass a list rather than a shell string, so this is defence in
    depth -- but an argv element is still an injection surface for the program
    being invoked, and a profile name has no reason to contain anything but this.
    """
    if not TOKEN_RE.match(value or ""):
        raise UnsafePath(
            f"{what} {value!r} contains characters that have no legitimate place in "
            f"one. Allowed: letters, digits, dot, underscore, hyphen.")
    return value

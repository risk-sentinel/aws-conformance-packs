# NIST SP 800-53 Rev 5 parameter index — derived, vendored

| | |
| --- | --- |
| Upstream | NIST OSCAL resolved baseline catalogs, SP 800-53 Rev 5 |
| Baselines | Low, Moderate, High (`*-baseline-resolved-profile_catalog.json`) |
| Derived by | `tools/build_nist_index.py` |
| Derived on | 2026-09-07 |
| Controls | 370 |
| Parameters | 767 |
| SHA-256 | `4bf384864fcaabb655e8f8163336906df3f2f288ec11c3651f85e4951e305548` |

## Why an index rather than the catalogs

The three resolved baselines are ~10.6 MB of OSCAL. Vendoring them into a
repository whose selling point is portability is a bad trade, and nobody reviews
a diff against 10.6 MB of JSON in a pull request. This index is **226 KB** and
carries only what the ODP catalog joins against:

- every control's parameters, with the Rev 5 canonical `_odp` id **and** the
  `_prm_` alt-identifier, so a value joins from either direction
- each parameter's label and guidelines prose, so a catalog entry can be written
  without opening the catalogue
- **which baselines each control resolves in** — load-bearing, because `ac-2.3`
  is absent from Low, and an ODP bound to a control outside the target baseline
  must not render into that baseline's pack

Cross-check on the derived counts: 149 / 287 / 370 controls for Low / Moderate /
High, which matches an independent count taken directly from the catalogs.

## Rebuild, do not hand-edit

```bash
python3 tools/build_nist_index.py --catalogs <dir-with-the-three-catalogs>
```

A hand-edit is how a parameter id that joins to nothing gets in — and a wrong id
does not error, it silently matches no ODP while looking correct.

## Provenance caveat

This snapshot was derived from resolved catalogs held in a sibling repository's
**test fixtures**. Those exist to serve tests and may change for test reasons.
Before this index is relied on for an assessment, re-derive it from a NIST
release artifact and record that release here instead.

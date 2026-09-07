# FedRAMP Consolidated Rules — vendored snapshot

Vendored so this repository is self-contained: a consumer clones it and can
generate and validate packs with no network call and no dependency on an
upstream that is still moving.

| | |
| --- | --- |
| Source | https://github.com/FedRAMP/rules |
| File | `fedramp-consolidated-rules.json` |
| Upstream commit | `58efbf3d898496dd4a3a419eba78e458bbad5cb6` |
| Datafile version | `2026.07.14.01` |
| Upstream last_updated | 2026-07-14 |
| Retrieved | 2026-09-07 |
| SHA-256 | `135707003f0aaa5ceb10d7d32c2681e5b1585a4eaf4403d0d135837787e5ae8e` |

## Why a snapshot rather than a fetch

FedRAMP 20x is changing rapidly and is expected to keep changing until the High
baseline locks around **2027-02**. Generating against a live fetch would mean a
pack's KSI crosswalk silently changing between two runs of the same command, and
evidence that cannot say what it was assessed against.

A pinned snapshot makes the version an explicit, reviewable fact. It is stamped
into every `evidence-tags.json` this repository emits, so a report says which KSI
revision it was assessed against rather than "FedRAMP 20x" unqualified.

## Refreshing it

```bash
python3 tools/sync_fedramp.py --check     # diff upstream against this snapshot
python3 tools/sync_fedramp.py --update    # replace it and rewrite this file
```

`--check` is what runs in CI. Drift should surface as a failing scheduled job
rather than as a question from an assessor.

## What this file is used for

- The KSI vocabulary the generator validates `ksi:` entries against. An
  unrecognised indicator is a build failure, not a warning.
- The KSI to NIST 800-53 crosswalk. Each indicator carries its own `controls[]`,
  so **this repository does not maintain that mapping** and does not own its
  accuracy.

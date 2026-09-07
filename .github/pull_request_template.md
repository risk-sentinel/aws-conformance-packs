<!-- Reference the issue so it auto-closes on merge, e.g. "Closes #11". -->

## What this does

## Verification

<!-- What did you actually run, and what did it show? Not "should work". -->

## Checklist

- [ ] `docs/dev/Implementation_plan.md` updated — status snapshot and the phase this touches
- [ ] Issue referenced above so it closes on merge
- [ ] `python3 tools/lint_packs.py` passes locally
- [ ] New guards were negative-controlled (shown to FAIL on the defect they catch)
- [ ] No account numbers, ARNs, registry URIs, resource ids or regions in this PR's text
- [ ] No scanner finding suppressed — or, if one is, it is called out above for review as a decision

<!--
The plan-update check is enforced in CI. If this PR genuinely does not warrant a
plan update, say so explicitly by including a line of the form:

    Plan-Update: not-required — <reason>

A stated reason is the point. An unexplained skip is what the check exists to stop.
-->

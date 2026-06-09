# Waveframe Guard v0.8.0 Release Notes

## Summary

v0.8.0 introduces admissibility continuity semantics for Guard. Decisions can now carry bounded validity metadata, and Guard can emit deterministic continuity drift signals when a prior admissibility decision becomes stale or needs revalidation.

## Highlights

- Added `docs/runtime/CONTINUITY_SEMANTICS.md` as the scope boundary for admissibility continuity.
- Added `valid_until`, `revalidation_required_after`, and `continuity_signals` result metadata.
- Added deterministic signals for authority revocation, authority supersession, expired admissibility windows, and actor continuity breaks.
- Added tests covering stale admissibility and continuity signal emission.

## Scope Boundary

Guard evaluates continuity. Cloud displays continuity.

This release does not introduce orchestration, async scheduling, distributed workflow management, probabilistic scoring, or autonomous retry management.

## Verification

- `pytest`: `40 passed`
- Build artifacts:
  - `waveframe_guard-0.8.0.tar.gz`
  - `waveframe_guard-0.8.0-py3-none-any.whl`

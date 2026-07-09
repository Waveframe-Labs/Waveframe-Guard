# Waveframe Guard v0.11.0 Release Notes

## Summary

v0.11.0 makes Guard compatible with the current compiler-produced authority shape and adds the canonical local Finance Policy to Guard demo.

The demo proves the core product sentence: a company writes a policy, an AI attempts a prohibited transfer, and Guard stops the protected function before it runs.

## Highlights

- Guard now enforces `approval_requirements.thresholds` as conditional approval evidence.
- Guard now accepts list-shaped `invariants.separation_of_duties`, matching compiler output.
- Added `examples/finance_policy_to_guard_demo/` as the five-minute local product demo.
- The demo uses the public SDK path: `from waveframe_guard import Guard`, `Guard.local(...)`, and `@guard.protect(...)`.
- The demo persists SDK-local Inspector-ready artifacts under `.guard-local/`: evaluation history, receipts, manifests, and replay records.

## Scope Boundary

This release stays in Waveframe Guard. It does not expand Cloud, Ledger Workspace, or Inspector architecture.

The demo uses Governance-Ledger extraction/review plus the installed compiler locally, then hands compiled authority to Guard for enforcement. Cloud remains outside this release.

## Verification

- `python -m pytest`: `114 passed`.
- `python -m build`: built `waveframe_guard-0.11.0.tar.gz` and `waveframe_guard-0.11.0-py3-none-any.whl`.
- Wheel metadata reports `Version: 0.11.0`.

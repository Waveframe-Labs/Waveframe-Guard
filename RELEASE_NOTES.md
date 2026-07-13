# Waveframe Guard v0.12.0 Release Notes

## Summary

v0.12.0 teaches Guard that Cloud preservation exists without moving Cloud into the execution boundary.

Guard still evaluates locally, writes local evidence, and enforces before Cloud can influence anything. When configured with `Guard.local(preserve_to=...)`, Guard preserves the completed local decision package to Cloud after local evaluation history, receipt, manifest, and replay artifacts exist.

## Highlights

- Added a transport-only Cloud preservation client for `POST /v1/preserve`.
- Added optional `Guard.local(preserve_to=...)` preservation configuration.
- Added Cloud preservation packages containing saved evaluation, Guard Receipt, artifact manifest, and replay result.
- Persisted Cloud package id, receipt id, SHA-256, and timestamp metadata back into `.guard-local` evaluation history for future Inspector display.
- Hardened malformed Cloud response handling so a 2xx response is not considered preserved unless required identifiers are present.
- Added invariant coverage proving Cloud failures cannot alter local enforcement status, outcome hash, execution behavior, value, rationale, receipt, manifest, or replay.

## Scope Boundary

This release stays in Waveframe Guard. It does not build Cloud and does not move Cloud into runtime admissibility.

Cloud preservation metadata is a post-decision durability annotation. The original Guard Receipt and artifact manifest remain immutable local decision evidence and are not regenerated after Cloud replies.

## Verification

- `python -m pytest -q`: `138 passed`.
- `python -m build`: built `waveframe_guard-0.12.0.tar.gz` and `waveframe_guard-0.12.0-py3-none-any.whl`.
- Wheel metadata reports `Version: 0.12.0`.

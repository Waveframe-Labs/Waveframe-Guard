# Waveframe Guard v0.9.0 Release Notes

## Summary

v0.9.0 stabilizes Guard as a local execution governance product surface:
Guard SDK, deterministic runtime evaluation, Guard Inspector, replay artifacts,
continuation governance, and deferred release enforcement.

This release also prepares the repository for a future product split by making
public and non-production surfaces explicit.

## Highlights

- Added Guard SDK primary-path documentation for `.guard-local` evaluation and receipt emission.
- Positioned Guard Inspector as a local evaluation and receipt inspection surface, not a policy authoring UI.
- Added deferred release enforcement docs for continuation leases, release validations, and release-blocked outcomes.
- Added persistent organizational runtime docs for local SQLite state, export/import, corruption recovery, and cleanup.
- Tiered docs into getting-started, architecture, runtime, and governance folders.
- Split examples into SDK, integration, and runtime folders.
- Moved benchmark tooling under `tools/benchmarks/`.
- Quarantined non-production Cloud lab code under `temp/labs/cloud_runtime/`.

## Scope Boundary

Guard evaluates runtime admissibility locally against compiled authority.
Guard never derives governance meaning from raw policy text.

Cloud remains a future production surface. Local Guard does not implement
managed tenancy, fleet-wide audit, policy publishing, hosted orchestration, or
centralized compliance exports.

## Verification

- `python -m pytest`: `104 passed`
- `python -m py_compile guard\sdk\execution.py guard\sdk\local_persistence.py guard\sdk\adapters.py guard\sdk\cleanup_local.py server\local_api.py guard\runtime\organization.py`: passed

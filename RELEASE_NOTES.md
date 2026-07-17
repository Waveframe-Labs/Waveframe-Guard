# Waveframe Guard v0.13.0 Release Notes

## Summary

v0.13.0 teaches Guard to consume verified Published Authorities.

Applications can now start from a deterministic authority reference:

```python
guard = Guard.local(authority="finance-policy@1.0.0")
```

Guard resolves the current registry entry, verifies the Ledger `authority_bundle.v1`, extracts the compiled authority contract, and then passes that contract into the existing enforcement pipeline. CRI-CORE and Guard's local enforcement behavior remain unchanged.

## Highlights

- Added canonical Published Authority loading through `load_authority("name@x.y.z")`.
- Added `Guard.local(authority="name@x.y.z")` for SDK construction from a published authority reference.
- Added local and memory authority resolvers behind a narrow `AuthorityResolver` boundary.
- Added resolver dependency injection for tests and embedded applications.
- Added `MemoryAuthorityCache`, keyed by immutable identity: `authority_ref + bundle_hash`.
- Kept legacy `contract=...`, `authorities={...}`, and `authority_loader=...` paths available for compatibility.

## Trust Hardening

- Verifies local registry `registry_hash` before trusting registry entries.
- Requires explicit `name@x.y.z` authority references.
- Requires canonical Ledger `authority_bundle.v1` structure.
- Requires bundle-level `authority_ref`, `contract_hash`, and `authority_contract`.
- Verifies registry, bundle, nested contract, and computed canonical contract hashes.
- Rejects duplicate local registry identities.
- Rejects ambiguous Guard authority-source inputs.
- Revalidates current lifecycle state on authority-cache hits so revoked or superseded authority cannot stay loadable through cache reuse.

## Scope Boundary

This release does not change runtime admissibility semantics and does not move Cloud, Ledger, or registry layout concerns into the enforcement pipeline.

Resolver implementations decide where the authority is. The verifier decides whether the authority is trustworthy. The enforcement pipeline continues to consume a compiled authority contract.

## Verification

- `python -m pytest`: `194 passed`.
- `python -m build`: built `waveframe_guard-0.13.0.tar.gz` and `waveframe_guard-0.13.0-py3-none-any.whl`.
- `twine check dist/waveframe_guard-0.13.0*`: source distribution and wheel pass.
- Wheel metadata reports `Version: 0.13.0`.
- Clean wheel-only installation succeeds.
- Installed package reports `0.13.0`.
- Published authority loads correctly from `authority_bundle.v1`.
- Wheel smoke returns `executed=False`, `blocked`.

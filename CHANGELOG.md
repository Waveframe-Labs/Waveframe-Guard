# Changelog

## [0.4.0] - Governed Runtime

### Added
- `GovernedRuntime` for registry-based contract lookup and guarded execution
- Runtime context binding with `install_actor()` and `bind_contract()`
- Function-bound execution with `runtime.execute(fn=...)`
- Proposal-bound execution with `runtime.execute_proposal(...)`
- `GovernedExecutionResult` for observable allow/block outcomes
- Structured runtime audit events with in-memory access through `last_event` and `audit_events`
- Optional local JSONL audit event emission via `audit_path`
- Example governed runtime usage and sample `contracts/index.json` registry

### Notes
- Guard remains SDK-local by default; runtime audit emission does not require Cloud, databases, or external telemetry infrastructure
- Existing `install_guard()` and `@guard` execution paths remain supported

## [0.3.1] — Contract Loader Public Surface

### Added
- Top-level `load_contract` export
- Published `finance-core-0.3.1.contract.json` contract artifact

### Changed
- Bumped package, SDK, citation, Cloud preview, docs, examples, and test metadata to `0.3.1`

## [0.3.0] — Execution Hardening & Cloud Fallback

### Added
- Policy caching with TTL
- Fail modes: `cache`, `open`, `closed`
- Circuit breaker for Cloud outages
- Async decision logging to Cloud
- Actor auto-discovery fallback
- Runtime loading from published contract artifacts via `contract_path`
- Contract metadata exposure in runtime context

### Improved
- Deterministic contract validation via canonical hashing
- Cached policy integrity verification
- Clear governance error messages
- SDK-first documentation and examples

### Fixed
- Cache integrity vulnerability (body tampering detection)
- Cloud policy validation before caching
- Mutable ContextVar default leak
- Fail-open path missing unverified warning
- Missing API key ambiguity in cloud mode

### Notes
- Guard enforces locally and does not depend on Cloud at runtime
- Decisions may be marked as **unverified** when Cloud is unavailable

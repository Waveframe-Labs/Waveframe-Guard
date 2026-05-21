# Changelog

## [0.7.0] - Cloud Evidence Runtime

### Added
- Added `GuardRuntime.from_cloud(...)` as a developer-friendly alias for local-first Cloud-connected runtime setup.
- Added durable local evidence spooling under `pending/`, `sent/`, and `failed/` with explicit `flush_evidence()`.
- Added SDK-local runtime diagnostics for authority resolution, revoked authority rejection, lineage validation failures, and admissibility evaluation lifecycle.

### Changed
- Updated package, SDK, citation, README, and Cloud preview metadata for the v0.7.0 release.
- Aligned experimental Cloud demo contracts with the canonical `1.0.0` sample authority version.
- Modernized package license metadata to avoid setuptools deprecation warnings.

### Verified
- Full Guard suite passes: `35 passed`.
- Build produces `waveframe_guard-0.7.0.tar.gz` and `waveframe_guard-0.7.0-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.7.0`.

## [0.6.1] - Runtime Lifecycle Patch

### Fixed
- Fixed runtime lifecycle validation ordering for revoked and superseded authorities.
- Fixed test isolation issues caused by site-packages import precedence during pytest collection.
- Added explicit Guard context reset between tests.
- Added repository-local import enforcement in test configuration.

### Reliability
- Revoked-authority validation is now consistently enforced before admissibility evaluation.
- Superseded-authority warnings now behave consistently across full-suite execution.
- Runtime lifecycle semantics verified under isolated and full-suite test execution.

### Verified
- Full Guard suite passes: `34 passed`.
- Build produces `waveframe_guard-0.6.1.tar.gz` and `waveframe_guard-0.6.1-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.6.1`.

## [0.6.0] - Authority Lifecycle Enforcement

### Added
- Added authority lifecycle validation during runtime authority resolution.
- Added `reject_revoked_authority` and `warn_on_superseded` runtime configuration flags.
- Added `authority_lifecycle` metadata to governed execution results and events when registry entries declare lifecycle state.

### Fixed
- Revoked authorities now fail before admissibility evaluation or governed execution.
- Superseded authorities now emit warning and result/event lifecycle metadata without blocking intentionally pinned versions.

### Changed
- Updated package, SDK, citation, README, and Cloud preview metadata for the v0.6.0 release.

### Verified
- Full Guard suite passes: `34 passed`.
- Build produces `waveframe_guard-0.6.0.tar.gz` and `waveframe_guard-0.6.0-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.6.0`.
- Built wheel exposes `evaluate_admissibility` from both `waveframe_guard` and `waveframe_guard.runtime`.

## [0.5.0] - Authority Ref Stabilization

### Changed
- Canonical runtime semantics now require explicit versioned authority refs such as `finance-policy@1.0.0`.
- Updated runtime tests, examples, README snippets, walkthroughs, benchmark setup, and sample Cloud metadata to use versioned authority refs.
- Updated package, SDK, citation, and Cloud preview metadata for the v0.5.0 release.
- Replaced the sample runtime registry with a versioned `finance-policy@1.0.0` entry.
- Added `contracts/finance-policy-1.0.0.contract.json` as the current sample published contract.

### Fixed
- Added a regression test for the public `evaluate_admissibility` export used by replay integrations.
- Removed stale dev-repo path assumptions from Guard tests and examples.
- Updated Cloud registry tests to use an in-repo test registry app instead of importing integration-only Cloud modules.

### Verified
- Full Guard suite passes: `32 passed`.
- Build produces `waveframe_guard-0.5.0.tar.gz` and `waveframe_guard-0.5.0-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.5.0`.
- Built wheel exposes `evaluate_admissibility` from both `waveframe_guard` and `waveframe_guard.runtime`.

## [0.4.0] - Governed Runtime

### Added
- `GovernedRuntime` for registry-based contract lookup and guarded execution.
- Runtime context binding with `install_actor()` and `bind_contract()`.
- Function-bound execution with `runtime.execute(fn=...)`.
- Proposal-bound execution with `runtime.execute_proposal(...)`.
- `GovernedExecutionResult` for observable allow/block outcomes.
- Structured runtime audit events with in-memory access through `last_event` and `audit_events`.
- Optional local JSONL audit event emission via `audit_path`.
- Example governed runtime usage and sample `contracts/index.json` registry.

### Notes
- Guard remains SDK-local by default; runtime audit emission does not require Cloud, databases, or external telemetry infrastructure.
- Existing `install_guard()` and `@guard` execution paths remain supported.

## [0.3.1] - Contract Loader Public Surface

### Added
- Top-level `load_contract` export.
- Published `finance-core-0.3.1.contract.json` contract artifact.

### Changed
- Bumped package, SDK, citation, Cloud preview, docs, examples, and test metadata to `0.3.1`.

## [0.3.0] - Execution Hardening & Cloud Fallback

### Added
- Policy caching with TTL.
- Fail modes: `cache`, `open`, `closed`.
- Circuit breaker for Cloud outages.
- Async decision logging to Cloud.
- Actor auto-discovery fallback.
- Runtime loading from published contract artifacts via `contract_path`.
- Contract metadata exposure in runtime context.

### Improved
- Deterministic contract validation via canonical hashing.
- Cached policy integrity verification.
- Clear governance error messages.
- SDK-first documentation and examples.

### Fixed
- Cache integrity vulnerability through body tampering detection.
- Cloud policy validation before caching.
- Mutable ContextVar default leak.
- Fail-open path missing unverified warning.
- Missing API key ambiguity in cloud mode.

### Notes
- Guard enforces locally and does not depend on Cloud at runtime.
- Decisions may be marked as unverified when Cloud cannot be reached.

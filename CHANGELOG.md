# Changelog

## [Unreleased]

- Add an explicit repository workspace and bound-file adapter for issue #33.
  Repository paths are validated before authority comparison; generic repository
  callbacks fail closed. Existing-file mutation currently requires local Windows
  NTFS namespace locks; POSIX mutation and creation fail closed. See the
  [workspace boundary and migration guide](docs/architecture/REPOSITORY_WORKSPACE.md).
- Recommend 0.18.0 for this integration break, including explicit domain selection
  for v1 target-scoped callers. This change does not prepare or publish a release.

## [0.17.0] - 2026-09-04 - Native Ledger v3 Authority Verification

Guard now verifies Ledger's additive multi-control and partial-coverage v3
publication envelope before enforcing its unchanged compiled v2 runtime
payload.

### Added
- Added native, receipt-required verification for Ledger
  `authority_bundle.v3` and `publication_receipt.v3`. Guard delegates complete
  normative reconstruction to Ledger before evaluating the unchanged
  `compiled_authority_contract.v2`, and v3 verification evidence identifies the
  artifact versions exactly.
- Added v3 cache integrity, revalidation, drift, substitution, and runtime-fact
  acceptance coverage, including multi-control and partial-coverage
  publications that require no translation proposal or private provider
  evidence at runtime.

### Compatibility
- Widened the base Ledger dependency to `governance-ledger>=0.7.0,<0.9.0`
  after exercising the exact Ledger 0.8 development candidate through normal
  dependency resolution, the complete Guard suite, packaging, and clean-wheel
  acceptance. Ledger 0.7.0 remains the minimum compatibility baseline.
- Guard continues to verify `compiled_authority_contract.v2`,
  `authority_bundle.v2`, and `publication_receipt.v2` independently. Translation
  proposals, human review records, and private provider evidence are not Guard
  runtime inputs.
- Guard 0.17.0 remains compatible with Ledger `>=0.7.0,<0.9.0`. Ledger 0.7
  continues to support existing v1/v2 authority; native v3 verification
  requires Ledger 0.8 or later, and supplying v3 with Ledger 0.7 fails closed
  with an explicit Ledger 0.8 requirement.

### Limitations
- Guard continues to evaluate `compiled_authority_contract.v2` after the
  complete v3 bundle and receipt pass validation. Guard 0.17.0 can parse and
  verify matching v2 and v3 publication envelopes. Current released/hosted
  Cloud does not yet serve the complete atomic v2 or v3 publication path. Cloud
  PR #133 remains the pending v2 server implementation. Hosted v3 serving
  requires an additional Cloud update.
- Guard does not call, integrate, or depend on an AI or model provider. Policy
  translation proposals and private provider evidence are not runtime inputs.

### References
- Releases issue #27 / PR #28.

## [0.16.1] - 2026-09-01 - Cloud v2 Publication Resolver

Guard can now retrieve one atomic Ledger v2 publication from Cloud and verify
it before enforcing any action.

### Added
- Added an authenticated, tenant-bound `cloud_authority_publication.v1` resolver
  protocol at `GET /v1/authorities/{authority_ref}/publication`. Atomic Ledger
  v2 bundle, receipt, logical-reference, registry, and envelope bindings flow
  through Guard's existing verifier and verified cache without application-facing
  facts, hashes, bundles, or Ledger-validator calls.
- Added `runtime_credential=` as an alias for the existing Cloud API-key
  credential. Existing organization and API-key authentication is unchanged.

### Hardened
- Added strict envelope fields and canonical bindings, duplicate-key rejection,
  encoded and decompressed 8 MiB limits, bounded gzip handling, redirect
  rejection, opaque logical-reference validation, safe status mapping, and a
  narrow explicit 404-only fallback to the unchanged legacy v1 contract path.
- Contract-only v2 responses still fail closed, and authority, tenant,
  registry, bundle, receipt, contract, domain-pack, runtime-schema, Constraint
  IR, mapping, and hash substitutions cannot activate an authority.
- A cold resolution performs one publication request and full verification.
  Warm evaluation performs no additional request or heavy Ledger validation.

### Compatibility
- `Guard.cloud(...)`, Cloud headers, v1 endpoint behavior, finance behavior,
  local resolvers, caching, and enforcement semantics remain compatible. The
  `runtime_credential=` spelling is additive; no new argument is required.
- Existing v1, finance, local-resolver, and Guard 0.16 behavior remains
  compatible.
- Current released Cloud does not expose the additive publication endpoint.
  Cloud PR #133 is the follow-on implementation. This release provides the
  client/protocol boundary and does not claim hosted availability.

### Limitations
- Native v2 runtime facts remain repository-change only. Guard does not
  interpret policy prose, and no AI or heuristic inference is involved.

### References
- Releases issue #22 / PR #23.

## [0.16.0] - 2026-09-01 - Verified Ledger Authority Enforcement

Guard verifies the exact Ledger-published authority, derives only
schema-approved runtime facts, and binds every decision to immutable evidence.

### Added
- Added native, provenance-complete Ledger v0.7 `authority_bundle.v2` and
  `publication_receipt.v2` loading for `repository-changes/1.0.0`.
- Added a deterministic fact-provider boundary keyed by the exact published
  domain-pack and runtime-fact-schema identities and hashes.
- Added compact authority/fact evidence bindings and a Guard-owned execution
  attestation that distinguishes decision, callback invocation/completion,
  execution outcome, and known/unknown mutation state without changing the
  existing Cloud preservation protocol.

### Hardened
- V2 contracts now require successful public Ledger bundle, receipt, and
  runtime-fact compatibility validation before use or caching.
- Cold load, refresh, untrusted serialized-cache recovery, and suspected drift
  run Ledger's complete validators. Warm process-local cache reads and governed
  actions use an immutable verified runtime projection plus a compact integrity
  check, while still rejecting contract drift and cross-authority substitution.
- Missing, mistyped, unsupported, or caller-supplied runtime facts fail closed
  before callback execution. Unrelated proposal metadata is ignored and cannot
  affect either decisions or the canonical derived-fact hash.
- Registry artifact locations are validated portable POSIX logical references;
  machine- and tenant-specific physical storage paths are not evidence inputs.

### Compatibility
- The base `governance-ledger>=0.7.0,<0.8.0` package is a runtime dependency.
  Guard tests the public 0.7.0 minimum; immutable v2 artifact schema dispatch is
  the validation boundary within the compatible 0.7 release line. Guard never
  depends on `governance-ledger[guard]`, and the v1 loading and evaluation paths
  remain backward compatible.

## [0.15.0] - 2026-08-21 - Deterministic Target Enforcement

### Added
- Enforced compiler-defined exact and prefix target requirements locally before
  callback execution. Matching is literal and case-sensitive, and deny rules
  take precedence over allow rules.
- Failed closed for malformed target scope and for missing or invalid targets
  when target scope is declared, while retaining legacy target-free authority
  decisions and evidence unchanged.
- Preserved target differentiation for the same actor and published authority:
  an allowed `README.md` mutation runs once, while a denied
  `deployment/production.example.yml` mutation never runs.
- Added `preservation_timeout_seconds`, with a 10.0-second default, exclusively
  for `POST /v1/preserve`. A timeout is ambiguous, does not retry blindly, and
  never changes local enforcement or callback behavior.

### Compatibility
- CRI-CORE Contract Compiler v0.4.0 defines deterministic target requirements;
  Guard v0.15.0 consumes and enforces compiled authority artifacts without a
  compiler runtime dependency.
- Waveframe Cloud v0.5.5 remains compatible and unchanged.

### References
- Closes #12 and #14 via PRs #13 and #15.
- References Waveframe-Labs/Waveframe-Cloud#109.

## [0.14.0] - 2026-08-10 - External Agent Integration

### Added
- Added organization-scoped Cloud preservation credentials through explicit `Guard.local()` configuration or `WAVEFRAME_CLOUD_ORGANIZATION_ID` and `WAVEFRAME_CLOUD_API_KEY`.
- Added provider-neutral `Guard.tool(...)` wrappers for protecting existing agent tool functions without requiring Guard-shaped model output or an Ollama dependency.
- Added `Guard.cloud(authority=...)` for fetching a published, versioned authority from hosted Cloud and preserving evidence without a Waveframe repository checkout.
- Added optional agent framework, model provider, and model metadata to protected tool evidence while keeping agent identity and authority selection independent.
- Added hosted runtime registration, initial and on-demand heartbeats, and post-execution result attestations to the provider-neutral `Guard.cloud(...)` path.
- Added a pip-installed external-agent quickstart that proves one allowed action, one blocked action, exactly one underlying mutation, two Cloud preservation receipts and proofs, and two runtime attestations without requiring Ollama, an agent framework, or a Waveframe checkout.

### Hardened
- Cloud organization and API-key credentials are transmitted only as request headers and are excluded from preservation packages and saved local evidence.
- Partial Cloud credential configuration now fails before an HTTP request is attempted.
- Cloud authority responses are validated as compiled authority, matched to the requested identity, and cryptographically rehashed before Guard accepts them.
- Agent tool arguments are excluded from evidence by default and must be explicitly selected for preservation.
- Runtime lifecycle and result reporting are observational: Cloud failures cannot alter local admissibility, execute a blocked callback, run an allowed callback twice, or mask an application exception.
- Callback failure attestations record only the exception type and never transmit application exception text.
- External-agent acceptance now fails with sanitized, action-specific HTTP status, error type, and Cloud response diagnostics unless runtime reporting, both preservation receipts/proofs, and both execution attestations succeed.
- Saved evaluation records now deep-copy live inputs and evaluation data before hashing so later result decoration cannot invalidate the preservation package's `record_hash`.

### Compatibility
- Hosted runtime credentials must be authorized to read the canonical `compiled_authority_contract.v1` selected by `authority`; Guard does not evaluate Cloud's separate governance-compatibility projection as policy.
- Declared Python support now starts at 3.10, matching the pinned Ledger 0.5.0 compatibility dependency used by Guard's release test environment.

### Verified
- Focused external-agent and Cloud-client tests: `41 passed`.
- `python -m pytest`: `226 passed` in the dependency-complete Python 3.14 environment.
- `python -m build`: built `waveframe_guard-0.14.0.tar.gz` and `waveframe_guard-0.14.0-py3-none-any.whl`.
- `python -m twine check dist/*`: source distribution and wheel passed.
- Fresh wheel-only installation outside the repository reported public and package metadata version `0.14.0` with no source-tree import shadowing.
- External-agent clean-machine acceptance passed all expected markers with two preservation and two attestation requests.

## [0.13.0] - Published Authority Consumption

### Added
- Added canonical Published Authority loading through `load_authority("name@x.y.z")`.
- Added local and memory authority resolvers behind the shared `AuthorityResolver` boundary.
- Added resolver dependency injection for authority loading and Guard SDK construction.
- Added `Guard.local(authority="name@x.y.z")` so applications can consume a published authority reference directly.
- Added `MemoryAuthorityCache` keyed by immutable authority identity: `authority_ref + bundle_hash`.

### Hardened
- Added local registry `registry_hash` verification before registry entries are trusted.
- Added canonical Ledger `authority_bundle.v1` verification with required `authority_ref`, `contract_hash`, and `authority_contract` fields.
- Added contract and bundle hash verification across registry entries, authority bundles, nested authority contracts, and computed canonical hashes.
- Added current lifecycle revalidation on cache hits so revoked or superseded authority cannot remain loadable through cache reuse.
- Added duplicate local registry identity rejection.
- Added ambiguous authority-source rejection for conflicting `authority`, `contract`, resolver, and authority map inputs.
- Added strict explicit authority references requiring deterministic `name@x.y.z` identifiers.

### Compatibility
- Legacy `contract=...`, `authorities={...}`, and `authority_loader=...` Guard SDK paths remain available.
- CRI-CORE and the existing enforcement pipeline remain unchanged.

### Verified
- `python -m pytest`: `194 passed`.
- `python -m build`: built `waveframe_guard-0.13.0.tar.gz` and `waveframe_guard-0.13.0-py3-none-any.whl`.
- Wheel metadata reports `Version: 0.13.0`.
- Fresh-environment installation and import smoke test reports `waveframe_guard.__version__ == 0.13.0`, package metadata `0.13.0`, and `Guard` import availability.

## [0.12.0] - Cloud Preservation Runtime

### Added
- Added a transport-only Cloud preservation client for `POST /v1/preserve` with timeout handling and graceful failure results.
- Added optional `Guard.local(preserve_to=...)` runtime configuration that preserves local Guard decision packages after local evidence artifacts are written.
- Added `guard_cloud_preservation_package.v1` payloads containing the saved evaluation, Guard Receipt, artifact manifest, and replay result.
- Added `guard_cloud_preservation_metadata.v1` annotations on saved local evaluations so Inspector can display Cloud package, receipt, hash, and timestamp metadata.

### Changed
- Bumped package metadata, citation metadata, security support line, README install guidance, quickstart metadata, and public version exports to `0.12.0`.
- Documented Cloud preservation metadata as a post-decision durability annotation, not part of the original immutable Guard Receipt or artifact manifest.

### Hardened
- Cloud preservation success now requires `package_id`, `receipt_id`, `sha256`, and `timestamp`; malformed 2xx responses return `ok=False` with `invalid_response`.
- Preservation runs only after local evaluation history, receipt, manifest, and replay artifacts exist.
- Cloud failures are isolated to `result["cloud_preservation"]` and cannot change enforcement status, outcome, execution behavior, value, rationale, or outcome hash.
- Local history enrichment recalculates the enriched record hash, preserves unrelated records and ordering, and rejects conflicting Cloud metadata instead of silently replacing evidence lineage.

### Verified
- `python -m pytest -q`: `138 passed`.
- `python -m build`: built `waveframe_guard-0.12.0.tar.gz` and `waveframe_guard-0.12.0-py3-none-any.whl`.
- Wheel metadata reports `Version: 0.12.0`.

## [0.11.0] - Compiler Compatibility and Flagship Demo

### Added
- Added the canonical Finance Policy to Guard demo showing local policy review, compiled authority publication, a blocked $2M transfer, an allowed CFO-approved retry, and persisted Guard SDK evidence under `.guard-local`.

### Changed
- Bumped package metadata, citation metadata, security support line, README install guidance, quickstart metadata, and public version exports to `0.11.0`.

### Fixed
- Fixed Guard compatibility with compiler-produced contracts by enforcing `approval_requirements.thresholds` as conditional approval evidence and accepting list-shaped `invariants.separation_of_duties`.

### Verified
- `python -m pytest`: `114 passed`.
- `python -m build`: built `waveframe_guard-0.11.0.tar.gz` and `waveframe_guard-0.11.0-py3-none-any.whl`.
- Wheel metadata reports `Version: 0.11.0`.

## [0.10.0] - Developer Path Freeze

### Added
- Added `Guard` as a top-level public export from `waveframe_guard` so the canonical SDK path is `from waveframe_guard import Guard`.
- Added a focused 30-second README example showing local allow/block behavior with a compiled authority and normalized execution request.
- Added `examples/quickstart_guard.py` as a runnable SDK quickstart that prints the local Guard execution decision.
- Added explicit release-discipline documentation for code, docs, changelog, package metadata, tests, build artifacts, tags, and PyPI release readiness.
- Added `waveframe_guard.server.local_api` as the stable package-qualified boundary for Guard local API tests and runtime inspection helpers.
- Added a dependency-boundary regression test that fails if Guard imports the bare `server` package again.

### Changed
- Reframed the README around the single adoption path: install Guard, wrap the action, and receive an allowed or blocked outcome before execution.
- Clarified the product boundary between Guard, Cloud, Ledger / Workspace, and CRI-CORE.
- Relaxed the Guard/Inspector documentation test to validate the package and semantics boundary instead of requiring one exact marketing sentence.
- Bumped package metadata, citation metadata, security support line, and public version exports to `0.10.0`.
- Updated package description and keywords around execution-boundary enforcement and agent safety.
- Updated Guard local API tests to import `from waveframe_guard.server import local_api` instead of relying on an ambiguous bare `server` package.

### Fixed
- Fixed a cross-repository import collision where local Guard tests could import `server` from `waveframe-ledger-workspace` when multiple Waveframe repositories were checked out side by side.

### Compatibility
- Existing `install_guard`, `guard`, `GovernedRuntime`, `GuardRuntime`, and `evaluate_admissibility` exports remain available.
- `from guard.sdk import Guard` remains available; `from waveframe_guard import Guard` is now the preferred public import.

### Verified
- `python -m pytest -q`: `108 passed`.
- `python examples/quickstart_guard.py`: `executed=False`, `decision=blocked`.
- `python -c "import waveframe_guard, importlib.metadata as m; print(waveframe_guard.__version__); print(m.version('waveframe-guard'))"`: `0.10.0`, `0.10.0`.

## [0.9.0] - Guard Runtime Checkpoint

### Added
- Added Guard SDK primary-path documentation for local `.guard-local` evaluation and receipt emission.
- Added Guard Inspector positioning as a local evaluation/receipt inspection surface, not policy authoring.
- Added deferred release enforcement documentation covering continuation leases, release validations, and release-blocked outcomes.
- Added persistent organizational runtime checkpoint documentation for local SQLite state, export/import, corruption recovery, and cleanup.
- Added local-to-Cloud lifecycle boundary documentation.

### Changed
- Clarified that Guard evaluates runtime admissibility locally against compiled authority.
- Clarified that Cloud owns managed organization lifecycle, centralized lineage, fleet-wide audit, policy publishing, and compliance exports.
- Kept Cloud outside Guard runtime admissibility and governance meaning derivation.
- Tiered docs into getting-started, architecture, runtime, and governance folders.
- Split examples into SDK, integration, and runtime folders.
- Quarantined non-production Cloud lab code under `temp/labs/cloud_runtime/`.
- Moved benchmark tooling under `tools/benchmarks/`.

### Verified
- Full Guard suite passes: `104 passed`.
- Checkpoint scan compiles Guard SDK, local API, and persistent runtime modules with `python -m py_compile`.

## [0.8.0] - Admissibility Continuity Semantics

### Added
- Added `docs/runtime/CONTINUITY_SEMANTICS.md` to define admissibility windows, deterministic revalidation, continuity drift signals, and explicit non-goals.
- Added runtime continuity metadata: `valid_until`, `revalidation_required_after`, and `continuity_signals`.
- Added minimal runtime evaluation and deterministic continuity revalidation support for delayed or resumed execution checks.
- Added deterministic continuity signals for expired admissibility windows, revoked authorities after decision, superseded authorities during resumed execution, and actor continuity breaks.
- Added focused tests for admissibility window expiration, stale admissibility detection, lifecycle drift, actor continuity drift, and continuity signal emission.

### Changed
- Bumped package, SDK, citation, README, Cloud preview, and security metadata for the v0.8.0 release.
- Documented the Guard/Cloud boundary for continuity: Guard evaluates continuity; Cloud displays continuity.

### Non-Goals
- No orchestration engine.
- No async scheduler.
- No distributed workflow management.
- No probabilistic scoring.
- No autonomous retry management.

### Verified
- Full Guard suite passes: `40 passed`.
- Build produces `waveframe_guard-0.8.0.tar.gz` and `waveframe_guard-0.8.0-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.8.0`.

## [0.7.1] - Release Metadata Normalization

### Changed
- Normalized package, SDK, citation, README, Cloud preview, and security metadata for the v0.7.1 release.
- Kept the Cloud evidence runtime behavior and canonical `finance-policy@1.0.0` sample authority contract unchanged.

### Verified
- Full Guard suite passes: `35 passed`.
- Build produces `waveframe_guard-0.7.1.tar.gz` and `waveframe_guard-0.7.1-py3-none-any.whl`.
- Built wheel metadata reports `Version: 0.7.1`.

## [0.7.0] - Cloud Evidence Runtime

### Added
- Added `GuardRuntime.from_cloud(...)` as a developer-friendly alias for local-first Cloud-connected runtime setup.
- Added durable local evidence spooling under `pending/`, `sent/`, and `failed` with explicit `flush_evidence()`.
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

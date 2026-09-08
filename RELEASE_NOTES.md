# Waveframe Guard v0.18.0 Release Notes

Release date: **2026-09-08**. **Prepared release; publication is pending.**
This release collects already merged work from #30, #31, #32, #33 and #39.
Release preparation adds no enforcement behavior, public API or schema change.

## Highlights

- **Repository-bound mediated mutation.** `Guard.local()` and `Guard.cloud()`
  with `repository_root` support `repository_tool` callbacks receiving an
  expiring `RepositoryTarget`. Canonical repository-relative paths, target
  identity and adapter provenance bind the supported existing-file operation.
  Noncanonical paths, aliases, indirection and workspace escapes are rejected.
- **Verifiable decision and execution/mutation attestations.** Existing
  `guard_execution_attestation.v2` records identify the mediated action, target
  binding, adapter/assurance class, authority basis, decision and callback or
  mutation outcome. Evidence reload and integrity verification retain their
  existing meanings; schema identifiers are unchanged.
- **Fail-closed legacy API migration.** All 11 retained legacy execution and
  permission entrypoints reject before callbacks, with zero allowed events.
  Modern local and Cloud APIs remain supported.
- **Bounded runtime dependencies.** Every direct runtime dependency has a
  reviewed lower and upper bound. Widening an upper bound requires a future
  Guard change and compatibility evidence.
- **Apache-2.0 Guard Core distribution.** 0.18.0 is the first package release
  under Apache License 2.0. Commercial use, modification, redistribution, and
  hosting of the Guard Core SDK are permitted under Apache-2.0. Prior tagged
  and PyPI releases are not retroactively relicensed. The license grants no
  rights to Waveframe trademarks. Separately distributed Waveframe Cloud,
  Console, hosted translation, managed evidence operations, Guard Inspector,
  Ledger Workspace, enterprise identity/integrations, support and other
  commercial products/services are not relicensed by this repository. See
  [licensing scope](docs/LICENSING.md).
- **Explicit mediation and bypass boundary.** Canonical packaged documentation
  includes the threat model, least-privilege deployment and operator checks.
  A connected runtime means a specific Guard integration is reporting.
  Connection does not establish global control of the repository or machine,
  or of the agent or organization.

## Migration requirements

1. Repository callers use `Guard.local()` / `Guard.cloud()` with
   `repository_root`, and wrap their mutation callable with `repository_tool`.
   Use the documented `RepositoryTarget` operations during the callback;
   retained targets expire when that callback ends.
2. Untyped v1 literal-target callers explicitly select `target_domain="literal"`.
   Generic callbacks do not provide repository mutation assurance.
3. Retained legacy `execute`, `@guard`, `evaluate_admissibility`, and
   `GovernedRuntime` / `GuardRuntime` execution or permission entrypoints no
   longer execute. They raise `LegacyExecutionError` with code
   `GUARD_LEGACY_EXECUTION_UNSUPPORTED`; `fail_mode="open"` does not enable them.

Follow the [strict-execution migration guide](docs/getting-started/STRICT_EXECUTION_MIGRATION.md)
and [repository-workspace migration guide](docs/architecture/REPOSITORY_WORKSPACE.md).
The [quickstart](docs/getting-started/README.md) shows the modern integration.

## Truthful limitations

Guard enforces actions that pass through its wrapped tool boundary. Actions
that reach the same capability through another function, tool, process,
credential, or API path are outside that enforcement guarantee.

- Registration does not remove access to the original callable. Direct
  filesystem/API/shell/subprocess paths and underlying credentials can bypass
  Guard. Expose wrapped tools and independently restrict alternate paths using
  the [deployment and operator guidance](docs/architecture/REPOSITORY_WORKSPACE.md#least-privilege-deployment).
- Guard is trusted in-process mediation, not a sandbox or tamper-resistant
  reference monitor. Privileged operators, in-process tampering and independent
  concurrent writers remain outside its isolation guarantee. Evidence of a
  mediated call does not prove that no alternate path was used.
- Repository mutation is limited to the documented Linux descriptor and local
  Windows NTFS handle implementations and supported existing-file operations.
  Creation, rename, deletion, macOS mutation and unsupported filesystems fail
  closed. See the canonical guide for the exact OS/filesystem prerequisites.
- Post-callback substitution detection cannot undo bytes already written.
  Failed post-checks can leave an unknown physical mutation outcome.
- Replay reproduces the logical decision, not physical mutation. Cloud decision
  preservation is not the local final mutation attestation.
- This release does not claim the hosted Cloud translation workflow or
  real-repository end-to-end acceptance is released or deployed. Disposable
  installed-wheel acceptance does not substitute for that operator acceptance.

## Dependency compatibility matrix

| Component | Declared range | Supported validation baseline |
| --- | --- | --- |
| Guard | 0.18.0 release candidate | Python 3.10 minimum; Python 3.14 current, native Linux/Windows |
| CRI-CORE | `>=0.13.0,<0.15.0` | Published 0.13.0; exact 0.14.0 candidate from [CRI PR #5](https://github.com/Waveframe-Labs/CRI-CORE/pull/5), commit `411dfaa976fd4b37efc5fd3e39076edcd3603e1b` |
| Proposal Normalizer | `>=0.2.0,<0.3.0` | Published 0.2.0 |
| Governance Ledger | `>=0.7.0,<0.9.0` | Published 0.7.0: existing v1/v2; published 0.8.0: v1/v2 plus native v3 |
| requests | `>=2.33.0,<3.0.0` | Published 2.33.0 minimum; 2.34.2 current validation |

The public package does not pin transitive dependencies. Ordinary installation
uses published dependencies and works with CRI 0.13.0; the unpublished exact
CRI candidate is a separate compatibility test, not an installation requirement.
Ledger 0.7 rejects native v3 with an explicit Ledger 0.8 requirement.

**Guard 0.18 must be publishable and published before CRI-CORE 0.14.0.**
Published Guard 0.17.0 has an unbounded CRI dependency and must not be paired
with CRI 0.14. No CRI implementation change or publication is part of this PR.

After 0.18.0 publication:

```text
pip install waveframe-guard==0.18.0
```

During release review, install the built 0.18.0 wheel instead. See the
[getting-started compatibility matrix](docs/getting-started/README.md#dependency-compatibility-matrix).

## Cloud availability and release gates

Guard 0.18.0 can parse and verify matching v2 and v3 publication envelopes.
Current released/hosted Cloud does not yet serve the complete atomic v2 or v3
publication path. Cloud PR #133 remains the pending v2 server implementation.
Hosted v3 serving requires an additional Cloud update. Cloud status-copy
follow-up remains Cloud #122; a connection reports one integration.

Guard #30, #31, #32 and #39 remain open until the release is merged and PyPI
publication plus external-install verification pass. Guard #33 additionally
requires real-repository end-to-end acceptance. All five issues remain open
during this release preparation.

This draft PR does not merge, tag, create a GitHub release, upload to PyPI,
deploy Cloud or modify another repository.

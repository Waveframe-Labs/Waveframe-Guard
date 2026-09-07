# Issue #39 execution surface audit

Base: `origin/main` at `d922390fe4fe1c42d151044f7ee6fa45a657b465`.
Baseline on Windows / Python 3.14, CRI 0.13.0, Ledger 0.8.0:
**650 passed, 19 skipped**. The tracked worktree and untracked file inventory
were clean before branching; existing ignored artifacts were retained.

## Complete active/public surface inventory

Searched both shipped packages (`guard/`, `waveframe_guard/`), exports,
examples and tests for `evaluate_structured`, `run_execution_pipeline`,
`mode="local"`, `run_context`, `commit_allowed`, `fail_mode`, and callback
invocations after decisions. The quarantined `temp/` tree is not shipped.

| Surface | Before | Remediation / finding |
| --- | --- | --- |
| `waveframe_guard.execute.execute` (package export) | Omitted CRI argument mode; context mode came from local/cloud configuration. Local selected advisory without integrity/publication evidence. | Unconditional migration error before resolution, evaluation, callbacks or events. |
| `waveframe_guard.guard.guard` (package decorator export) | Delegated to `execute`; same defect. | Symbol retained; invocation reaches the migration error. |
| Legacy `fail_mode="open"` | Cloud/policy failure could invoke callback and send `commit_allowed=True` without policy. | Execution rejects before resolution; private no-policy resolver also always raises. |
| `GovernedRuntime.execute_proposal` | Omitted CRI argument mode, forced context `local`, returned allowed with event/receipt. | Unconditional migration error; both CRI execution calls removed. |
| `GovernedRuntime.execute` | Delegated to legacy `execute`, **or directly invoked callback after approval-only checking**. | Both branches removed and replaced by migration error. Additional affected execution path beyond the two reported calls. |
| `GovernedRuntime.evaluate`, `.revalidate` | Returned `allowed` from approval-only checking or prior/supplied state, without full enforcement. | Permission-returning legacy methods also raise migration error. |
| `evaluate_admissibility` (module and package export) | Approval-only dictionary could report `allowed=True`, including for an empty contract. | Retained symbol raises migration error. |
| `GuardRuntime`, `.from_cloud` | Alias/factory for the same legacy class, including cached/offline instances. | Alias/factory retained; execution and permission methods reject. |
| `Guard.local/cloud`, `.tool`, `.protect`, `.repository_tool`, `GuardRuntimeBoundary.execute/execute_repository/decorator`, callable/agent/queue/webhook/HTTP adapters | Current Guard authority intake/fact derivation, enforcement and callback boundary. No CRI evaluator/pipeline invocation. | No shared advisory/fail-open defect found; behavior unchanged. Repository capability remains required for mutation. |
| `guard.runtime.evaluate_runtime`, organizational runtime, local API, projection/cognition/continuation helpers | Guard evaluation/projection, persistence or continuation state; no CRI advisory evaluation. | Unchanged. |
| `guard.adapters.upstream_semantics` | Imports/returns optional upstream modules for availability; no CRI execution call. | Unchanged. |
| Legacy result/schema/registry/evidence helpers | Read/validate historical data or resolve authority; not a public callback authorization boundary. | Retained; historical data is not new permission. |

Modern Cloud's publication-unavailable v1 fallback still resolves a compiled
authority and passes through the current boundary. Modern preservation failures
annotate an already governed decision; they do not bypass authority enforcement.
No modern network-failure change was needed. No CRI-CORE, Cloud, Ledger,
Compiler or Normalizer repository was modified.

## Reproducible evidence

Run `python -m tools.security.reproduce_issue39` from this checkout. The script
only increments an in-memory counter and uses a temporary local registry. To
repeat the base result, use the same script with Guard imported from the exact
base in an isolated checkout. No callback performs external work.

On the base with CRI 0.13.0:

```text
strict_control_allowed=false
strict_control_failed_stages=integrity, integrity-finalization, publication, publication-commit
execute_result=callback completed
callback_count=1
execute_proposal_allowed=true
runtime_allowed_events=1
```

After remediation with the same inputs:

```text
strict_control_allowed=false
strict_control_failed_stages=integrity, integrity-finalization, publication, publication-commit
execute_error=GUARD_LEGACY_EXECUTION_UNSUPPORTED
callback_count=0
execute_proposal_error=GUARD_LEGACY_EXECUTION_UNSUPPORTED
runtime_allowed_events=0
```

Full errors explain the missing strict execution evidence and direct callers to
`Guard.local()` / `Guard.cloud()` and guarded tools. Rejected calls emit neither
an allowed event nor a blocked execution receipt pretending evaluation occurred.

## Regression approach

The complete suite runs with a CRI monkeypatch rejecting omitted/non-strict
argument mode and conflicting context mode, anticipating CRI-CORE #2. A source
inventory regression rejects restoration of CRI evaluator/pipeline imports or
attribute calls in either active package. No active CRI execution call remains.
The standalone reproduction retains an explicit strict control using actual CRI.

Security tests cover local/cloud, explicit/cached/expired/offline/missing policy,
all legacy fail modes, aliases, decorator invocation, supplied approvals,
missing/fake prerequisites, input immutability, zero callbacks and zero new
events/logs/receipts/spooled artifacts. Obsolete legacy allow/receipt expectations
are replaced by migration assertions; registry/cache/lineage integrity checks
remain separate from permission. Existing modern and repository tests are retained.

Native Windows/Linux, Ledger 0.7 v2 and Ledger 0.8 v2/v3, clean wheels, real
existing-file mutation and governance audits are recorded with exact results
in the draft PR. This validates the strict-mode contract using a test double,
not a claim of testing an unidentified CRI-CORE candidate build.

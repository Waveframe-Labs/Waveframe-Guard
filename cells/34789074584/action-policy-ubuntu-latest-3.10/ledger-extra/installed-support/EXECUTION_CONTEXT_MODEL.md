# Execution Context Model

Ledger models execution context as governance semantics: where execution is expected to occur, whether it can be deferred or resumed, and which replay, temporal, and state snapshot expectations should bind to that context.

Ledger does not enforce execution admissibility. It records deterministic governance assumptions so Guard and Cloud can later enforce, verify, attest, or compare runtime evidence.

## Canonical Execution Contexts

`execution_context_semantics.v1` uses one of these canonical contexts:

- `local_interactive`: execution occurs immediately in a local interactive surface.
- `queued_async`: execution is queued for asynchronous completion.
- `scheduled_execution`: execution occurs at a future scheduled time.
- `human_approval_chain`: execution waits for one or more human approval stages.
- `external_system_execution`: execution is performed by an external operational system.
- `agent_orchestrated`: execution is coordinated by an agent or orchestration layer.
- `multi_stage_workflow`: execution crosses multiple governed workflow stages.
- `resumed_workflow`: execution may pause and resume later.
- `cloud_attested_execution`: execution depends on Cloud-attested runtime evidence.

## Canonical Shape

```json
{
  "schema_version": "execution_context_semantics.v1",
  "execution_context": "queued_async",
  "execution_boundary": "external_worker",
  "requires_replay_evidence": true,
  "requires_state_snapshot": true,
  "requires_temporal_validation": true,
  "resume_behavior": "revalidate_on_resume",
  "continuity_risk_profile": "medium",
  "runtime_enforced_by": "Guard/Cloud"
}
```

## Interpretation Rules

Ledger deterministically extracts execution context from policy language such as:

- scheduled transfer
- resume after approval
- batch execution
- external settlement system
- queued deployment
- manual override
- multi-step approval
- execution may resume later

If deferred execution is implied but the execution context is not explicit, Ledger emits `execution_context_ambiguity`.

## Diagnostic Semantics

Execution context diagnostics are advisory and non-blocking:

- `Execution Context Ambiguity`: governance semantics imply deferred execution but no execution context was defined.
- `Replay Requirement Gap`: queued or deferred execution semantics require replay evidence expectations.
- `Resume Validation Gap`: resumable execution context exists without continuity revalidation semantics.

## Boundary

Ledger owns:

- governance execution context modeling,
- execution assumptions,
- replay and continuity expectations,
- deterministic context diagnostics.

Guard and Cloud own:

- runtime admissibility,
- runtime evidence verification,
- execution state attestation,
- timestamp validation,
- state snapshot comparison.

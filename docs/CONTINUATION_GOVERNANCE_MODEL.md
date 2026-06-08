# Continuation Governance Model

Status: emerging subsystem.

Continuation governance is a Guard subsystem for evaluating whether a previously
valid execution posture remains valid at the moment execution is attempted. It is
not a separate repository, not a separate package, and not a new authority layer.

The canonical invariant still applies:

Guard evaluates admissibility against compiled authority. Guard never derives
governance meaning from raw policy text.

## Scope

Continuation governance belongs inside Waveframe Guard runtime evaluation. It
does not own governance semantics, policy compilation, proposal normalization,
Cloud persistence, or authority lifecycle administration.

Guard owns the continuation question:

Can this execution continue under the same deterministic basis?

The first subsystem fields are:

- `continuation_status`
- `continuation_requirements`
- `invalidation_reasons`
- `runtime_condition_checks`
- `runtime_dependency_posture`
- `runtime_lifecycle_state`

## Status Values

`continuation_status` may be:

- `admissible`
- `invalidated`
- `expired`
- `revalidation_required`
- `escalation_required`

These are runtime states. They do not redefine compiled governance meaning.

## Runtime Conditions

Runtime condition checks are deterministic booleans derived from runtime
evidence, replay posture, dependency posture, and lineage continuity posture.
They explain why continuation remained valid or failed.

Initial checks:

- evidence validity
- replay validity
- runtime dependency validity
- lineage continuity validity
- expiration status

## Dependency Invalidation

Runtime dependencies may include approvals, replay evidence, external execution
context, and other artifacts whose identity is part of the replay basis.

Canonical runtime dependencies use `guard_runtime_dependency.v1`:

```json
{
  "schema_version": "guard_runtime_dependency.v1",
  "dependency_type": "approval",
  "dependency_id": "director-approval-1",
  "dependency_hash": "sha256:...",
  "current_hash": "sha256:...",
  "valid_until": "2026-06-03T22:31:00Z",
  "status": "valid"
}
```

Dependency invalidation occurs when a dependency:

- expires
- is explicitly marked invalid
- drifts from its recorded hash

Dependency failures can invalidate continuation without requiring Guard to parse
policy text or compile governance meaning.

## Runtime Lifecycle

Continuation governance formalizes the runtime lifecycle as:

- `pending`
- `admissible`
- `continuation_required`
- `revalidation_required`
- `invalidated`
- `expired`
- `escalated`
- `blocked`
- `released`
- `executed`

This lifecycle is distinct from the enforcement outcome states. Guard still emits
`allowed`, `blocked`, or `escalated` as execution state; lifecycle state explains
why a once-valid execution may no longer be continuously valid.

## Deferred Release Enforcement

Deferred release enforcement is Phase 1 of continuous execution validity. It is
local and deterministic. It is not a scheduler, not a queue service, not a Cloud
agent, and not distributed orchestration.

The release model separates:

- `admissible`: execution satisfied Guard evaluation at T1
- `released`: continuation remained valid at release time T2
- `executed`: the protected mutation actually ran at T3

These states are not interchangeable. Continuation governance exists in the gap
between `admissible` and `released`.

The first release artifact is `guard_continuation_lease.v1`:

```json
{
  "schema_version": "guard_continuation_lease.v1",
  "continuation_id": "cont_...",
  "execution_id": "exec_1",
  "authority_ref": "finance-policy@1.0.0",
  "issued_at": "2026-06-03T22:00:00Z",
  "admissible_until": "2026-06-03T22:35:00Z",
  "runtime_dependencies": [],
  "continuation_status": {
    "schema_version": "guard_continuation_status.v1",
    "status": "admissible"
  },
  "revalidation_required": false
}
```

Before deferred execution is released, Guard validates the lease with
`guard_release_validation.v1`. Outcomes are:

- `release_allowed`
- `release_blocked`
- `revalidation_required`
- `continuation_invalidated`
- `dependency_expired`

## Invalidation Chronology

Guard chronology can show continuation invalidation without implying hosted live
infrastructure:

- evaluation admissible
- continuation lease issued
- runtime dependency linked
- runtime dependency expired or invalidated
- continuation invalidated
- release blocked

Example operator story:

Transfer initially admissible. Approval expired before execution. Continuation
invalidated. Release blocked at runtime.

## Outcome Binding

`guard_enforcement_outcome.v1` may carry continuation fields as additive runtime
metadata. This keeps continuation behavior inspectable in Guard Inspector and
replayable in local artifacts without changing the authority boundary.

Continuation fields are part of the Guard runtime subsystem. They are not a repo split,
not a package split, and not a Cloud persistence contract.

# Guard Semantics Freeze

## Canonical terminology

| Layer | Canonical Name |
| --- | --- |
| SDK runtime | Guard SDK |
| UI | Guard Inspector |
| Kernel | CRI-CORE |
| Result | Guard enforcement outcome |
| Saved package | Evaluation artifact |
| Replay identity | Replay basis |
| Continuity binding | Lineage continuity |
| Persisted package | Artifact manifest |

These names are product and architecture terms. Avoid introducing aliases in
runtime artifacts, UI labels, docs, tests, or examples unless the alias is an
external integration name.

## Execution states

Guard exposes three canonical execution states:

| Execution state | Meaning |
| --- | --- |
| `allowed` | The execution is admissible and may proceed. |
| `blocked` | The execution is inadmissible and must not proceed. |
| `escalated` | The execution is admissible only after an external obligation is satisfied. |

`guard_enforcement_outcome.v1` keeps the runtime `status` field for contract
compatibility. The operator-facing `execution_state` maps as follows:

| Runtime status | Execution state |
| --- | --- |
| `admissible` | `allowed` |
| `blocked` | `blocked` |
| `escalated` | `escalated` |

This distinction is intentional: blocked executions fail admissibility;
escalated executions are held pending external evidence, review, or replay
obligation.

## Chronology contract

Guard chronology is deterministic and evaluation-scoped. It is not a live
event stream and it is not Cloud history.

Chronology ordering is defined by the integer `sequence` field. For one
evaluation, Guard emits these event types in order:

1. `authority_context_resolved`
2. `evaluation_pipeline_started`
3. `runtime_evidence_loaded`
4. `continuity_checked`
5. `replay_validated`
6. `admissibility_evaluated`
7. `enforcement_outcome_recorded`

Event names use lower snake case, past-tense operational phrasing, and describe
runtime evaluation work rather than governance authoring. Event categories are:

- authority
- evidence
- continuity
- replay
- admissibility
- enforcement

The Guard Receipt stores chronology event identifiers and the chronology hash.
The Artifact manifest stores the evaluation hash that contains the chronology.
Replay must classify chronology changes as `chronology_mutation`.

## Replay trust posture

Replay failures should be explained operationally first:

> This execution can no longer be trusted because the replay basis diverged from
> the original deterministic identity.

Hash deltas remain available as technical details. They should not be the
primary operator explanation.

## Continuation validity

Guard evaluates continuation validity as runtime state, not governance meaning.
The first continuation engine accepts:

- evidence validity
- replay validity
- dependency validity
- continuity validity
- dependency expiration

It emits `guard_continuation_status.v1` with one canonical status:

- `admissible`
- `invalidated`
- `expired`
- `revalidation_required`
- `escalation_required`

`invalidated` and `expired` block execution. `revalidation_required` and
`escalation_required` escalate execution.

Runtime dependencies are represented as evidence:

```json
{
  "runtime_dependencies": [
    {
      "type": "approval",
      "id": "director-approval-1",
      "hash": "sha256:...",
      "valid_until": "2026-06-03T23:30:00+00:00"
    }
  ]
}
```

Dependency hash drift, invalidation, or expiration can invalidate continuation.
The Guard Receipt binds runtime dependency hashes into replay basis and lineage
continuity.

## Expiration-aware chronology

Guard chronology may include continuation events when dependencies expire or
drift:

- `runtime_dependency_expired`
- `runtime_dependency_invalidated`
- `continuation_evaluated`

The Guard Inspector presents these with both audit time and relative execution
delta so operators can distinguish durable audit evidence from execution
progression.

## Local and Cloud boundary

Guard local owns:

- Guard SDK interception
- before-mutation enforcement
- local evaluation artifacts
- local Guard Receipts
- local Artifact manifests
- local replay basis and replay records
- local `.guard-local/` workspace
- Guard Inspector inspection over local artifacts

Cloud owns:

- organization management
- remote authorities
- centralized lineage
- fleet-wide audit
- policy publishing
- enforcement analytics
- cross-system history
- managed replay
- compliance exports

Guard local may emit artifacts Cloud later imports or manages. Guard local does
not implement Cloud persistence, organization tenancy, policy publishing, or
fleet-wide analytics.

# Runtime Evaluation Flow

Runtime evaluation is the ordered path from requested execution to allowed or
blocked posture.

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

## Flow

1. Resolve the authority reference.
2. Load a legacy `compiled_authority_contract.v1`, or verify the complete Ledger
   v2 bundle/receipt chain before selecting the exact embedded
   `compiled_authority_contract.v2`.
3. Verify authority identity, version, hash, lifecycle, and lineage metadata.
4. Accept only a normalized execution request.
5. For v2, select the fact provider by immutable domain-pack and fact-schema
   identity/hash, derive the exact typed facts, and fail closed on any gap.
6. Validate execution state as a Guard runtime payload.
7. Materialize `guard_runtime_evidence_model.v1`.
8. Evaluate admissibility against the unchanged compiled authority.
9. Record chronology and revalidation metadata.
10. Enforce the decision by allowing, blocking, or escalating execution.
11. Emit telemetry, audit evidence, posture data, and
   `guard_enforcement_outcome.v1`.

## Runtime cognition substrate

The operational backbone materializes deterministic runtime payloads:

- `execution_admissibility_projection.v1`
- `execution_runtime_posture.v1`
- `guard_runtime_event.v1`
- `guard_evaluation_trace.v1`
- `guard_continuity_posture.v1`
- `guard_enforcement_outcome.v1`

These payloads are Guard-owned runtime surfaces. They are derived from compiled
authority, execution request, actor identity, continuity state, replay posture,
and evidence posture. They do not derive governance meaning from raw policy text.

## Boundary in the flow

The flow begins after governance meaning has already been compiled. Guard may
reject, verify, evaluate, and record compiled authority. It must not move the
boundary earlier by reading raw policy text and deriving meaning itself.

## Revalidation

Runtime evaluation is not a one-time semantic claim. A prior admissibility
decision can require revalidation when:

- authority was revoked after decision
- authority was superseded during execution
- the admissibility window expired
- actor continuity changed
- runtime chronology indicates a revalidation signal

Revalidation evaluates whether the execution posture remains admissible. It does
not reinterpret governance meaning.

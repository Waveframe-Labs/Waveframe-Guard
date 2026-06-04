# Runtime Evaluation Flow

Runtime evaluation is the ordered path from requested execution to allowed or
blocked posture.

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

## Flow

1. Resolve the authority reference.
2. Load compiled authority from the registry, cache, or explicit runtime binding.
3. Verify authority identity, version, hash, lifecycle, and lineage metadata.
4. Build execution state from actor, action, target, arguments, artifacts, and
   approval evidence.
5. Validate execution state as a Guard runtime payload.
6. Evaluate admissibility against compiled authority.
7. Record chronology and revalidation metadata.
8. Enforce the decision by allowing or blocking execution.
9. Emit telemetry, audit evidence, and posture data.

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

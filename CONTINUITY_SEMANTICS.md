# Continuity Semantics

## Admissibility Window

An admissibility decision may include a bounded validity interval.

Execution outside this interval requires deterministic revalidation before the prior decision can be relied on.

Runtime evaluation metadata may include:

- `valid_until`
- `revalidation_required_after`
- `continuity_signals`

## Revalidation

Guard may require revalidation before resumed or delayed execution.

Revalidation reevaluates:

- authority lifecycle
- authority continuity
- actor continuity
- admissibility validity
- execution context integrity

## Continuity Drift Signals

Initial deterministic continuity signals:

- `AUTHORITY_SUPERSEDED_DURING_EXECUTION`
- `AUTHORITY_REVOKED_POST_DECISION`
- `ADMISSIBILITY_WINDOW_EXPIRED`
- `ACTOR_CONTINUITY_BROKEN`
- `REVALIDATION_REQUIRED`

These are continuity signals. They are not admissibility decisions.

Continuity signal emission is deterministic and structural. Initial signals are limited to lifecycle drift, actor continuity drift, and admissibility window expiration.

## Non-Goals

Continuity semantics do not introduce:

- orchestration engine
- async scheduler
- distributed workflow management
- probabilistic scoring
- autonomous retry management

Guard evaluates continuity. Cloud displays continuity.

# Continuity Semantics

## Admissibility Window

An admissibility decision may include a bounded validity interval.

Execution outside this interval requires deterministic revalidation before the prior decision can be relied on.

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

## Non-Goals

Continuity semantics do not introduce:

- orchestration engine
- async scheduler
- distributed workflow management
- probabilistic scoring
- autonomous retry management

Guard evaluates continuity. Cloud displays continuity.

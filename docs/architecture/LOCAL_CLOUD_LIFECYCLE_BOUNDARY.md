# Local to Cloud Lifecycle Boundary

Status: architecture freeze note.

Guard local runtime and Cloud are lifecycle-adjacent, not interchangeable.

## Local Runtime Lifecycle

Guard local owns execution-edge state:

- SDK interception before mutation
- local organization and workspace context
- local actor and compiled authority references
- local evaluation runs
- local Guard Receipts
- local artifact manifests
- local replay basis
- local continuation leases
- local release validations
- local runtime dependencies
- local release queue rows

This state may be persisted under:

```text
.guard-local/
    guard-runtime.sqlite3
```

The local store exists so continuation governance can survive process restart.
It is scoped to a local workspace and is suitable for development, inspection,
deterministic replay, and handoff artifact generation.

## Cloud Lifecycle

Cloud owns managed, organization-wide lifecycle:

- managed organization tenancy
- remote authority distribution
- centralized lineage
- fleet-wide audit
- policy publishing
- enforcement analytics
- cross-system history
- managed replay
- compliance exports

Cloud may ingest local artifacts and runtime exports. Cloud does not change the
canonical Guard invariant:

```text
Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.
```

## Preservation Annotation Rule

Cloud preservation is post-decision evidence durability. Guard must complete
the local decision record before Cloud is contacted:

- evaluation history
- Guard Receipt
- artifact manifest
- replay record

The Guard Receipt and artifact manifest are immutable local decision evidence.
Cloud preservation metadata is a later durability annotation on the saved
evaluation container. It records Cloud identifiers such as package id, receipt
id, content hash, and timestamp so inspection tools can show preservation
status without manual import.

Cloud metadata must not retroactively claim to be covered by the original Guard
Receipt or artifact manifest unless those artifacts are explicitly regenerated
as a new evidence set. v0.12.0 does not regenerate them.

For an allowed decision, the preserved package means Guard evaluated the request
and declared it admissible. It is not proof that the protected business
mutation completed.

## Handoff Rule

Local Guard may export:

- evaluation artifacts
- Guard Receipts
- artifact manifests
- replay records
- continuation leases
- release validations
- persistent runtime state exports

Cloud may import, aggregate, verify, retain, and report on those artifacts.

Local Guard must not implement Cloud ownership concerns such as managed tenancy,
fleet-wide analytics, policy publishing, or centralized governance history.

## Recovery Rule

Local runtime recovery is a development and inspection capability. If
`.guard-local/guard-runtime.sqlite3` is corrupt, Guard may quarantine the local
database and initialize an empty one. This is not a Cloud durability guarantee.

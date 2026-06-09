# Persistent Organizational Runtime

Status: transitional local architecture.

Persistent Organizational Runtime is not Cloud. It is a local SQLite-backed
runtime layer that lets Guard preserve longitudinal continuation state across
process restarts.

## Why It Exists

Continuation governance depends on state over time:

- an execution is evaluated
- a continuation lease is issued
- runtime dependencies age or drift
- release is requested
- release is allowed or blocked

That sequence cannot be represented as one stateless evaluation.

## Local Persistence

The local runtime database is:

```text
.guard-local/guard-runtime.sqlite3
```

It persists:

- organizations
- workspaces
- runs
- continuation leases
- release validations
- runtime dependencies
- actors
- compiled authority references
- release queue rows

## Organization Context

The local context fields are:

- `organization_id`
- `workspace_id`
- `environment`
- `authority_namespace`

Default local context:

```json
{
  "organization_id": "org-finance",
  "workspace_id": "workspace-local",
  "environment": "local",
  "authority_namespace": "finance"
}
```

## Identity Registry

Actors are persisted locally with:

- actor id
- role
- team
- clearance
- delegation
- revocation
- status

This prepares Guard for continuation invalidation caused by manager approval
revocation, employee termination, expired delegation, or authority supersession.

## Release Queue

The first local release queue lifecycle is:

```text
admissible
lease issued
queued
release requested
revalidated
released
executed
```

Phase 1 records queue state. It does not implement a scheduler, worker, queue
service, distributed orchestrator, Cloud agent, or managed tenancy.

## Dashboard Signals

Guard Inspector can read local dashboard signals:

- active continuation leases
- expiring dependencies
- blocked releases
- escalation queue
- replay failures
- invalidated continuations
- runtime drift alerts

These are local operational signals over `.guard-local/guard-runtime.sqlite3`.
Cloud may later aggregate them, but Cloud does not exist in this layer.

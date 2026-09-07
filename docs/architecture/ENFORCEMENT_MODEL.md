# Enforcement Model

Guard enforcement is runtime enforcement, not semantic authority ownership.

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

## Enforcement responsibility

Guard enforces whether a proposed execution can proceed under compiled authority.
It may:

- resolve the active compiled authority reference
- verify authority identity, hash, lifecycle, and lineage metadata
- build execution state
- evaluate admissibility
- block or allow execution
- emit runtime telemetry and audit evidence
- render execution posture for users and operators

It may not:

- compile raw policy text
- extract governance meaning from natural language
- define governance schemas for compiled authority
- reinterpret authority requirements
- patch or synthesize missing governance meaning

## Enforcement inputs

Guard enforcement depends on:

- compiled authority
- execution state
- actor identity
- approval evidence
- runtime context
- authority lifecycle metadata
- chronology and revalidation signals

Raw policy text is not an enforcement input.

## Enforcement outputs

Guard enforcement produces runtime outputs:

- admissibility decision
- block or allow reason
- missing approval evidence
- decision trace
- governed execution event
- runtime chronology entries
- telemetry records

These outputs describe runtime enforcement posture. They do not become source
authority for governance meaning.

## Outcome contract

Every Guard runtime evaluation emits `guard_enforcement_outcome.v1`. This is the
stable enforcement bridge object for later Cloud integration. Cloud may persist
or route it later, but Guard does not own Cloud persistence behavior.

## Failure posture

When authority cannot be resolved or verified, execution fails closed. Legacy
`fail_mode="open"` cannot invoke an ungoverned callback. Guard execution is never
advisory: local/cloud controls authority resolution, not enforcement strength,
and advisory CRI evaluation is not permission to execute. Legacy APIs unable to
establish strict execution evidence raise a migration error; use
`Guard.local()` / `Guard.cloud()` and guarded tools. See the
[migration guide](../getting-started/STRICT_EXECUTION_MIGRATION.md).

Modern post-decision Cloud preservation failures retain their existing diagnostic
semantics; they do not replace authority resolution or grant permission.

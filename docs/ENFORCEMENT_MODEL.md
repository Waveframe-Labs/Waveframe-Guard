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

## Failure posture

When authority cannot be resolved or verified, Guard must treat that as a runtime
admissibility problem. It should fail closed unless an explicitly configured,
auditable fail-open mode is in effect.

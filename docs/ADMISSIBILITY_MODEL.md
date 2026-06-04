# Admissibility Model

Admissibility is the central Guard question:

> Is this execution admissible under the compiled authority available at runtime?

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

## What admissibility includes

Admissibility evaluation may consider:

- authority identity
- authority version
- authority hash and integrity
- authority lifecycle status
- actor identity
- requested action
- target resource
- runtime arguments
- approval evidence
- separation-of-duty constraints supplied by compiled authority
- validity windows
- revalidation signals

These checks are runtime execution checks. They do not define what the authority
means.

## What admissibility excludes

Admissibility evaluation must not:

- parse raw policy text
- infer obligations from prose
- compile policy into authority
- define compiled authority schemas
- duplicate Governance Ledger semantic models
- decide that missing authority meaning can be filled locally

If Guard needs governance meaning that is not present in compiled authority, the
execution is not admissible until valid compiled authority is supplied.

## Decision shape

An admissibility decision should be explicit enough to support enforcement,
telemetry, audit, and user posture rendering:

- `allowed`
- `decision`
- `reason`
- `authority_ref`
- `contract_hash`
- `execution_state`
- `missing_approvals`
- `decision_trace`

The decision should explain runtime evaluation, not governance authorship.

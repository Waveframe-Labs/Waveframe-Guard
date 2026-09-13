# Governance Semantic Reconciliation

Governance Semantic Reconciliation records how human governance language becomes deterministic governance meaning.

Ledger must preserve not only the final authority semantics, but also the interpretation path that established those semantics:

- what was inferred from source language
- what was ambiguous
- what required operator clarification
- what was normalized
- what was rejected
- what changed between interpretations

This is interpretation provenance. It lets chronology replay reconstruct why governance meaning became what it became.

## Canonical Artifacts

`governance_semantic_reconciliation.v1` is the canonical reconciliation record for one semantic extraction and operator review pass.

It references:

- `governance_source.v1`
- `governance_semantic_extraction.v1`
- `semantic_ambiguity.v1`
- `semantic_conflict.v1`
- `semantic_interpretation_decision.v1`
- `semantic_stability_projection.v1`

## Critical Invariant

No unresolved ambiguity may silently become deterministic authority meaning.

If source language is ambiguous, Ledger must keep the ambiguity explicit as:

- `unresolved`
- `operator_required`
- `interpretation_incomplete`

Publication logic may later decide how to handle incomplete interpretation, but reconciliation itself must never hide it.

## Example

Source language:

```text
Large financial transfers require executive review.
```

Extraction may emit:

```json
{
  "schema_version": "semantic_ambiguity.v1",
  "ambiguity_type": "undefined_threshold",
  "text": "Large financial transfers",
  "requires_operator_resolution": true
}
```

Operator interpretation:

```json
{
  "schema_version": "semantic_interpretation_decision.v1",
  "decision_id": "decision-...",
  "field": "escalation_threshold",
  "selected_interpretation": 250000,
  "rejected_interpretations": ["undefined large transfer"],
  "decision_type": "threshold_definition",
  "ambiguity_id": "ambiguity-large-transfer",
  "resolved_value": 250000,
  "operator": "governance-ledger",
  "timestamp": "2026-01-01T00:00:00Z",
  "rationale": "Treasury policy baseline",
  "justification": "Treasury policy baseline",
  "decision_posture": "operator_reviewed"
}
```

Reconciliation records the original ambiguity, the operator interpretation, and the final normalized semantic meaning.

## Operator Decision Ownership

Semantic conflict resolution is operator-owned.

Ledger may extract candidates, detect ambiguity, and normalize confirmed decisions, but it must explicitly record:

- the semantic field being decided
- the selected interpretation
- rejected interpretations
- the operator identity
- the decision timestamp
- the justification

Viewing or extracting policy text is not a decision. A semantic interpretation decision is the explicit boundary where candidate meaning becomes operator-owned interpretation provenance.

## Projection

`semantic_reconciliation_projection.v1` is the UI-facing view over reconciliation state.

It may emit:

- unresolved ambiguities
- operator-reviewed interpretations
- conflicting extracted semantics
- normalization decisions
- interpretation completeness posture

`semantic_stability_projection.v1` compares interpretation lineage across extraction or reconciliation runs.

It detects:

- same source text producing different extracted semantics
- extraction method changes
- changed operator interpretation decisions
- semantic meaning drift between versions

This projection answers the organizational question:

> Did interpretation meaning drift, and why?

## Non-Goals

Semantic reconciliation does not:

- approve authority
- determine admissibility
- call Guard
- call Cloud
- execute policy
- hide incomplete interpretation

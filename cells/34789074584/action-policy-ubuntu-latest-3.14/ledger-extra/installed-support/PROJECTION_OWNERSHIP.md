---
title: "Projection Ownership"
document_type: "architecture"
system: "Governance-Ledger"
component: "public-projections"
version: "0.4.0"
status: "draft"

created: "2026-05-27"
updated: "2026-06-03"

authors:
  - "Waveframe Labs"

maintainers:
  - "Waveframe Labs"

license: "Apache-2.0"

repository: "https://github.com/Waveframe-Labs/Governance-Ledger"

summary: >
  Ownership boundaries, stability expectations, freshness semantics, and
  invalidation rules for public Ledger governance projections.
---

# Projection Ownership

Ledger projections are deterministic governance views over Ledger-owned artifacts. They are not UI conveniences, Cloud compatibility shims, or Guard runtime decisions.

## Ownership Rule

`governance_ledger/semantics/` owns semantic, compilation, publication, lifecycle consequence, and execution-facing projection meaning.

Consumers may select, format, collapse, expand, store, or render projection fields. They must not independently derive:

- what an authority means operationally
- whether continuity posture changed
- whether replay obligations are complete
- whether identity, approval, or execution constraints changed
- whether semantic interpretation is complete
- what Guard-facing enforcement requirements would change

Those meanings flow from canonical Ledger artifacts.

## Canonical Projection Families

### Semantic

- `governance_impact_preview.v1`
- `authority_diff_impact.v1`
- `semantic_authority_diff.v1`
- `governance_review_packet.v1`
- `semantic_reconciliation_projection.v1`
- `semantic_stability_projection.v1`

### Compilation And Execution

- `compiled_authority_contract.v1`
- `authority_execution_projection.v1`
- `execution_requirement_projection.v1`
- `execution_admissibility_projection.v1`
- `runtime_consequence_projection.v1`
- `guard_enforcement_projection.v1`

### Lifecycle Consequence

- `semantic_lifecycle_enforcement_projection.v1`

### Publication And Replay

- `authority_bundle.v1`
- `publication_receipt.v1`
- `governance_replay_state.v1`
- `governance_replay_diff.v1`

### Events And Freshness

- `governance_event.v1`
- `projection_generation_event.v1`
- `projection_invalidation_event.v1`
- `continuity_transition_event.v1`

## Durable Facts

These are durable facts, not projections:

- `governance_source.v1`
- `governance_semantic_extraction.v1`
- `governance_semantic_reconciliation.v1`
- `semantic_commit_bundle.v1`
- `compiled_authority_contract.v1`
- `authority_bundle.v1`
- `publication_receipt.v1`
- `governance_event.v1`

Durable facts are never rewritten to make later projections easier. Corrections must be represented by later facts or append-only events.

## Compatibility Layers

Compatibility layers adapt transitional artifact shapes into canonical public schemas.

Examples:

- publication manifest aliases
- authority bundle aliases
- legacy contract registry fields
- older review packet field names

Compatibility layers are adapters. They do not own governance meaning.

## Governance-Native Severity

Ledger uses governance-native severity semantics:

- `info`: advisory governance context with no immediate operational risk.
- `warning`: governance posture changed and should be reviewed.
- `critical`: authority state creates a severe lifecycle consequence.
- `continuity_risk`: continuity guarantees or resumed execution semantics changed.
- `replay_risk`: replay evidence, receipt posture, or semantic hash linkage is incomplete.
- `authority_conflict`: authority posture changed in a way that may alter active authority interpretation.

These are not infrastructure severities. They describe governance consequences.

## Invalidation Semantics

Projection invalidation is deterministic. Source facts persist; affected projections recompute.

| Change | Invalidated projections | Persist historically |
| --- | --- | --- |
| Governance source changed | `governance_semantic_extraction.v1`, `semantic_reconciliation_projection.v1`, `governance_impact_preview.v1`, `compiled_authority_contract.v1` | Prior source hashes and extraction artifacts |
| Ambiguity resolved | `semantic_reconciliation_projection.v1`, `semantic_commit_bundle.v1`, `compiled_authority_contract.v1`, execution projections | Interpretation decisions |
| Semantic commit changed | `compiled_authority_contract.v1`, `authority_execution_projection.v1`, `governance_impact_preview.v1`, `authority_bundle.v1` | Prior semantic commit bundle |
| Compiled contract changed | `execution_requirement_projection.v1`, `execution_admissibility_projection.v1`, `guard_enforcement_projection.v1`, `runtime_consequence_projection.v1` | Prior compiled contract hash |
| Authority superseded | `authority_diff_impact.v1`, `semantic_authority_diff.v1`, `semantic_lifecycle_enforcement_projection.v1`, `governance_replay_state.v1` | Supersession event and prior bundle |
| Replay posture invalidated | `runtime_consequence_projection.v1`, `execution_admissibility_projection.v1`, `governance_impact_preview.v1`, `governance_replay_state.v1` | Existing receipts as historical evidence |

## Recompute Rules

Persist:

- semantic extraction artifacts
- semantic reconciliation artifacts
- semantic commit bundles
- compiled authority contracts
- authority bundles
- publication receipts
- append-only governance events

Recompute:

- impact previews
- semantic diffs
- execution projections
- lifecycle consequence projections
- replay states and replay diffs
- freshness and invalidation events

## Boundary

Projection builders must not call Guard, Cloud, or runtime admissibility evaluators.

Ledger projections describe governance meaning from Ledger-owned artifacts. Cloud may store and operate those artifacts. Guard may later decide admissibility from runtime context, but Guard does not own Ledger projection semantics.

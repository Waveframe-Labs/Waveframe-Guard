---
title: "Semantic Governance Model"
document_type: "ontology"
system: "Governance-Ledger"
component: "semantic-governance"
version: "0.4.0"
status: "draft"

created: "2026-05-27"
updated: "2026-05-27"

authors:
  - "Waveframe Labs"

maintainers:
  - "Waveframe Labs"

license: "Apache-2.0"

repository: "https://github.com/Waveframe-Labs/Governance-Ledger"

summary: >
  Canonical ontology for Ledger-owned semantic governance primitives,
  projection roles, mutation boundaries, freshness semantics, and
  governance-native severity language.
---

# Semantic Governance Model

Ledger owns governance meaning.

This document defines the canonical semantic ontology for public Ledger governance objects, deterministic semantic interpretation, compiled authority contracts, replay posture, continuity semantics, reconciliation, freshness, and projection boundaries.

It is intentionally not a Cloud operations model and not a Guard admissibility model.

## Core Governance Primitives

### Authority

An authority is a deterministic governance object that states what operational resource is governed, what action is controlled, which authority requirements apply, when escalation occurs, what evidence is expected, and what lifecycle or continuity posture affects execution.

Canonical artifact:

- `authority_contract.v1`

Publishable envelope:

- `authority_bundle.v1`

### Lineage

Lineage is the versioned relationship between authorities in one authority family. It includes version successors, supersession relationships, revocation posture, provenance, and lifecycle continuity.

Lineage answers:

- what came before this authority
- what superseded it
- whether the version chain is complete
- whether replay or continuity can bind to prior posture

### Continuity

Continuity is the semantic relationship between authority posture and resumed, delayed, replayed, or lineage-dependent execution.

Continuity answers:

- whether resumed workflows require revalidation
- whether revocation invalidates resumed execution
- whether supersession changes execution posture
- whether lineage gaps or churn degrade governance stability

### Replay Posture

Replay posture is the evidence-readiness state that determines whether future replay review can bind to the authority, receipt, manifest, semantic hashes, and lineage.

Replay posture is not runtime replay execution. It is publication evidence readiness.

### Drift

Drift is deterministic semantic change across authority versions or lifecycle posture.

Examples:

- approval requirement changed
- escalation threshold changed
- continuity posture changed
- lifecycle posture changed

Drift is not a score and not an anomaly detector.

### Reconciliation

Reconciliation compares source interpretation, semantic ambiguity, replay posture, continuity posture, projection freshness, and compiled authority meaning to detect deterministic divergence.

Reconciliation does not fix state and does not recommend policy changes.

### Invalidation

Invalidation is the condition where a source change makes one or more projections no longer authoritative for the current state.

Example:

```text
draft updated
  -> governance_semantic_extraction.v1 invalidated
  -> semantic_reconciliation_projection.v1 invalidated
  -> governance_impact_preview.v1 invalidated
  -> compiled_authority_contract.v1 invalidated
```

Invalidation does not delete historical artifacts.

### Freshness

Freshness is the relation between a projection and the source events or facts from which it was generated.

Freshness answers:

- was this projection generated from current source events?
- did a later lifecycle event make it stale?
- did a state transition explicitly invalidate it?

### Lifecycle Event

A lifecycle event is an append-only fact attached to an authority lineage.

Canonical artifact:

- `governance_event.v1`

Lifecycle events include:

- `drafted`
- `reviewed`
- `exported`
- `registered`
- `superseded`
- `revoked`

### Operational Summary

An operational summary is a deterministic interpretation of what an authority means operationally.

It includes governance meaning, continuity implications, replay posture, execution consequences, and publication implications.

Canonical artifacts:

- `governance_impact_preview.v1`
- `authority_execution_projection.v1`

### Active Authority

An active authority is the authority version selected by a consuming registry or operations system as the current governance posture for an authority family.

Public Ledger defines deterministic authority objects, lineage metadata, event semantics, and replayable chronology state. Hosted products and consuming systems decide how active authority selection is stored and displayed.

### Governance Activity

Governance activity is the deterministic chronology of governance events, projection generation, projection invalidation, continuity transitions, and semantic drift.

Canonical artifacts:

- `governance_event.v1`
- `projection_generation_event.v1`
- `projection_invalidation_event.v1`
- `continuity_transition_event.v1`

### Governance Coherence

Governance coherence is the posture that summarizes whether semantic interpretation, compiled authority meaning, replay posture, continuity semantics, and projection freshness remain aligned.

Coherence uses governance-native language:

- healthy
- stale
- invalidated
- continuity risk
- replay risk
- authority conflict

## Projection Taxonomy

### Semantic

Semantic projections render deterministic governance meaning and interpretation posture.

- `governance_impact_preview.v1`
- `authority_diff_impact.v1`
- `governance_review_packet.v1`
- `governance_semantic_extraction.v1`
- `semantic_reconciliation_projection.v1`
- `semantic_stability_projection.v1`

### Compilation And Execution

Compilation and execution projections render deterministic runtime-facing requirements without invoking Guard.

- `compiled_authority_contract.v1`
- `execution_requirement_projection.v1`
- `execution_admissibility_projection.v1`
- `runtime_consequence_projection.v1`
- `guard_enforcement_projection.v1`
- `authority_execution_projection.v1`

### Publication And Replay

Publication and replay artifacts bind semantic outputs to lineage, receipts, replay state, and replay diffs.

- `authority_bundle.v1`
- `publication_receipt.v1`
- `governance_replay_state.v1`
- `governance_replay_diff.v1`

### Lifecycle Consequence

Lifecycle consequence projections describe deterministic continuity and admissibility consequences from semantic authority changes.

- `semantic_lifecycle_enforcement_projection.v1`

### Events And Freshness

Event and freshness artifacts record projection causality and invalidation.

- `governance_event.v1`
- `projection_generation_event.v1`
- `projection_invalidation_event.v1`
- `continuity_transition_event.v1`

## Mutation Boundaries

These are ontology rules, not UI preferences.

### Viewing Is Not A Lifecycle Transition

Viewing bundle, preview, receipt, diff, diagnostics, lineage, or timeline artifacts must not create lifecycle events.

### Rendering Is Not Approval

Rendering an artifact must not approve, review, export, register, supersede, revoke, or otherwise mutate authority posture.

### Preview Is Not Review

Generating or viewing `governance_impact_preview.v1` does not mean the operator reviewed impact.

Review requires an explicit review action.

### Export Is Not Registration

Exporting `authority_bundle.v1` creates or prepares publication evidence. It does not register the authority lifecycle event unless a separate explicit registration action occurs.

### Registration Is Not Admissibility

Registering an authority locally records lifecycle posture and evidence. It does not make any runtime execution admissible.

Guard owns admissibility.

### Diagnostics Are Advisory

Diagnostics describe deterministic governance quality observations. They do not reject publication, approve authority, or evaluate runtime execution.

## Projection Freshness Semantics

### Fresh

`fresh` means the projection was generated from the current source event set and no known invalidation applies.

### Stale

`stale` means newer source events exist than the projection's recorded `source_event_ids`, but the projection was not explicitly invalidated.

### Invalidated

`invalidated` means a source transition explicitly made the projection unfit for current operational posture.

Examples:

- draft changed after review
- authority superseded
- replay posture invalidated
- diagnostics stale

### Reconciled

`reconciled` means reconciliation found no divergence across semantic interpretation, compiled authority meaning, lineage, replay posture, continuity semantics, or projection freshness.

## Invalidation Propagation

Invalidation propagates from source facts to dependent projections.

Examples:

```text
draft changed
  -> governance_semantic_extraction.v1 invalidated
  -> semantic_reconciliation_projection.v1 invalidated
  -> governance_impact_preview.v1 invalidated
  -> compiled_authority_contract.v1 invalidated

authority superseded
  -> authority_diff_impact.v1 regenerated
  -> semantic_lifecycle_enforcement_projection.v1 regenerated
  -> governance_replay_state.v1 regenerated for later cutoffs
  -> guard_enforcement_projection.v1 regenerated if compiled contract changed

replay posture invalidated
  -> runtime_consequence_projection.v1 invalidated
  -> execution_admissibility_projection.v1 invalidated
  -> governance_impact_preview.v1 invalidated
  -> governance_replay_state.v1 regenerated
```

Historical source facts persist. Projections recompute.

## Governance-Native Severity Semantics

Ledger uses governance-native severity semantics.

These are not infrastructure alert levels.

### info

Contextual governance information with no immediate continuity, replay, or authority conflict.

### warning

A governance posture changed or requires operator awareness, but does not directly indicate continuity risk, replay risk, or authority conflict.

### critical

A lifecycle posture has severe governance consequence, such as revocation.

### continuity_risk

Continuity semantics changed or resumed execution posture may require revalidation.

### replay_risk

Replay evidence, receipt posture, semantic hash linkage, manifest alignment, or lineage evidence is incomplete or inconsistent.

### authority_conflict

Authority interpretation is ambiguous or conflicting, such as multiple active authorities in one authority family.

## Projection Generation Standard

All canonical projections should evolve toward a common metadata envelope.

Required standard fields:

```json
{
  "schema_version": "projection_name.v1",
  "projection_version": "v1",
  "generated_at": "2026-05-27T00:00:00Z",
  "source_event_ids": [],
  "freshness_posture": "fresh",
  "projection_dependencies": []
}
```

### generated_at

The deterministic or runtime timestamp when the projection was generated.

When deterministic test generation is required, callers may supply `generated_at`.

### source_event_ids

The lifecycle event IDs, registry event IDs, or source artifact identifiers used to build the projection.

### freshness_posture

One of:

- `fresh`
- `stale`
- `invalidated`

### projection_version

The additive evolution version of the projection contract.

For `*.v1` projections, this should be `v1`.

### projection_dependencies

The projection schemas or source facts required to derive the projection.

Examples:

- `governance_impact_preview.v1`
- `authority_lifecycle_event.v1`
- `compiled_authority_contract.v1`
- `guard_enforcement_projection.v1`

## Non-Goals

Ledger semantic projections must not:

- invoke Guard
- call Cloud
- evaluate runtime admissibility
- probabilistically score governance risk
- generate AI recommendations
- mutate source facts during rendering
- replace explicit lifecycle actions

Ledger produces deterministic governance meaning. Cloud operates it. Guard evaluates runtime admissibility.

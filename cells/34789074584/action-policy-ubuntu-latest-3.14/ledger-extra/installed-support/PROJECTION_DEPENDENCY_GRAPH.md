---
title: "Projection Dependency Graph"
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
  Canonical dependency, invalidation, freshness, and generation-order semantics
  for public Ledger governance projections.
---

# Projection Dependency Graph

Ledger projections are deterministic views over public governance artifacts. Dependency order matters because semantic extraction, reconciliation, compilation, execution projection, publication, and chronology replay must remain causally aligned.

## Source Facts

The projection graph starts from durable facts:

- `governance_source.v1`
- `governance_semantic_extraction.v1`
- `governance_semantic_reconciliation.v1`
- `semantic_commit_bundle.v1`
- `compiled_authority_contract.v1`
- `authority_bundle.v1`
- `publication_receipt.v1`
- `governance_event.v1`

These facts persist historically. Projections recompute from them.

## Canonical Generation Order

```text
governance_source.v1
  -> governance_semantic_extraction.v1
  -> governance_semantic_reconciliation.v1
  -> semantic_reconciliation_projection.v1
  -> semantic_commit_bundle.v1
  -> compiled_authority_contract.v1
  -> authority_execution_projection.v1
  -> execution_requirement_projection.v1
  -> execution_admissibility_projection.v1
  -> guard_enforcement_projection.v1
  -> runtime_consequence_projection.v1
  -> governance_impact_preview.v1
  -> authority_bundle.v1
  -> publication_receipt.v1
  -> governance_replay_state.v1
```

Diff projections compare durable artifacts across versions:

```text
previous compiled_authority_contract.v1
current compiled_authority_contract.v1
  -> semantic_authority_diff.v1
  -> authority_diff_impact.v1
  -> semantic_lifecycle_enforcement_projection.v1
  -> governance_replay_diff.v1
```

## Dependency Table

| Projection | Depends on | Purpose |
| --- | --- | --- |
| `semantic_reconciliation_projection.v1` | extraction, conflicts, ambiguities, interpretation decisions | Summarize interpretation completeness and unresolved semantic posture. |
| `compiled_authority_contract.v1` | semantic commit bundle | Emit deterministic contract structure from committed semantic meaning. |
| `authority_execution_projection.v1` | compiled authority contract | Summarize execution-facing authority requirements. |
| `execution_requirement_projection.v1` | compiled authority contract | Emit deterministic runtime requirement facts without evaluating execution. |
| `execution_admissibility_projection.v1` | compiled authority contract, execution requirements | Describe admissibility inputs Guard would require. |
| `guard_enforcement_projection.v1` | compiled authority contract | Isolate the subset of compiled authority Guard may consume. |
| `runtime_consequence_projection.v1` | compiled authority contract, execution projections | Describe runtime consequences without executing or blocking. |
| `governance_impact_preview.v1` | authority contract, semantic commit, compiled contract, execution projections | Render deterministic operational meaning. |
| `semantic_authority_diff.v1` | previous and current compiled contracts | Diff governance meaning instead of document structure. |
| `authority_diff_impact.v1` | previous and current authority artifacts or compiled contracts | Render operational impact of authority changes. |
| `semantic_lifecycle_enforcement_projection.v1` | semantic diff, compiled contracts, replay posture | Describe lifecycle invalidation and continuity consequences. |
| `governance_replay_state.v1` | append-only governance events and replay cutoff | Reconstruct governance posture at a point in time. |
| `governance_replay_diff.v1` | two governance replay states | Compare governance posture over time. |

## Freshness Fields

Freshness-capable projections should use:

```json
{
  "generated_at": "2026-06-03T00:00:00Z",
  "source_event_ids": [],
  "freshness_posture": "fresh",
  "projection_version": "v1",
  "projection_dependencies": []
}
```

Allowed `freshness_posture` values:

- `fresh`: projection source events match current source facts.
- `stale`: projection source events are older than current source facts.
- `invalidated`: a change explicitly invalidated the projection.
- `reconciled`: reconciliation found no divergence for the projection's source facts.

## Invalidation Propagation

Invalidation starts with a source artifact or governance event and propagates along dependency edges.

Examples:

- `governance_source_changed` invalidates extraction, reconciliation, semantic commit, compiled contract, impact preview, and publication readiness.
- `interpretation_decision_changed` invalidates semantic commit, compiled contract, execution projections, and impact preview.
- `compiled_contract_changed` invalidates execution requirements, admissibility projection, Guard enforcement projection, runtime consequences, authority bundle, and publication receipt.
- `authority_superseded` invalidates semantic diff, diff impact, lifecycle enforcement projection, and replay state for later cutoffs.
- `replay_posture_invalidated` invalidates runtime consequence projection, admissibility projection, impact preview, and replay state.

## Freshness Propagation

Freshness propagates downstream:

```text
stale semantic extraction
  -> stale reconciliation
  -> stale semantic commit
  -> stale compiled authority
  -> stale execution projections
  -> stale publication bundle
```

Invalidation is stronger than staleness:

```text
invalidated compiled authority
  -> publication blocked until recompilation
```

## Reconciliation Boundary

Reconciliation does not fix state and does not generate recommendations.

It only emits deterministic observations such as:

- unresolved ambiguity
- semantic conflict
- interpretation changed
- committed semantics stale
- compiled contract stale
- continuity posture changed
- replay posture inconsistent

This keeps Ledger in its proper role: semantic governance infrastructure, not automated policy remediation.

---
title: "Governance Object Model"
document_type: "reference"
system: "Governance-Ledger"
component: "core"
version: "0.4.0"
status: "draft"

created: "2026-05-08"
updated: "2026-05-24"

authors:
  - "Waveframe Labs"

maintainers:
  - "Waveframe Labs"

license: "Apache-2.0"

repository: "https://github.com/Waveframe-Labs/Governance-Ledger"

summary: >
  Reference model for Governance-Ledger review artifacts, lifecycle entries,
  compiled contract linkage, deployment provenance, snapshots, rollback
  provenance, governance diffs, and semantic artifacts.

related_components:
  - "CRI-CORE"
  - "Waveframe Guard"
  - "Proposal Normalizer"
  - "CRI-CORE Contract Compiler"

related_documents:
  - "README.md"
  - "LIFECYCLE.md"
  - "PROVENANCE.md"
  - "NON_GOALS.md"
  - "SEMANTICS.md"

governance_primitives:
  - "review_artifact"
  - "lifecycle_transition"
  - "deployment_provenance"
  - "snapshot"
  - "rollback"
  - "governance_diff"
  - "semantic_artifact"

determinism:
  deterministic_ids: true
  canonical_hashing: true
  mutable_history: false

provenance:
  review_lineage: true
  deployment_traceability: true
  rollback_traceability: true
  snapshot_integrity: true

ai_assisted: "partial"

notes: >
  This document defines object shapes and semantics for deterministic
  governance state evolution.
---

# Governance Object Model

This document describes the deterministic governance objects produced and transformed by Governance-Ledger.

The object model is the project ontology: governance text becomes structured state, and state evolves through explicit artifacts.

## Review Object

A review object is the central Governance-Ledger artifact.

```json
{
  "review_id": "review-001",
  "created_at": "2026-05-07T20:14:00Z",
  "source_document": "finance_policy.txt",
  "review_status": "pending",
  "detected_constraints": [],
  "warnings": []
}
```

Fields:

- `review_id`: stable review identifier.
- `created_at`: review artifact creation timestamp.
- `source_document`: source policy document name when known.
- `review_status`: lifecycle state.
- `detected_constraints`: deterministic extracted governance primitives.
- `warnings`: unsupported, ambiguous, or unextracted governance language.

## Naming Conventions

The following field names are canonical and should remain stable across code, schemas, and documentation:

- `review_status`
- `snapshot_hash`
- `deployment`
- `compiled_contract`
- `rollback`
- `detected_constraints`
- `warnings`
- `lifecycle`

Documents may use human-readable phrases such as "compiled contract linkage" in prose, but object keys should use the canonical snake_case names above.

## Operational Artifact Directories

Governance-Ledger separates draft, review, runtime, and recovery artifacts by directory:

- `policies/`: source governance text only.
- `generated/`: machine-generated extraction and validation artifacts.
- `reviews/`: human-review artifacts and deployed review lineage.
- `contracts/`: runtime contract artifacts only.
- `snapshots/`: deterministic frozen governance state snapshots.

Runtime contracts should only be written to `contracts/`.

Publication manifests are written to `contracts/` because they index runtime contract publication outputs.

Contract artifacts and publication manifests are immutable publication outputs. Re-running publication may confirm identical outputs, but it must not replace different content at the same path.

`contracts/index.json` is the published contract registry. It is the operational catalog for runtime discovery, audit visibility, and future registry integration.

Publication manifests and registry entries store artifact paths in POSIX style with `/` separators, for example `contracts/finance-policy-0.1.0.contract.json`, even when generated on Windows.

## Detected Constraints

Role requirement:

```json
{
  "type": "required_role",
  "value": "manager",
  "source_text": "require manager approval"
}
```

Separation of duties:

```json
{
  "type": "separation_of_duties",
  "value": true,
  "source_text": "must be separate"
}
```

Approval threshold:

```json
{
  "type": "approval_threshold",
  "field": "amount",
  "operator": ">",
  "value": 1000000,
  "requires_role": "manager",
  "source_text": "above $1M"
}
```

## Warnings

Warnings make governance loss visible.

Unsupported constraint:

```json
{
  "type": "unsupported_constraint",
  "text": "reasonable approval timing"
}
```

Ambiguous authority:

```json
{
  "type": "ambiguous_authority",
  "text": "appropriate manager"
}
```

Extraction gap:

```json
{
  "type": "extraction_gap",
  "text": "Transfers shall be reviewed quarterly."
}
```

## Lifecycle Entries

Lifecycle entries record state evolution.

```json
{
  "from_status": "pending",
  "to_status": "reviewed",
  "actor": "governance-team",
  "timestamp": "2026-05-07T20:14:00Z",
  "note": "Reviewed extracted constraints."
}
```

Rollback entries are also lifecycle entries, but they record restoration provenance:

```json
{
  "from_snapshot": "snapshot-abc123",
  "rollback_actor": "ops-team",
  "rollback_reason": "restore approved governance",
  "rolled_back_at": "2026-05-07T22:00:00Z"
}
```

## Compiled Contract Linkage

Governance-Ledger does not embed compiled contracts. It records lightweight linkage only.

```json
{
  "compiled_contract": {
    "contract_id": "finance-core",
    "contract_version": "1.0.0",
    "contract_hash": "abc123"
  },
  "compiled_by": "compiler-service",
  "compiled_at": "2026-05-07T20:30:00Z"
}
```

The full compiled contract remains an external artifact owned by the canonical compiler.

## Deployment Provenance

Deployment provenance records where a compiled governance contract was activated.

```json
{
  "deployment": {
    "environment": "production",
    "runtime": "waveframe-guard",
    "enforcement_engine": "cricore",
    "engine_version": "0.12.0",
    "deployed_by": "ops-team",
    "deployed_at": "2026-05-07T21:00:00Z"
  }
}
```

## Snapshot Object

A snapshot freezes a review state.

```json
{
  "snapshot_id": "snapshot-abc123",
  "created_at": "2026-05-07T21:30:00Z",
  "review_id": "review-001",
  "review_status": "deployed",
  "snapshot_hash": "abc123...",
  "review": {}
}
```

The `snapshot_hash` is deterministic over canonical JSON for the embedded review state.

## Rollback Provenance

Rollback restores a review from a validated snapshot and appends rollback provenance.

```json
{
  "rollback": {
    "from_review_id": "review-001",
    "from_review_status": "deployed",
    "to_snapshot_id": "snapshot-abc123",
    "to_review_id": "review-001",
    "to_review_status": "approved",
    "rollback_actor": "ops-team",
    "rollback_reason": "restore approved governance",
    "rolled_back_at": "2026-05-07T22:00:00Z"
  }
}
```

Rollback is a governance event. It does not erase history.

## Diff Structure

Review diffs compare governance versions.

```json
{
  "added_constraints": [],
  "removed_constraints": [],
  "modified_constraints": [],
  "new_warnings": [],
  "resolved_warnings": [],
  "deployment_changes": {
    "engine_version": ["0.12.0", "0.13.0"]
  }
}
```

Diffs are structural, not semantic guesses.

## Semantic Artifacts

Semantic artifacts are deterministic derivations from structured authority and publication artifacts. They live under `governance_ledger/semantics/` and are not runtime evaluations.

Canonical semantic artifacts:

- `governance_impact_preview.v1`: authority summary, enforcement behavior, consequences, lifecycle implications, and example governed outcomes.
- `authority_diff_impact.v1`: semantic impact of authority contract changes.
- `governance_review_packet.v1`: review packet binding semantic context, immutable inputs, and review metadata.
- `authority_bundle.v1`: publishable governance object binding authority, publication manifest, semantic artifacts, lineage, provenance, schema compatibility, and immutable inputs.

Semantic artifacts do not call Guard, call Cloud, mutate evidence, alter replay, bypass admissibility, or change execution outcomes.

## Versioned Schemas

Initial JSON Schemas live in [schemas/](schemas/):

- [review.schema.json](schemas/review.schema.json)
- [snapshot.schema.json](schemas/snapshot.schema.json)
- [deployment.schema.json](schemas/deployment.schema.json)
- [cricore_policy.schema.json](schemas/cricore_policy.schema.json)
- [publication_manifest.schema.json](schemas/publication_manifest.schema.json)
- [contract_registry.schema.json](schemas/contract_registry.schema.json)
- [governance_impact_preview.v1.json](schemas/governance_impact_preview.v1.json)
- [authority_diff_impact.v1.json](schemas/authority_diff_impact.v1.json)
- [governance_review_packet.v1.json](schemas/governance_review_packet.v1.json)
- [authority_bundle.v1.json](schemas/authority_bundle.v1.json)

Schemas are references for artifact shape stability. Runtime code remains deterministic and explicit; schemas document expected object boundaries.

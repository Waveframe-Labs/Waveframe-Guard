# Temporal And State Continuity

Ledger records temporal authority intent and resumed-workflow state posture expectations as semantic governance meaning. It does not use local wall-clock assumptions to decide runtime admissibility, and it does not perform runtime continuity enforcement.

## Temporal Authority Semantics

Temporal authority semantics describe how an authority expects time to be interpreted when validity windows or expiration language appears in source policy. Ledger records the intent so downstream systems can enforce or attest it consistently.

Canonical fields:

```json
{
  "temporal_semantics": {
    "schema_version": "temporal_authority_semantics.v1",
    "validity_window": "P30D",
    "timestamp_source": "execution_payload",
    "expiration_basis": "signed_execution_time",
    "runtime_enforced_by": "Guard/Cloud"
  }
}
```

Ledger records:

- `validity_window`: normalized duration intent, such as `P30D`.
- `timestamp_source`: the expected binding source, such as `execution_payload`, `signed_oracle`, `block_timestamp`, or `cloud_attested_time`.
- `expiration_basis`: the semantic basis used to interpret expiration.
- `runtime_enforced_by`: always outside Ledger for runtime enforcement.

If a policy says an approval is valid for a period but does not state the timestamp source, Ledger keeps the ambiguity explicit as `timestamp_source_unspecified`.

## State Posture Snapshot Semantics

State posture snapshot semantics describe what must be captured and compared when a workflow resumes after governance posture may have changed.

Canonical fields:

```json
{
  "state_snapshot_semantics": {
    "schema_version": "state_posture_snapshot_semantics.v1",
    "snapshot_required": true,
    "snapshot_hash_algorithm": "sha256",
    "snapshot_subject": "active_governance_state",
    "resume_comparison": "snapshot_hash_must_match_active_state_hash",
    "drift_result": "continuity_drift_detected",
    "runtime_enforced_by": "Guard/Cloud"
  }
}
```

Ledger records:

- what governance posture must be captured,
- which hash algorithm identifies the posture snapshot,
- how resumed workflows should compare prior posture against current posture,
- what semantic result constitutes continuity drift.

If a policy requires revalidation on resume but does not identify the snapshot subject, Ledger emits `state_snapshot_subject_unspecified`.

## Boundary

Ledger defines what must be captured, what must be compared, and what constitutes continuity drift.

Guard and Cloud own runtime enforcement or attestation of:

- timestamp source authenticity,
- actual runtime hash comparison,
- resumed workflow validation,
- execution blocking or admissibility decisions.

Ledger must not turn temporal or snapshot semantics into runtime admissibility evaluation.

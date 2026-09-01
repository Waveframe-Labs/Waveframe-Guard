# Artifact Semantics

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

Artifact semantics exist to make Guard's runtime artifacts replayable,
auditable, and deterministic. They do not define governance meaning.

## Persisted artifacts

A saved Guard run persists `guard_saved_evaluation.v1`.

The saved evaluation contains:

- `inputs`
  - `compiled_authority_contract.v1`
  - `normalized_execution_request.v1`
  - `guard_runtime_evidence_model.v1`
  - runtime dependencies
  - optional continuity posture

For native v2 decisions the same saved evaluation also carries compact
`guard_verified_authority_evidence.v1` identities, the actual derived runtime
fact set and its canonical hash, and the fact-projected request used for
evaluation. The full Ledger bundle and receipt remain at the authority-loading
boundary and are not duplicated into every event. Receipt input hashes bind the
compact authority evidence and fact set. A separate
`guard_execution_attestation.v1` records the decision, execution status, and
whether the mutation callback ran.
- `evaluation`
  - runtime admissibility result
  - runtime posture
  - chronology events
  - evaluation trace
  - enforcement outcome
- `guard_enforcement_outcome`
- `guard_enforcement_receipt.v1`
- `guard_continuation_lease.v1`
- `guard_release_validation.v1`
- `guard_artifact_manifest.v1`

The local store appends saved evaluations to:

```text
.guard-local/evaluation-history.jsonl
```

Receipts are exported to:

```text
.guard-local/receipts/<run_id>.json
```

Artifact manifests are exported to:

```text
.guard-local/manifests/<run_id>.json
```

Replay records are exported to:

```text
.guard-local/replays/<run_id>.json
```

Continuation leases are exported to:

```text
.guard-local/continuation-leases/<continuation_id>.json
```

Release validations are exported to:

```text
.guard-local/release-validations/<release_validation_id>.json
```

The Guard Inspector observes this local workspace. The normal operational loop
is:

```python
from guard.sdk import Guard

guard = Guard.local(workspace=".guard-local")

@guard.protect(authority="finance-policy@1.0.0")
def wire_transfer(request):
    return execute_transfer(request)
```

The SDK intercepts before mutation, emits the Evaluation artifact, Guard
Receipt, Artifact manifest, and Replay basis, and the Inspector loads those
artifacts from disk.

## Hashed artifacts

Guard uses canonical JSON for artifact hashing:

```text
json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
```

Every hash is SHA-256 with a `sha256:` prefix.

The artifact manifest hashes:

- all inputs
- full evaluation payload
- enforcement outcome
- receipt

The receipt also carries hashes for:

- compiled authority
- execution request
- runtime evidence
- continuity posture
- replay posture
- actor identity
- approval evidence
- execution context
- timestamp source
- runtime dependencies
- chronology

## Deferred release artifacts

Deferred release enforcement introduces two local deterministic artifacts:

- `guard_continuation_lease.v1`
- `guard_release_validation.v1`

A continuation lease proves that execution remained admissible after evaluation
and before release validation. It binds:

- continuation id
- execution id
- authority ref
- issued time
- admissible-until time
- runtime dependencies
- continuation status
- lease hash

Release validation decides whether release is allowed before execution. It can
emit:

- `release_allowed`
- `release_blocked`
- `revalidation_required`
- `continuation_invalidated`
- `dependency_expired`

`release blocked` means the original evaluation may have been admissible, but
the continuation lease no longer validates at release time.

## Replay basis

An artifact is replayable when it contains enough material to rerun
`evaluate_runtime(...)` deterministically.

The replay basis is:

- compiled authority
- normalized execution request
- actor identity
- continuity state
- replay posture
- evidence posture
  - approvals
  - execution context
  - runtime dependencies
- evaluation time
- start sequence

The receipt stores `replay_basis_hash`.

Replay succeeds when the replayed enforcement outcome hash equals the original
receipt outcome hash and the replay basis has not diverged from the original
deterministic identity.

Replay failure classes are deterministic:

- `contract_drift`
- `evidence_mutation`
- `chronology_mutation`
- `continuity_mismatch`
- `request_mismatch`
- `manifest_integrity_failure`

## Deterministic identity

`run_id` is derived from the deterministic identity basis.

The identity basis is:

- authority reference
- contract hash
- outcome hash
- execution request hash
- runtime evidence hash
- continuity posture hash
- replay basis hash

The receipt stores `deterministic_identity_hash`.

If replayable inputs change, deterministic identity changes.

## Lineage continuity

Lineage continuity means the receipt can prove that the decision, authority,
runtime evidence, replay posture, continuity posture, trace, and chronology
belong to the same evaluated execution.

The lineage continuity basis is:

- authority reference
- contract hash
- execution request hash
- runtime evidence hash
- continuity posture hash
- replay posture hash
- runtime dependency hash
- outcome hash
- evaluation trace hash
- chronology hash

The receipt stores `lineage_continuity_hash`.

This hash does not prove governance meaning. It proves the evaluated runtime
artifact chain has not been detached from its authority, evidence, chronology,
or outcome.

## What is not persisted as meaning

Guard artifacts must not persist raw policy text as a semantic authority.
Guard artifacts may reference compiled authority and its hashes, but they must
not become a backdoor compiler output or a duplicated governance schema.

If an artifact needs governance meaning, it must point to compiled authority.
If an artifact needs runtime explanation, it should point to the evaluation
trace, chronology, evidence, and receipt hashes.

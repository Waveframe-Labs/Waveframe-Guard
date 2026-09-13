---
title: "Event Ordering Semantics"
document_type: "architecture"
system: "Governance-Ledger"
component: "governance-events"
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
  Deterministic ordering, cutoff, replay, and checkpoint semantics for
  append-only Ledger governance events.
---

# Event Ordering Semantics

Governance chronology replay depends on deterministic event ordering.

Ledger must produce the same replay state for the same event stream and cutoff, even when the input list arrives unordered.

## Canonical Ordering

Events are ordered by:

1. `timestamp`
2. `event_id`

This means identical timestamps are resolved deterministically by event ID.

```text
sort_key = (timestamp, event_id)
```

## Replay Cutoff

Replay includes events where:

```text
event.timestamp <= replay_cutoff
```

Events after the cutoff are ignored.

If `replay_cutoff` is omitted, replay includes all valid events and the cutoff becomes the latest included timestamp.

## Missing Timestamp

Canonical governance events should always include a timestamp.

For strict event ingestion, missing timestamps should be rejected. For compatibility replay, missing timestamps may sort as an empty timestamp and should be treated as legacy or incomplete input.

Future ingestion layers should prefer rejection over silent ordering.

## Invalid Timestamp

Canonical governance timestamps should be ISO-8601 strings.

The initial chronology replay implementation compares timestamp strings and therefore assumes canonical ISO-8601 formatting. Future strict ingestion should validate timestamp format before persistence.

## Missing Event ID

Canonical governance events must include `event_id`.

Missing event IDs are invalid for canonical replay because event ID is the deterministic tie-breaker.

## Tie Breaks

When two events have the same timestamp:

```text
lower event_id sorts first
```

This avoids nondeterministic replay when multiple events occur in the same instant.

## Deterministic Replay Guarantees

Ledger guarantees:

```text
same events + same cutoff = same governance_replay_state.v1
same replay states = same governance_replay_diff.v1
```

Replay must not:

- call Guard
- call Cloud
- mutate source events
- evaluate execution admissibility

## Governance Chronology Checkpoints

Future checkpoint artifact:

```json
{
  "schema_version": "governance_chronology_checkpoint.v1",
  "checkpoint_id": "...",
  "replay_cutoff": "...",
  "governance_replay_state_hash": "sha256:..."
}
```

Checkpoints allow:

- replay verification
- chronology integrity checks
- deterministic replay attestation
- historical governance posture audit

Checkpoints must be derived from replay state. They must not replace append-only events as the source of truth.

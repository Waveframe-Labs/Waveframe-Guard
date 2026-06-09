# Telemetry Model

Guard telemetry records runtime enforcement cognition and chronology. It is
evidence of what Guard evaluated and did at runtime.

## Canonical invariant

Guard evaluates admissibility against compiled authority.
Guard never derives governance meaning from raw policy text.

## Telemetry owns

Guard telemetry may record:

- authority resolution started, completed, or failed
- lineage validation started, completed, or failed
- admissibility evaluation started and completed
- admissibility revalidation completed
- allow or block decisions
- missing approval evidence
- runtime continuity signals
- cache source and evidence queue state
- audit receipts

Telemetry describes runtime posture. It is not a semantic source of truth.

## Telemetry must include authority context

Telemetry should retain enough authority context to make decisions auditable:

- `authority_ref`
- `contract_ref`
- `contract_hash`
- authority lifecycle status when available
- cache or registry source when available
- decision reason
- continuity signals when available

## Telemetry must not include governance derivation

Telemetry must not claim to explain how governance meaning was extracted from
raw policy text. If telemetry needs to reference governance meaning, it should
reference the compiled authority and its metadata.

## Audit posture

Audit evidence should prove:

- which compiled authority was used
- what execution state was evaluated
- what decision Guard reached
- why Guard allowed or blocked the execution
- when revalidation became required

Audit evidence should not become a backdoor governance schema or compiler.

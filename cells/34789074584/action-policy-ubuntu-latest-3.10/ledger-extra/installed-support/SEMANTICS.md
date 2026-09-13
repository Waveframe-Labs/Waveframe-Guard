---
title: "Semantic Governance Artifacts"
document_type: "reference"
system: "Governance-Ledger"
component: "semantics"
version: "0.4.0"
status: "draft"

created: "2026-05-24"
updated: "2026-05-24"

authors:
  - "Waveframe Labs"

maintainers:
  - "Waveframe Labs"

license: "Apache-2.0"

repository: "https://github.com/Waveframe-Labs/Governance-Ledger"

summary: >
  Canonical semantic derivation artifacts for deterministic governance
  interpretation, operational consequence derivation, review packets, and
  authority bundles.
---

# Semantic Governance Artifacts

Governance-Ledger owns deterministic governance meaning for structured authority artifacts.

The semantic layer lives under `governance_ledger/semantics/`. It derives canonical artifacts from authority contracts and publication evidence. It does not invoke Guard, Cloud services, replay execution, simulation, or admissibility evaluation.

## Boundary

Ledger owns governance meaning:

- deterministic governance interpretation
- operational consequence derivation
- lifecycle and continuity implications
- semantic lineage artifacts
- publishable authority bundles

Cloud owns governance operations:

- ingest
- validate
- store
- replay
- operate

Guard owns governance admissibility:

- runtime allow or block decisions
- execution-state evaluation
- enforcement traces

The plain customer-policy boundary is also Ledger-owned but intentionally narrow. `interpret_customer_policy(...)` is a pure deterministic recognizer for the published v0.6 sentence grammar, not general natural-language interpretation. `finalize_customer_policy_authority(...)` reconstructs and validates that interpretation, applies only bounded interpreter-produced resolution options, binds explicit human approval, and sends canonical structured input to the installed contract compiler. Cloud may orchestrate these calls and persist their returned artifacts, but it does not redefine their meaning.

Customer-policy publication requires at least one confirmed enforceable rule. Required acting roles, conditional approval thresholds, target allow/deny rules, and separation-of-duties constraints are separate semantic categories. Ledger validates their equivalence across final normalized meaning, semantic commit, compiler input, and compiled contract before returning publication-ready artifacts; an acting role is never projected as an approver role.

## Canonical Artifacts

`governance_impact_preview.v1`

Derives a deterministic preview from `authority_contract.v1`, including governance summary, enforcement behavior, operational consequences, lifecycle implications, and example governed outcomes.

`authority_diff_impact.v1`

Derives semantic impact from old and new authority contracts, including changed governance rules, operational implications, escalation impact, lifecycle continuity implications, and replay continuity implications.

`governance_review_packet.v1`

Builds a review-ready packet from authority, preview, optional diff impact, optional execution evidence, and optional review metadata. It binds immutable input hashes and explicit non-goals.

`authority_bundle.v1`

Builds the publishable governance object from authority contract, publication manifest, preview, optional diff impact, optional review packets, lineage, provenance, schema compatibility, and immutable inputs.

## Deterministic Guarantees

Semantic artifacts are stable for identical structured inputs.

Plain-policy drafts are stable for identical exact bytes and identities. Final semantic commits, compiled contracts, authority bundles, and receipts are stable for identical complete interpretation, resolution, approval, commit, and publication inputs. Exact bytes remain distinct across LF/CRLF, trailing-newline, Unicode normalization-form, whitespace, and punctuation differences.

They are derived only from supplied artifact fields. They must not:

- call Guard
- call Cloud
- perform runtime admissibility evaluation
- mutate evidence
- alter replay
- change execution outcomes
- infer unsupported governance meaning

## CLI Examples

```powershell
governance-ledger preview `
  contracts/finance-policy-0.1.0.contract.json `
  --output generated/finance-policy.preview.json

governance-ledger diff-impact `
  --old contracts/finance-policy-0.1.0.contract.json `
  --new contracts/finance-policy-0.2.0.contract.json `
  --output generated/finance-policy.diff-impact.json

governance-ledger review-packet `
  --authority contracts/finance-policy-0.1.0.contract.json `
  --preview generated/finance-policy.preview.json `
  --output generated/finance-policy.review-packet.json

governance-ledger authority-bundle `
  --authority contracts/finance-policy-0.1.0.contract.json `
  --manifest contracts/finance_policy.publication_manifest.json `
  --preview generated/finance-policy.preview.json `
  --output generated/finance-policy.authority-bundle.json
```

## Schema References

- [schemas/governance_impact_preview.v1.json](schemas/governance_impact_preview.v1.json)
- [schemas/authority_diff_impact.v1.json](schemas/authority_diff_impact.v1.json)
- [schemas/governance_review_packet.v1.json](schemas/governance_review_packet.v1.json)
- [schemas/authority_bundle.v1.json](schemas/authority_bundle.v1.json)

## Publishable Governance Object

`authority_bundle.v1` is the publishable governance object.

It lets downstream systems ingest a single canonical bundle instead of reconstructing governance context from separate files. The bundle includes authority identity, contract hash, manifest provenance, semantic artifacts, optional review packets, lineage, schema compatibility, and immutable input hashes.

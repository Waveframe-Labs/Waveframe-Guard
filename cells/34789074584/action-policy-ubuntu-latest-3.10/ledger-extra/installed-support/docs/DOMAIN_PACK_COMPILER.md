# Deterministic Domain-Pack Policy Compiler

## Scope

A Waveframe domain pack is an immutable, versioned compiler contract for one bounded policy domain. It is more than a lexicon: it binds scoped vocabulary and synonyms, typed resource contracts, types and units, an exact runtime-fact schema, one installed deterministic grammar/compiler, namespaced mapping-control emitters, semantic validation rules, one compiler lowering, conformance vectors, and a canonical hash.

Waveframe Ledger v0.8.0 ships only `repository-changes` / `1.0.0`. Packs are canonical data bound to exact trusted implementations installed with Ledger. Arbitrary data-only packs, remote executable plugins, remote installation, a marketplace, and a hosted registry are not supported. A later platform release may let organizations host private pack artifacts, but execution will still require a locally trusted implementation bound by exact identity, version, and hash.

No domain-pack operation calls an AI model, probabilistic classifier, embedding service, external inference service, spaCy heuristic, network lookup, or filesystem. Arbitrary company prose cannot be automatically interpreted under this contract, and Ledger does not claim otherwise.

## Representations

The original policy is the customer's exact UTF-8 bytes and their complete ordered statement spans. Canonical controlled language (CNL) is a deterministic human-readable preview of selected meaning. Waveframe-owned `constraint_ir.v1` is the canonical typed enforcement meaning; it is not Rego, Cedar, DMN, or JSON Logic. The compiled authority is the existing deterministic compiler output produced by the pack's trusted lowering.

CNL is derived from Constraint IR and is never an injection surface. Console users will later choose bounded form or decision-table controls; they do not author policy JSON or rule JSON.

## Constraint IR, resources, and runtime facts

`constraint_ir.v1` represents subject/principal selectors, acting roles, actions, typed resource selectors, allow/deny/require effects, explicitly grouped Boolean conditions, typed literals and canonical units, approval and evidence obligations, separation of duties, explicit conditional exceptions, and exact required runtime facts.

The generic IR has no repository-path rule. Each pack declares a strict resource contract per resource kind: permitted match modes, value type, null policy, optional enum, exact optional format-validator identity, and value fact. Ledger invokes only a validator bound to the pack's exact trusted compiler. Unknown emitters and format validators fail closed. Repository-relative path safety is therefore strict only when the repository pack selects its namespaced validator.

`runtime_fact_schema.v1` gives each fact an exact dotted identity, type, optional enum, canonical unit, required status, supported operators, and optional proposal-field derivation as a canonical pointer such as `/resource/path`. Version 1 has no free-form expression derivation and executes no speculative expressions.

Runtime-fact availability is a publication gate. Ledger rejects unavailable or mismatched facts rather than omitting a condition. A diagnostic is actionable, for example: “This rule requires account.created_at, but the selected runtime schema does not provide it.”

Validation also rejects unknown fields, symbols, operators, incompatible comparisons, implicit precedence, untyped values, contradictory effects, malformed exceptions, and empty enforceable rule sets.

The IR can represent advanced Boolean conditions, approval and evidence obligations, separation of duties, and exceptions, but representation is not a claim of lowering support. The repository pack's current lowering supports only acting-role requirements and exact/prefix repository-path allow/deny rules. Any advanced IR concept fails closed during lowering until an exact compiler surface supports it.

## Direct parsing and explicit statement decisions

A matching clause is parsed deterministically. Every other nonempty statement is `pending`; no global keyword heuristic infers that it is informational.

`inspect_policy_mapping_controls(...)` returns the selected pack's enforcement controls plus two fixed non-enforcement dispositions. `apply_policy_mapping_decision(...)` records exactly one disposition:

- `enforced` selects one available pack control and produces a constraint;
- `informational` explicitly records why no constraint is intended;
- `unsupported` explicitly records why no constraint can be produced by this pack.

All dispositions bind the exact source hash, statement ID and byte span, pack identity/version/hash, bounded reason, mapper, canonical UTC time, and decision hash. Only enforced decisions contain a control, selections, typed enforcement fields, and constraint ID. Unknown selection fields, arbitrary rule injection, changed source/span/pack bindings, and modified decisions fail replay.

Finalization requires every nonempty statement to have a direct parse or explicit decision, no pending statement, and at least one enforceable constraint. Informational and unsupported statements remain visible and provenance-bound and never silently disappear.

## Built-in repository pack and v0.6 compatibility

`repository-changes` / `1.0.0` contains only repository concepts: agent subjects; repository-maintainer, repository-reviewer, and security-reviewer roles; the `modify` action; repository-change and repository-path resources; proposal facts; and acting-role, exact-path allow/deny, and path-prefix allow/deny controls.

It contains no finance action, resource, fact, unit, synonym, control, or vector. Finance prose is pending when this pack is selected and needs an explicit human disposition. A finance pack is not included in v0.8.0.

The released v0.6 compatibility APIs retain their byte-identical behavior and hashes, including approval thresholds, requester/approver separation, ambiguity handling, and finance examples:

- `interpret_customer_policy(...)`
- `interpret_customer_policy_text(...)`
- `finalize_customer_policy_authority(...)`

Those APIs intentionally remain on their isolated compatibility path and continue to emit v1 publication artifacts.

## Public API

```python
from governance_ledger import (
    apply_policy_mapping_decision,
    finalize_domain_policy_authority,
    get_builtin_domain_pack,
    inspect_policy_mapping_controls,
    interpret_policy_with_domain_pack,
    list_builtin_domain_packs,
    validate_authority_bundle,
    validate_constraint_ir,
    validate_domain_pack,
    validate_publication_receipt,
    validate_runtime_fact_compatibility,
    validate_runtime_fact_schema,
)

pack = get_builtin_domain_pack("repository-changes", "1.0.0")
draft = interpret_policy_with_domain_pack(
    exact_policy_bytes,
    domain_pack_id="repository-changes",
    domain_pack_version="1.0.0",
    source_policy_id="repository-policy",
    source_revision="rev-17",
    authority_id="repository-authority",
    authority_version="1.0.0",
)

controls = inspect_policy_mapping_controls(draft, statement_id)
application = apply_policy_mapping_decision(
    draft,
    statement_id=statement_id,
    disposition="enforced",
    control_id="exact-path-access",
    selections={"effect": "allow", "path": "README.md"},
    mapper_identity="policy-owner@example.com",
    mapped_at="2026-08-30T19:00:00Z",
)
draft = application["updated_interpretation"]

application = apply_policy_mapping_decision(
    draft,
    statement_id=another_statement_id,
    disposition="unsupported",
    reason_code="outside-domain",
    mapper_identity="policy-owner@example.com",
    mapped_at="2026-08-30T19:01:00Z",
)

publication = finalize_domain_policy_authority(
    application["updated_interpretation"],
    approval_id="approval-001",
    approved_by="policy-owner@example.com",
    approved_at="2026-08-30T19:30:00Z",
    committed_by="policy-owner@example.com",
    committed_at="2026-08-30T19:45:00Z",
    publication_id="publication-001",
    published_by="publisher@example.com",
    published_at="2026-08-30T20:00:00Z",
)

validate_authority_bundle(publication["authority_bundle"])
validate_publication_receipt(publication["authority_bundle"], publication["publication_receipt"])
```

Direct-only policies skip decision calls. A multi-clause policy applies decisions successively to each application's `updated_interpretation`.

## Publication boundary and provenance

Released `semantic_commit_bundle.v1`, `authority_bundle.v1`, and `publication_receipt.v1` remain unchanged. The new workflow emits one native, complete `authority_bundle.v2` and one `publication_receipt.v2`; neither nests a v1 bundle or receipt. The normal public validators dispatch by schema version, so callers work with authority bundles rather than a separate “domain policy bundle” concept.

`authority_bundle.v2` directly binds:

```text
exact source bytes and identity
→ complete ordered statement spans
→ direct parses or explicit policy_mapping_decision.v1 records
→ source-to-constraint mappings and canonical CNL previews
→ constraint_ir.v1 and runtime_fact_schema.v1
→ domain_pack.v1 identity/version/hash
→ semantic_commit_bundle.v1
→ compiled_authority_contract.v2
→ authority identity/version and approval record
→ publication manifest and complete provenance bindings
→ authority_bundle.v2
→ publication_receipt.v2
```

`compiled_authority_contract.v2` is a standalone strict schema for only the presently compiled repository surface: optional required roles plus exact/prefix target allow/deny rules. It is not an alias for the structurally different released `compiled_authority_contract.v1`. `authority_bundle.v2` references the standalone v2 schema rather than duplicating its definition.

The v2 JSON schemas strictly define or reference security-critical nested components. Runtime validation additionally reconstructs source partitions and mapping replay, regenerates and independently validates the v2 compiled contract, cross-checks all identities and hashes, and verifies the receipt. Schema-valid semantic tampering therefore still fails. Missing lineage is never inferred for historical v1 artifacts.

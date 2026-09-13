---
title: "Published Authority Specification"
filetype: "documentation"
type: "platform-contract"
domain: "governance-publication"
version: "1.0.0-draft"
status: "Draft"
created: "2026-07-13"
updated: "2026-09-04"
author:
  name: "Waveframe Labs"
license: "Apache-2.0"
ai_assisted: "partial"
---

# Published Authority Specification

## 1. Purpose

This document defines **Published Authority** as the canonical governance publication concept used across the Waveframe platform.

A Published Authority is not merely a compiled contract file. It is an immutable, version-addressed governance publication that binds deterministic enforcement semantics to the evidence required to identify, verify, distribute, inspect, and replay that authority.

The platform lifecycle is:

```text
Human policy
  -> Ledger review and approval
  -> deterministic compilation
  -> Published Authority
  -> registry resolution
  -> Guard enforcement
  -> Cloud preservation
  -> Operations inspection
```

This specification establishes the boundary between governance authoring and runtime enforcement. Ledger owns publication. Guard consumes published authority. Cloud stores and distributes it. Operations surfaces its state and evidence.

## 2. Product ownership

| Component | Responsibility |
| --- | --- |
| Waveframe Ledger | Author, review, approve, compile, publish, and register authority. |
| Contract Compiler | Produce deterministic compiled enforcement semantics. |
| Waveframe Guard | Resolve an explicit authority reference and enforce it before execution. |
| CRI-CORE | Evaluate admissibility under the resolved compiled authority. |
| Waveframe Cloud | Store, distribute, preserve, and lifecycle-manage published authority and execution evidence. |
| Operations | Explain publication state, runtime outcomes, receipts, lineage, and replay history. |

No component other than Ledger may redefine the semantic contents of a Published Authority.

## 3. Canonical term

The user-facing platform term is:

```text
Published Authority
```

The canonical machine-readable publication objects are the versioned
`authority_bundle` schema family:

```text
authority_bundle.v1
authority_bundle.v2
authority_bundle.v3
```

Each is a transport and preservation representation of a Published Authority. Version
1 remains the compatibility representation, version 2 adds the native domain-pack
publication chain, and version 3 additively binds multi-control and partial-coverage
translation commitments. The conceptual name and schema names serve different purposes:

- **Published Authority** is the product and domain concept.
- **`authority_bundle.v1`**, **`.v2`**, and **`.v3`** are compatible, explicitly
  versioned serialized representations.

A compiled contract by itself is not a Published Authority.

## 4. Authority identity

Every Published Authority MUST have an immutable identity composed of:

```text
authority_id + authority_version + contract_hash
```

The canonical human- and API-facing reference is:

```text
<authority_id>@<authority_version>
```

Example:

```text
finance-policy@1.2.0
```

The reference identifies a single published version. The `contract_hash` verifies the immutable compiled authority resolved by that reference.

### 4.1 Identity requirements

A Published Authority MUST include:

- `authority_id`
- `authority_version`
- `authority_ref`
- `contract_hash`
- `publication_id`
- `published_at`
- `schema_version`

The following invariant MUST hold:

```text
authority_ref == authority_id + "@" + authority_version
```

A registry MUST reject ambiguous or unversioned runtime resolution.

The following is valid:

```text
finance-policy@1.2.0
```

The following is not a deterministic runtime reference:

```text
finance-policy
```

Aliases such as `latest` or `active` may exist in operator-facing discovery surfaces, but Guard MUST resolve them to an explicit immutable authority reference before enforcement begins.

## 5. Required publication contents

A Published Authority MUST bind the following classes of information.

### 5.1 Compiled enforcement authority

The deterministic compiled authority consumed by Guard and CRI-CORE, including:

- contract identifier
- contract version
- authority requirements
- approval requirements
- artifact requirements
- stage requirements
- invariants
- contract hash

### 5.2 Publication identity

The immutable publication record, including:

- publication identifier
- publication timestamp
- publisher identity or publishing actor
- authority reference
- publication status
- publication schema version

### 5.3 Governance lineage

The evidence connecting the published authority to its source and review process, including as applicable:

- source governance identity
- source hash
- compilation report hash
- review identifier
- approval evidence
- compiler identity and version
- provenance chain

### 5.4 Semantic review artifacts

The deterministic artifacts required to understand the authority without reinterpreting policy, including as applicable:

- governance impact preview
- authority diff impact
- governance review packet
- diagnostics
- compatibility declarations

### 5.5 Publication integrity

The hashes and manifests required to verify that the publication has not changed, including:

- contract hash
- publication manifest hash
- bundle hash or equivalent canonical object hash
- bound artifact hashes
- schema compatibility metadata

### 5.6 Provenance-complete customer-policy profile

`authority_bundle.v1` remains the canonical schema. A new customer-authored publication declares `provenance_profile: customer_policy_provenance_complete_v1` and includes:

- `source_policy`: source identity, independent source revision, derived source reference, base64-preserved exact bytes, and byte-level SHA-256;
- `source_statements`: full-SHA-256-derived identities, ordered non-overlapping byte spans that partition the entire source, exact statement bytes, statement hashes, and exactly one final classification (`enforced`, `informational`, `unsupported`, or `requires_resolution`);
- `interpretation`: interpretation identity, sentence-to-confirmed-rule mappings, and mapping hash;
- `resolution`: resolution-set identity and ordered records that bind stable ambiguity and resolution identities, referenced statement identities, the selected decision or meaning, resolver, UTC resolution time, and the complete record-set hash;
- `approval_record`: approval identity, actor, timestamp, approved semantic-commit hash, and record hash;
- `version_binding`: the source-policy reference, published authority reference, named relationship, and binding hash.

The source reference is `<source_policy_id>@<source_revision>`; neither component may contain `@`. It is not the authority reference and its revision is not required to equal the authority version. This profile currently permits only the canonical `publishes_as` relationship, valid only when both references and the relationship match the canonical `version_binding.binding_hash`.

The exact source must be non-empty UTF-8 text. Every byte belongs to exactly one statement. `enforced` statements have exactly one mapping with one or more confirmed rule IDs; `informational` and `unsupported` statements have none. A complete publication contains no `requires_resolution` statement, and the union of mapped rules equals the confirmed semantic rule set.

The profile is bounded for short operational policies: at most 245,760 decoded source bytes (240 KiB), 2,048 statements, 1,024 statement mappings, and 1,024 resolution records. Source and statement bytes use canonical base64: decoding and re-encoding must reproduce the supplied string exactly. Document ingestion is outside this profile.

The semantic commit binds the source snapshot, stable statement set, interpretation mapping, and resolution set. Approval attests the resulting semantic-commit hash. The compiled contract binds that commit; the bundle immutable inputs bind the approval, compiled contract, authority identity, and version relationship; the receipt binds all of them plus the canonical bundle hash.

Artifacts without this explicit profile are `legacy_provenance_incomplete`. Readers must not reconstruct or infer missing historical source bytes, spans, mappings, resolutions, or approval evidence.

### 5.7 Plain-policy authority workflow

Ledger exposes two pure programmatic stages for customer-authored short operational policies. `interpret_customer_policy(...)` accepts exact UTF-8 bytes plus independent source-policy and authority identities and produces an immutable interpretation draft. `finalize_customer_policy_authority(...)` accepts that draft, interpreter-produced-option selections, and explicit human approval, commit, and publication evidence. Neither stage reads or writes files, imports Guard or Cloud, invokes a CLI, or accepts free-form rule JSON.

The interpreter recognizes only the v0.6 grammar documented in `README.md`. Similar-looking normative language is retained as `unsupported`; ambiguous normative qualifiers are `requires_resolution`; other prose is `informational`. Duplicate rules and allow/deny overlaps also require a bounded resolution. Publication is forbidden until every ambiguity has one valid selection and no contradictory confirmed meaning remains.

Finalization reconstructs the draft from its exact embedded source rather than trusting supplied derived fields. Confirmed rules are projected into `authority.required_roles`, `targets.allow`, `targets.deny`, `approvals.thresholds`, and separation-of-duties constraints, then compiled through the installed canonical CRI-CORE Contract Compiler. No inferred rule becomes enforceable: only grammar-produced rules retained in the explicitly approved semantic commit are compiled.

A zero-rule interpretation is not publishable. It remains available for review with completed statement classifications, but readiness requires no unresolved ambiguity and at least one enforceable rule. A recognized ambiguity modifier may expose one bounded enforceable choice only when its deterministic removal produces exactly one supported rule. Resolution, approval, commit, and publication evidence must satisfy `resolved_at <= approved_at <= committed_at <= published_at`; records retain caller order.

### 5.8 Domain-pack publication extension

The production domain-pack path is documented in `docs/DOMAIN_PACK_COMPILER.md`. It does not mutate the meaning of `semantic_commit_bundle.v1`, `compiled_authority_contract.v1`, `authority_bundle.v1`, or `publication_receipt.v1`. It emits standalone `compiled_authority_contract.v2` for the presently supported repository lowering and a native `authority_bundle.v2` that directly binds exact source and statements, direct parses and explicit human statement decisions, canonical CNL, Constraint IR, selected runtime schema, exact pack identity/version/hash, semantic commit, compiled authority, approval, manifest, and complete provenance. `publication_receipt.v2` directly binds that complete v2 bundle and its critical component identities and hashes.

No v1 bundle or receipt is nested inside v2. Version-aware authority validators preserve the exact v1 path and validate v2 by reconstructing statement decisions, semantic commitment, compilation, and publication bindings. Historical v1 artifacts remain readable, and Ledger does not infer new lineage for them.

### Additive multi-control publication

`authority_bundle.v3` is the native successor for one source clause that publishes zero
or more individually confirmed controls while retaining explicitly acknowledged
residual meaning. It embeds `policy_translation_commitment.v1`, exact source bytes and
clause spans, resolved customer bindings, trusted capability identity, Constraint IR,
runtime-fact and domain-pack identity, grammar/lowering/emitter identity, semantic
commit, public approval, unchanged `compiled_authority_contract.v2`, authority identity,
manifest, and complete canonical provenance bindings. `publication_receipt.v3` binds
that exact bundle and the same public chain.

The v3 commitment excludes translation runs, provider/model/prompt attribution, raw
responses, retries, failures, explanations, and token usage. Those are private authoring
evidence and may be deleted without affecting publication or execution. Customer text is
rendered deterministically from validated controls and residual dispositions.

This is additive, not an upgrade of existing artifacts. Released v2 schemas, hashes,
fixtures, dispatch, and validation behavior remain unchanged. Consumers must opt into
v3 explicitly. Guard 0.17.0 verifies and enforces native v3 publications; the embedded
runtime payload remains `compiled_authority_contract.v2`. Hosted Cloud authoring and
native v3 serving are not yet available.

## 6. Publication transaction

Publication MUST be treated as one deterministic transaction.

A successful Ledger publication produces or updates all required artifacts together:

```text
compiled authority contract
publication manifest
authority bundle
registry entry
deployed review record
snapshot
publication receipt
```

Publication MUST fail without partial registration when any required gate fails.

Blocking conditions include:

- review is not approved
- compilation diagnostics block publication
- authority identity conflicts with an existing immutable version
- contract hash does not match the compiled authority
- required lineage evidence is missing or inconsistent
- registry update cannot be completed
- snapshot or receipt generation fails where required by the publication transaction

Published artifacts are immutable. Corrections require a new authority version and a new publication.

## 7. Registry contract

The authority registry is the deterministic discovery surface between publication and enforcement.

A registry entry MUST allow a consumer to resolve:

```text
finance-policy@1.2.0
```

into the corresponding Published Authority or its compiled enforcement subset.

### 7.1 Minimum registry entry

A registry entry MUST include:

- `authority_ref`
- `authority_id`
- `authority_version`
- `contract_hash`
- `bundle_hash`
- `bundle_path` or equivalent retrieval identifier
- `publication_id`
- `published_at`
- `lifecycle_state`

### 7.2 Lifecycle state

Supported lifecycle states are:

- `active`
- `superseded`
- `revoked`

Lifecycle state does not alter the immutable contents of the published version. It is append-only operational metadata associated with that version.

Guard policy determines whether a resolved state is acceptable. For example, a runtime may reject revoked authority and warn on superseded authority.

### 7.3 Registry implementations

The registry contract MUST remain implementation-independent.

Valid implementations may include:

- Ledger local publication registry
- verified local cache
- Waveframe Cloud organization registry
- self-hosted enterprise registry
- offline registry snapshot

Guard MUST depend on the registry interface and canonical publication contract, not on Ledger file paths or Cloud-specific storage internals.

## 8. Guard resolution contract

The intended developer-facing API is explicit authority selection:

```python
@guard.protect(authority="finance-policy@1.2.0")
def transfer(execution_request):
    ...
```

The resolution sequence is:

```text
authority reference
  -> registry lookup
  -> publication identity verification
  -> contract hash verification
  -> lifecycle-state check
  -> compiled authority extraction
  -> local enforcement
```

Guard MUST NOT:

- interpret source policy
- choose an authority version implicitly at enforcement time
- trust a contract whose hash does not match the publication identity
- require knowledge of Ledger's internal file layout
- make Cloud availability a prerequisite for a locally cached admissibility decision

## 9. Cloud contract

Cloud stores and distributes Published Authorities but does not author or reinterpret them.

Cloud MAY:

- accept a canonical `authority_bundle.v1`
- validate schema shape and hashes
- enforce organization ownership
- preserve immutable publication artifacts
- expose explicit authority lookup
- maintain lifecycle metadata
- issue durable publication receipts
- distribute verified authority to Guard
- export replay and recovery packages

Cloud MUST NOT:

- compile source policy into authority
- modify published authority semantics
- decide runtime admissibility
- replace Guard or CRI-CORE as the execution boundary

## 10. Operations contract

Operations surfaces the state of Published Authority across the platform.

The operator experience SHOULD expose:

- authority reference
- version
- contract hash
- publication identifier
- publisher
- publication time
- lifecycle state
- review and approval status
- source and compilation lineage
- deployment and cache posture
- Guard usage and associated outcomes
- receipts and replay packages

Operations explains what happened and what needs attention. It does not author policy or decide admissibility.

## 11. Naming and compatibility

The repository is named **Waveframe Ledger**.

The Python distribution name MAY remain:

```text
governance-ledger
```

The repository name, product name, import package, and PyPI distribution name are independent identifiers. Renaming the GitHub repository does not require changing:

- the PyPI project name
- the `governance_ledger` Python package
- the `governance-ledger` CLI command

A package rename should occur only as a deliberate compatibility migration, not as a consequence of repository branding.

## 12. Sprint 1 acceptance criteria

Sprint 1 is complete when Waveframe Ledger can prove the following locally:

1. Publishing produces a stable `authority_ref`.
2. Publishing produces a stable `publication_id`.
3. Publishing binds the exact compiled `contract_hash`.
4. Publishing emits a canonical `authority_bundle.v1`.
5. The local registry records the authority bundle by explicit versioned reference.
6. A lookup for `finance-policy@1.2.0` deterministically resolves the correct immutable publication.
7. Duplicate publication of the same identity cannot silently replace different contents.
8. Published identity and registry behavior are covered by tests.
9. Existing publication, snapshot, lineage, and replay behavior remains compatible.
10. Guard-specific loading is deferred until the Ledger publication contract is complete.

## 13. Non-goals for Sprint 1

Sprint 1 does not include:

- hosted Cloud retrieval
- Guard networking
- billing or entitlements
- organization administration UI
- policy interpretation by an AI model
- runtime enforcement changes
- replacement of existing canonical schemas without a demonstrated incompatibility

## 14. Governing principle

A governance policy becomes operational only when it is published as immutable, verifiable, version-addressed authority.

```text
Ledger publishes authority.
Guard resolves and enforces authority.
Cloud preserves and distributes authority.
Operations explains authority and its consequences.
```

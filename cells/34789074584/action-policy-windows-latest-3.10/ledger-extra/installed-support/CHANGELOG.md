# Changelog

## 0.9.0 - Unreleased

Raw legacy contract/execution-state replay requires an explicit injected evaluator.
Guard 0.19's retired evaluator is reported through Ledger integration errors and
CLI exit code 2; the `[guard]` extra does not restore it. Native publication and
saved logical replay use Guard's supported SDK/store, with mediated repository
writes. Issue #25 validates exact candidate archives and installed resource bytes
and requires all four source/installed/combined acceptance cells. Release readiness
remains false pending Guard repinning, Cloud final-set acceptance and coordination.

- Prepare explicit release catalog 3 for independently authorized create/modify
  actions, fresh human approval and public compiler-independent verification.
  Catalog 1 remains the default; catalog 2 development identities, opt-ins,
  approved wording and historical fixture bytes remain immutable.
- Require `cricore-contract-compiler>=0.5.0,<0.6.0` and its public action API,
  without fallback. Acceptance uses unchanged Compiler #8 at
  `ae590dee058d3481e384dea850d5b7d980f533ff`.
- Declare `waveframe-guard>=0.19.0,<0.20.0` in `[guard]`. The intended
  Ledger 0.9.0 / Guard 0.19.0 pair has **pending install and execution
  compatibility** until the separate real Guard candidate passes combined acceptance.
- Split Windows/Linux, Python 3.10/3.14 source and clean-installed base acceptance
  from the downstream extra gate. Retain published historical runtime checks.
  Compatible-runtime acceptance and separate activation remain required; this
  candidate is not fully release-ready and authorizes no publication or deployment.

## 0.8.0 - 2026-09-04

Waveframe Ledger v0.8.0 introduces an untrusted policy-translation proposal boundary
and additive native v3 publication while preserving every released v1/v2 schema and
compatibility behavior.

### Added

- Strict, model-agnostic `policy_translation_proposal.v1` authoring, finite capability
  catalogs, canonical human confirmation and approval, deterministic review rendering,
  exact clause coverage, and enforced translation-run chronology.
- Ordered zero-or-more candidate controls per clause, with independent human
  confirmation for every control and explicit full, partial, unsupported, or
  informational clause coverage.
- Provider-free `policy_translation_commitment.v1`, `authority_bundle.v3`, and
  `publication_receipt.v3` artifacts for clause-to-many-control meaning and explicitly
  acknowledged residual meaning.
- Six deterministic customer coverage states and exact full, partial, waiting,
  unenforced, informational, confirmed-control, and acknowledged-residual totals.

### Changed

- Restored the optional `guard` extra with the exact release-tested dependency
  `waveframe-guard==0.17.0`. Guard 0.17.0 verifies native v3 publications and enforces
  their unchanged `compiled_authority_contract.v2` runtime payload.
- Provider and model evidence remains private, independently deletable authoring
  evidence. Ledger neither calls nor bundles an AI or model provider, and published
  authority contains no provider, model, prompt, retry, token-usage, request, response,
  or private run evidence.

### Compatibility

- Existing v1/v2 schemas, validators, fixtures, canonical hashes, and compatibility
  behavior remain unchanged. Native v3 is additive and explicitly selected.
- Partial coverage enforces only independently confirmed published controls; exact
  acknowledged residual meaning remains public provenance and never becomes executable.
- Ledger does not claim arbitrary English policy comprehension. It proves source
  preservation and confirmed mappings; semantic completeness remains a human decision.
- Hosted Cloud authoring and native v3 serving are not yet available.

## 0.7.0 - 2026-08-31

Waveframe Ledger v0.7.0 introduces the deterministic domain-pack compiler and its native v2 publication artifacts while preserving the released v0.6 compatibility path and all published v1 schema meanings.

### Added

- Waveframe-owned `constraint_ir.v1`, `runtime_fact_schema.v1`, `domain_pack.v1`, and `policy_mapping_decision.v1` contracts with strict deterministic validation.
- Built-in repository-only `repository-changes` / `1.0.0` domain pack, direct deterministic interpretation, bounded human statement dispositions, runtime-fact publication gating, and lowering through the existing Contract Compiler boundary.
- Native `authority_bundle.v2` and `publication_receipt.v2` artifacts for complete new-workflow provenance, without nesting or changing released v1 artifacts.
- Standalone strict `compiled_authority_contract.v2` for the repository pack's currently supported acting-role and path allow/deny lowering; advanced IR concepts remain fail-closed.
- Namespaced trusted emitter/format identities and pack-defined, domain-neutral resource contracts. Every unmatched statement remains pending until an explicit enforced, informational, or unsupported decision.

### Compatibility

- The published v0.6 customer-policy APIs remain exact compatibility delegates; supported/rejected behavior and canonical hashes are unchanged.
- Existing `authority_bundle.v1`, `publication_receipt.v1`, and `semantic_commit_bundle.v1` artifacts remain readable. Missing historical domain-pack lineage is not inferred.

## 0.6.0 - 2026-08-29

Waveframe Ledger v0.6.0 provides a deterministic, provenance-complete path from short company-policy text to published authority while keeping runtime enforcement optional and separate.

### Added

- Exact company-policy byte preservation through stable statement spans, full-SHA identities, explicit source revision, and an independently versioned published authority.
- Pure `interpret_customer_policy` and `finalize_customer_policy_authority` APIs that produce the approved semantic commit, canonical compiled contract, provenance-complete `authority_bundle.v1`, and verified `publication_receipt.v1` without requiring customers to author structured policy artifacts.
- Bounded clarification choices and explicit human approval, commit, and publication evidence, with enforced resolution-to-publication chronology.
- Deterministic support for required actor roles, exact and prefix repository target allow/deny rules, approval thresholds, and separation of duties.
- Additive `customer_policy_provenance_complete_v1` verification binding exact source bytes, classifications, mappings, resolutions, approval, semantic commit, compiled contract, authority identity, bundle, and receipt.
- Optional `guard` integration extra and evaluator injection for admissibility replay.

### Changed

- The supported customer-policy grammar is deliberately narrow and deterministic. Unsupported or unsafe ambiguous language remains visible and never becomes enforceable through general natural-language inference.
- Informational and unsupported-only drafts remain inspectable but cannot publish without at least one confirmed enforceable rule; Ledger invents neither allow-all nor implicit deny-all behavior.
- Waveframe Guard is no longer a mandatory dependency. Base installation, core imports, publication, lineage, and provenance verification remain Guard-free; the tested runtime integration is selected explicitly with `governance-ledger[guard]`.
- Legacy `authority_bundle.v1` artifacts remain readable as `legacy_provenance_incomplete`, and missing historical lineage is never inferred or fabricated.
- The minimum CRI-CORE Contract Compiler dependency is `0.4.0`, providing the canonical exact and prefix target representation used by this workflow.
- Package version advanced to `0.6.0`; published schema-version identifiers remain unchanged.

## 0.5.0 - 2026-07-13

Waveframe Ledger v0.5.0 closes the Published Authority publication path so approved governance can be resolved by explicit, immutable authority identity.

### Added

- Transactional publication of `authority_bundle.v1` and `publication_receipt.v1` alongside the compiled contract, deployed review, snapshot, publication manifest, and registry update.
- Explicit authority resolution through `governance-ledger resolve <authority-id>@<version>`.
- Registry bundle identity through `bundle_path` and `bundle_hash`.
- Registry lifecycle state through `active`, `superseded`, and `revoked`.
- Duplicate identity protection for conflicting contract or authority-bundle hashes.
- Canonical Published Authority specification in `docs/PUBLISHED_AUTHORITY_SPEC.md`.

### Changed

- Registry updates now require complete Published Authority identity rather than contract-only entries.
- Invalid lifecycle states fail closed instead of being coerced to `active`.
- Registry schema identity now uses the Waveframe Ledger repository name.
- Package version bumped to `0.5.0` while retaining the `governance-ledger` PyPI distribution and CLI names for compatibility.

### Verification

- Full public-core test suite passes with `200` tests before release cleanup.
- Added direct invariant coverage for conflicting bundle identity and invalid lifecycle state.

## 0.4.0 - 2026-06-03

Governance-Ledger v0.4.0 formalizes the public deterministic governance object layer, governance event architecture, chronology replay contracts, semantic reconciliation, compiled authority contracts, and execution-facing projection boundaries.

### Added

- Governance event architecture with canonical event schemas:
  - `governance_event.v1`
  - `projection_generation_event.v1`
  - `projection_invalidation_event.v1`
  - `continuity_transition_event.v1`
- Deterministic governance chronology replay via `governance_replay_state.v1`.
- Governance replay diff via `governance_replay_diff.v1`.
- Architecture docs for projection ownership, dependency graph, semantic governance model, governance event model, chronology replay, and event ordering semantics.
- Semantic extraction, reconciliation, provenance, temporal continuity, execution context, identity responsibility, compiled authority, semantic lifecycle enforcement, authority execution, and Guard enforcement projection schemas.

### Changed

- README now documents governance event architecture, chronology replay, and new canonical public schemas.
- Public package surface is normalized around deterministic governance objects and reference tooling.
- Package version bumped to `0.4.0`.

### Verification

- Full public-core test suite passes with `198` tests after private workspace staging.

## 0.3.0 - 2026-05-24

Governance-Ledger v0.3.0 adds the canonical semantic derivation layer and promotes semantic governance artifacts to first-class Ledger outputs.

### Added

- `governance_ledger/semantics/` as the canonical semantic derivation layer.
- `governance_impact_preview.v1` for deterministic governance summaries, enforcement behavior, consequences, lifecycle implications, and example governed outcomes.
- `authority_diff_impact.v1` for semantic impact of authority changes, including operational, escalation, lifecycle continuity, and replay continuity implications.
- `governance_review_packet.v1` for review-ready packets that bind authority, previews, optional diffs, optional evidence, review context, immutable inputs, and non-goals.
- `authority_bundle.v1` as the publishable governance object binding authority contracts, publication manifests, semantic artifacts, optional review packets, lineage, provenance, schema compatibility, and immutable inputs.
- CLI commands: `preview`, `diff-impact`, `review-packet`, and `authority-bundle`.
- Canonical JSON schemas for all new semantic artifacts.
- `SEMANTICS.md` documenting semantic governance compilation boundaries, artifacts, guarantees, and CLI examples.

### Changed

- README now describes Ledger as governance compiler and semantic derivation infrastructure.
- Documentation now explicitly distinguishes Ledger-owned governance meaning from Cloud-owned governance operations and Guard-owned admissibility.
- Package version bumped to `0.3.0`.

### Verification

- Full test suite passes with `125` tests.

## 0.2.0 - 2026-05-17

Governance-Ledger v0.2.0 is a major release that repositions Ledger as governance compiler and semantic validation infrastructure.

### Added

- Governance normalization engine with statement classification, normalized statement traces, and coverage reporting.
- Semantic diagnostics for ambiguous authority, weak coverage, overlapping thresholds, duplicate requirements, and compiler validation issues.
- Governance compilation reports with source identity, normalized statements, diagnostics, compiler summaries, and deterministic report hashes.
- Publication gating based on validation errors and blocking compiler diagnostics.
- Authority provenance chain using `governance_authority_lineage.v1`.
- Lineage verification CLI through `verify-lineage`.
- Governance replay tooling through `replay-authority` and `replay-execution`.
- Publication integrity checks for contract, manifest, registry, deployed review, and snapshot transactions.
- Canonical JSON schemas for governance source identity, diagnostics, compilation reports, replay requests, publication manifests, registries, reviews, and snapshots.
- Registry integrity hashing and normalized publication paths.
- Normalization corpus tests for domain policy examples.

### Changed

- Reframed Ledger from earlier extraction-centered workflows to deterministic governance operationalization infrastructure.
- Publishing now treats lineage as Ledger-owned publication evidence and stamps it onto compiled authority contracts before manifest and registry assembly.
- Runtime integration now relies on installed package contracts rather than local checkout path resolution.
- Package version bumped to `0.2.0`.

### Removed

- Local integration path resolution helper.
- Guard compatibility shim for missing replay admissibility exports.
- Test-time imports that pointed at monorepo integration paths.

### Verification

- Full test suite passes with `96` tests.

## 0.1.1 - 2026-05-10

- Early deterministic governance ledger workflows.
- Review lifecycle transitions.
- Basic policy normalization and validation.
- Publication artifacts, manifests, registry entries, snapshots, and rollback support.

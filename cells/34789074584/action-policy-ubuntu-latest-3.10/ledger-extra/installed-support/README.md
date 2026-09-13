<p align="center">
  <img src="https://raw.githubusercontent.com/Waveframe-Labs/.github/main/assets/branding/canon_wf_logo_extended.png" width="700">
</p>

# Governance-Ledger

Governance-Ledger turns governed source text and authority contracts into deterministic, reviewable, publishable governance authority. It is best understood as **Governance Compiler + Semantic Derivation Infrastructure**.

Ledger is not an AI or general-purpose policy interpreter, workflow automation layer, orchestration engine, cloud operations layer, or runtime execution system. It does not guess meaning from policy language. It recognizes only a published deterministic sentence grammar, preserves everything else as informational, unsupported, or requiring resolution, derives deterministic governance meaning, gates publication, preserves lineage, and makes governance authority replayable.

## What It Provides

- Governance normalization from source text into canonical governance statements.
- Semantic diagnostics for ambiguous, conflicting, incomplete, or unsafe authority.
- Governance compilation reports with coverage, diagnostics, statement traces, and report hashes.
- Publication gating so governance authority cannot be published when blocking diagnostics are present.
- Provenance chains from source governance to compilation reports to published authority contracts.
- Publication manifests and contract registries with integrity hashes.
- Lineage verification for authority artifacts.
- Replay tooling for compilation and admissibility evidence.
- Deterministic snapshots, rollback artifacts, diffs, and review lifecycle state.
- Canonical semantic artifacts for previews, diff impacts, review packets, and authority bundles.
- Governance chronology replay and replay diff infrastructure for reconstructing authority posture from append-only events.
- Canonical schemas for generated governance, diagnostics, replay, publication, review, registry, snapshot, and semantic artifacts.

## Why This Exists

Governance used by runtime systems must be deterministic, inspectable, and reproducible. Human governance language can enter the system, but publication authority should only come from normalized statements, explicit diagnostics, approved reviews, canonical compilation reports, and traceable provenance.

Governance-Ledger exists to make that path auditable:

```text
Governance Source
  -> Normalized Statements
  -> Semantic Diagnostics
  -> Governance Compilation Report
  -> Human Review and Approval
  -> Published Authority Contract
  -> Semantic Derivation Artifacts
  -> Manifest, Registry, Snapshot
  -> Authority Bundle
  -> Lineage Verification and Replay
```

## Core Concepts

**Governance normalization**

Ledger classifies governance statements and converts supported language into canonical policy structures. Unsupported or ambiguous language remains visible as diagnostics; it is not silently converted into executable authority.

**Semantic diagnostics**

Diagnostics identify governance risks such as missing authority, overlapping thresholds, duplicate roles, weak normalization coverage, and publication-blocking compiler issues. Diagnostics are structured artifacts with stable codes, severity, domains, and publication impact.

**Governance compilation reports**

Compilation reports bind source governance identity, normalized statement traces, coverage metrics, diagnostics, compiler summaries, and a deterministic `report_hash`. They are evidence objects, not log output.

**Publication gating**

Publishing requires an approved review and generated policy that passes compiler-ingestion validation. Blocking diagnostics prevent publication. Published contract, manifest, registry, deployed review, and snapshot artifacts are written as one transaction.

**Lineage verification**

Published authority contracts include `governance_authority_lineage.v1` linking the authority to source governance and compilation report hashes. Ledger can verify that lineage independently.

**Semantic governance compilation**

Ledger owns deterministic governance interpretation after authority has been structured. Semantic derivation modules convert `authority_contract.v1` and related publication artifacts into canonical meaning artifacts without invoking Guard, Cloud, simulation, runtime evaluation, or admissibility execution.

The canonical semantic artifacts are:

- `governance_impact_preview.v1`: governance summary, enforcement behavior, consequences, lifecycle implications, and example governed outcomes.
- `authority_diff_impact.v1`: semantic impact of authority changes, including escalation, operational, lifecycle, and replay continuity implications.
- `governance_review_packet.v1`: review-ready packet binding authority, preview, optional diff impact, optional evidence, review context, immutable hashes, and explicit non-goals.
- `authority_bundle.v1`: publishable governance object binding authority contract, publication manifest, semantic artifacts, review packets, lineage, provenance, schema compatibility, and immutable inputs. Customer-authored bundles may declare the additive `customer_policy_provenance_complete_v1` profile; older bundles remain readable as provenance-incomplete.

**Replayability**

Replay tooling reproduces compilation evidence from source governance and can replay admissibility decisions against authority and execution state using an explicitly injected evaluator. Replay failures produce diagnostics rather than silent disagreement.

**Deterministic governance operationalization**

Ledger records governance state transitions and publication artifacts with deterministic identifiers, hashes, normalized paths, immutable publication outputs, and rollback-capable snapshots.

**Governance chronology replay**

Ledger can replay append-only governance events to reconstruct governance meaning at a point in time. Chronology replay reconstructs active authority, lineage state, continuity posture, replay posture, projection freshness, governance health, and operational summaries without calling Guard or Cloud.

Ledger can also compare replay states across cutoffs with `governance_replay_diff.v1`, making governance posture changes over time deterministic and reviewable.

## What It Is Not

Governance-Ledger is not:

- AI policy interpretation.
- Legal advice or legal reasoning.
- A workflow automation product.
- An orchestration engine.
- A cloud governance operations service.
- A runtime mutation executor.
- A replacement for CRI-CORE Contract Compiler semantics.
- A replacement for Waveframe Guard runtime enforcement.
- A system that bypasses Guard admissibility.
- A system that infers unsupported governance meaning.

## Install

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install governance-ledger
```

Ledger relies on installed package contracts for integration behavior:

- `cricore-contract-compiler>=0.5.0,<0.6.0` for this unpublished development branch.
  Development acceptance requires the exact Compiler PR #8 candidate; see
  [installation and gates](docs/ACTION_POLICY_DEVELOPMENT.md). Ordinary PyPI
  availability is not claimed. This is the unpublished **0.9.0 candidate**.
- Optional `[guard]` requires `waveframe-guard>=0.19.0,<0.20.0`. The intended
  **Ledger 0.9.0 / Guard 0.19.0** pair has **pending release
  coordination**, with the exact Guard #51 candidate supplied to the required matrix. See the
  [base and combined acceptance entry points](docs/LEDGER_090_ACCEPTANCE.md).

Catalog 3.0.0 supports explicit create/modify authoring and fresh approval/public
verification without development flags. The default remains catalog 1.0.0;
development catalog 2.0.0 remains opt-in. See the [release catalog API, fixtures and
Guard/Cloud handoff](docs/RELEASE_CATALOG_3.md). Publication does not establish runtime
activation or hosted availability.

The following installation and compatibility evidence describes the **historical
released 0.8.0**, not release compatibility of this candidate.
The base install does not install Waveframe Guard. Install the release-tested runtime
integration explicitly:

```powershell
pip install "governance-ledger[guard]==0.8.0"
```

Ledger 0.8.0 pins its `guard` extra to `waveframe-guard==0.17.0`. Guard 0.17.0 declares
`governance-ledger>=0.7.0,<0.9.0`, verifies native v3 publications, and enforces their
unchanged `compiled_authority_contract.v2` runtime payload. Normal dependency resolution
and `pip check` are part of release acceptance.

### Release compatibility matrix

| Ledger | Guard | Publication support | Notes |
| --- | --- | --- | --- |
| 0.9.0 | 0.19.0 | Intended v1/v2/v3 and catalog-3 v4 | Exact candidate acceptance: see issue #25 evidence; release coordination pending. |
| 0.8.0 | 0.17.0 | v1, v2, native v3 | Historical release-tested extra for Ledger 0.8.0 only. |
| 0.7.0 | 0.17.0 | v1, v2 | Dependency-compatible; native v3 requires Ledger 0.8 or later. |
| 0.7.0 | 0.16.1 | v1, v2 | Prior release-tested compatibility pair; no native v3 support. |

Applications can inject a compatible evaluator without installing Guard in Ledger's
environment:

```python
from governance_ledger.replay import replay_admissibility

result = replay_admissibility(
    authority_contract=authority,
    execution_state=execution_state,
    evaluator=my_admissibility_evaluator,
)
```

Callers that omit `evaluator` receive `GuardIntegrationUnavailableError` when Guard
is absent, or its subclass `GuardReplayUnsupportedError` when Guard is installed.
Guard 0.19 retires raw legacy contract + execution-state evaluation. Installing
`governance-ledger[guard]` does not restore that API. The `replay-execution` CLI
returns exit code 2 with `LEDGER_GUARD_UNAVAILABLE` or
`LEDGER_GUARD_REPLAY_UNSUPPORTED`, respectively. No decision is fabricated.

Native public authority execution uses Guard's supported SDK. Repository writes
require an absolute `repository_root`, `repository_tool(action="modify", ...)`,
and mediated `RepositoryTarget.write_bytes()`. Saved logical replay uses
`guard.store.replay(run_id)` and does not invoke an execution callback. Run
`examples/native_v3_multi_control.py --candidate` with the exact candidate wheel
set to exercise private-evidence deletion, native publication, enforcement and
saved replay. The default example mode retains the historical 0.8/0.17 run.

Local checkout path resolution is not part of production behavior.

## Deterministic Domain-Pack Policy Compiler

Ledger's production policy boundary is a selected, immutable domain pack rather than a universal company-policy grammar. The only built-in pack is `repository-changes` / `1.0.0`; it contains repository concepts only. It binds scoped vocabulary, typed resource contracts, runtime facts, typed Constraint IR semantics, trusted grammar/emitter/format/lowering identities, conformance vectors, and a canonical hash.

Clauses inside the selected grammar compile directly. Every other nonempty clause remains pending until a human explicitly chooses one pack-bounded enforcement control, `informational`, or `unsupported`. Users do not author policy JSON or rule JSON. Arbitrary prose cannot be automatically interpreted without AI, and this workflow uses no AI, probabilistic inference, embeddings, external inference, spaCy heuristics, or network lookup. Missing runtime facts block publication rather than weakening a rule.

The domain-pack publication path emits standalone `compiled_authority_contract.v2`, limited to the repository pack's current acting-role and exact/prefix path allow/deny lowering. Advanced conditions, evidence, exceptions, approvals, and other obligations remain representable in Constraint IR but fail closed until a trusted lowering supports them. Released v0.6 compatibility outputs remain unchanged.

See [Deterministic Domain-Pack Policy Compiler](docs/DOMAIN_PACK_COMPILER.md) for the representation boundaries, guided-mapping workflow, exact public APIs, repository/finance compatibility boundary, and native `authority_bundle.v2` provenance chain.

## Untrusted policy translation proposals

Ledger provides a model-agnostic `policy_translation_proposal.v1` boundary for coding-agent
engineering policy. An external model or deterministic form may propose; a human confirms;
Ledger validates, renders, and compiles; Guard enforces published authority without a
model. Ledger does not call or bundle an AI/model provider. Exact source bytes
remain bound through the semantic commitment, contract, bundle, receipt, and Guard
evidence. Ordered proposal run descriptors retain exact request/response hashes and
attribution, never raw bytes. Optional raw request/response bytes live in a separate,
private, independently deletable retention artifact; optional provider prose lives only
there. Provider output and explanations
are evidence, never runtime authority or approval text.

Each clause may contain an ordered list of candidate controls, and each control requires
its own human confirmation. The human separately confirms whether the original visible
clause is fully represented, partially represented with explicit unsupported residual
meaning, entirely unsupported, or informational. Ledger proves exact source preservation
and the confirmed mappings; it cannot mathematically prove that an untrusted translator
extracted every meaning from arbitrary English. That semantic-completeness judgment is
explicitly human-confirmed.

The unchanged v2 publication path supports multiple controls only when the deterministic
source grammar reconstructs all of them. It cannot encode multiple human-mapped controls,
or both enforced and residual unsupported meaning, inside one otherwise pending source
statement. The additive `policy_translation_commitment.v1`, `authority_bundle.v3`, and
`publication_receipt.v3` path publishes those cases without changing v2. Every control
has its own confirmation, every residual has an explicit acknowledgment, and the
runtime payload remains `compiled_authority_contract.v2`.

Customer review uses six deterministic states: Ready to enforce, Needs an answer, Needs
a connection, Partially enforceable, Not currently enforceable, and Informational.
Provider/model/prompt details and raw translation evidence remain private, independently
deletable, and absent from the package and published authority. The published commitment,
authority, receipt, and runtime contract do not depend on them. Guard 0.17.0 verifies and
enforces native v3 publications as well as existing v1/v2 authority. Hosted Cloud
authoring and native v3 serving are not yet available.

The first catalog truthfully supports only autonomous-agent repository modification,
repository roles, and exact/prefix path allow/deny controls already implemented by the
released repository compiler and Guard 0.17.0 boundary. Branch, push, pull-request,
reviewer, threshold, separation-of-duties, environment, and evidence semantics fail
closed. The proposal schema uses portable capability identifiers, while the trusted
catalog registry—not caller input—decides what is actually available. See [Untrusted
Policy Translation Proposals](docs/UNTRUSTED_POLICY_TRANSLATION.md) for the APIs,
provenance proof, coverage rules, and precise limitations.

The runnable [native v3 multi-control example](examples/native_v3_multi_control.py)
publishes two exact-path controls from one clause, deletes its private translation
evidence, loads the v3 bundle and receipt through Guard 0.17.0, allows both published
paths, and blocks an unpublished path.

## v0.6 Customer-Policy Compatibility Service

The published v0.6 APIs remain stable compatibility wrappers with their exact supported/rejected behavior and canonical hashes. They do not add domain-pack metadata to legacy artifacts:

```python
from governance_ledger import (
    finalize_customer_policy_authority,
    interpret_customer_policy,
)

draft = interpret_customer_policy(
    exact_policy_bytes,
    source_policy_id="repository-change-policy",
    source_revision="rev-17",
    authority_id="repository-change-authority",
    authority_version="6.0.0",
)

publication = finalize_customer_policy_authority(
    draft,
    resolutions=[],
    approval_id="approval-001",
    approved_by="policy-owner@example.com",
    approved_at="2026-08-29T13:58:00Z",
    committed_by="policy-owner@example.com",
    committed_at="2026-08-29T13:59:00Z",
    publication_id="publication-001",
    published_by="publisher@example.com",
    published_at="2026-08-29T14:00:00Z",
)
```

`interpret_customer_policy_text(...)` is a convenience wrapper that performs only `text.encode("utf-8")`. Neither entry point normalizes newlines, Unicode, whitespace, or punctuation. Finalization reconstructs the draft from its embedded exact bytes and identities, so caller-edited classifications, rules, mappings, spans, or hashes are rejected.

The v0.6 grammar recognizes only these case-sensitive, period-terminated forms:

- `<subject> may be made only by <plural-role>.` — required actor role; the plural role must end in `s`, which is removed before lower-case hyphenation.
- `Agents may modify <exact-path>.`
- `Agents must not modify <exact-path>.`
- `Agents may modify files under <prefix-path/>.`
- `Agents must not modify files under <prefix-path/>.`
- `<Transfers|Purchases|Payments|Invoices|Requests> <above|over|at least|below|under> $<number> require <role> approval.`
- `Requester and approver must be separate.` (an initial `The ` is also accepted).

Exact and prefix targets must be repository-relative forward-slash paths. Absolute, drive-qualified, traversal, backslash, control-character, unsafe empty-segment, and malformed trailing-slash targets fail closed. Duplicate and overlapping allow/deny meanings become bounded ambiguities; Ledger never invents precedence.

Normative text outside this exact grammar is `unsupported`. Non-normative text is `informational`. Normative statements containing terms such as `normally`, `appropriate`, `unless necessary`, or other documented ambiguous qualifiers are `requires_resolution`. When removing exactly one recognized modifier produces exactly one valid grammar rule, Ledger offers that specific enforcement consequence alongside `unsupported` and `informational`; otherwise only the two non-enforcement choices are available. A resolution can select only an interpreter-produced option. Unsupported text remains visible in the approved interpretation.

Statement classification is complete once every source statement has one classification; interpretation remains incomplete while any ambiguity is unresolved. A draft is ready for finalization only when no ambiguity remains and at least one enforceable rule is present. Informational/unsupported-only drafts remain inspectable but cannot publish, and Ledger invents neither allow-all nor implicit deny-all semantics.

Finalization requires explicit resolution, approval, commit, and publication identities and canonical UTC timestamps. Chronology is enforced as every `resolved_at` ≤ `approved_at` ≤ `committed_at` ≤ `published_at`, with equality allowed and supplied resolution order preserved. Required actor roles, conditional approval thresholds, target rules, and separation-of-duties constraints remain distinct when projected into the installed CRI-CORE Contract Compiler. Finalization then returns the validated interpretation, resolution set, approval record, semantic commit, compiler input, canonical compiled contract, impact preview, manifest, provenance-complete `authority_bundle.v1`, and `publication_receipt.v1`. Source revision and authority version are independent and are hash-bound by `publishes_as`.

## Command Workflow

Generate normalized governance drafts and validation artifacts:

```powershell
governance-ledger run policies/
```

Check publication readiness:

```powershell
governance-ledger check generated/
```

Approve a reviewed governance artifact:

```powershell
governance-ledger approve reviews/finance_policy.review.json --actor governance-team
```

Publish approved governance authority:

```powershell
governance-ledger publish reviews/finance_policy.review.json
```

Inspect published authority:

```powershell
governance-ledger list contracts
governance-ledger resolve finance-policy@0.1.0
governance-ledger show contracts/finance-policy-0.1.0.contract.json
```

Verify authority lineage:

```powershell
governance-ledger verify-lineage --contract contracts/finance-policy-0.1.0.contract.json
```

Replay source governance into compilation evidence:

```powershell
governance-ledger replay-authority `
  --source policies/finance_policy.txt `
  --report reviews/finance_policy.deployed.review.json `
  --contract contracts/finance-policy-0.1.0.contract.json
```

Replay execution admissibility:

```powershell
governance-ledger replay-execution `
  --contract contracts/finance-policy-0.1.0.contract.json `
  --execution-state execution_state.json
```

The CLI form uses the optional Guard adapter and therefore requires
`governance-ledger[guard]`. Programmatic callers may use evaluator injection instead.

Generate semantic governance artifacts:

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

`publish` now emits the canonical local authority bundle automatically. The `authority-bundle` command remains available for deterministic derivation and inspection workflows.

## Artifact Layout

```text
policies/      source governance text
generated/     normalized policy drafts and validation artifacts
reviews/       review, approval, compilation, and deployment evidence
contracts/     immutable published authority contracts, manifests, registry
snapshots/     deterministic governance state snapshots
schemas/       canonical JSON schemas
governance_ledger/semantics/
               canonical semantic derivation layer
```

Publication produces:

- `contracts/<contract-id>-<version>.contract.json`
- `contracts/<contract-id>-<version>.authority-bundle.json`
- `contracts/<contract-id>-<version>.publication-receipt.json`
- `contracts/<policy>.publication_manifest.json`
- `contracts/index.json`
- `reviews/<policy>.deployed.review.json`
- `snapshots/<snapshot-id>.json`

Publication artifacts use normalized POSIX-style paths such as `contracts/finance-policy-0.1.0.contract.json`, even on Windows.

The registry entry for a published authority includes deterministic bundle identity:

```json
{
  "authority_ref": "finance-policy@0.1.0",
  "contract_hash": "sha256:...",
  "bundle_path": "contracts/finance-policy-0.1.0.authority-bundle.json",
  "bundle_hash": "sha256:...",
  "lifecycle_state": "active"
}
```

`governance-ledger resolve <authority-ref>` accepts only explicit versioned references such as `finance-policy@0.1.0` and resolves them to the canonical local authority bundle.

Semantic artifacts are deterministic derivations. They may be exported under `generated/` for review or packaging, but they are not runtime evaluations and do not change execution outcomes.

## Example Normalization

Source governance:

```text
Transfers above $1M require manager approval.
Requester and approver must be separate.
All transfer approvals must be recorded for audit purposes.
```

Normalized policy excerpt:

```json
{
  "contract_id": "finance-policy",
  "contract_version": "0.1.0",
  "authority": {
    "required_roles": ["manager"],
    "separation_of_duties": true
  },
  "approvals": {
    "required": [
      {
        "role": "manager",
        "condition": {
          "field": "amount",
          "operator": ">",
          "value": 1000000
        }
      }
    ],
    "thresholds": [
      {
        "field": "amount",
        "operator": ">",
        "value": 1000000,
        "requires_role": "manager"
      }
    ]
  },
  "artifacts": {
    "required": ["approval_audit_record"]
  }
}
```

## Diagnostics and Gates

Validation artifacts and review artifacts include structured warnings and compiler diagnostics. A diagnostic may be informational, warning-level, or publication-blocking.

Examples of publication-blocking conditions:

- Ambiguous authority, such as approval without a named approving role.
- Low governance normalization coverage.
- Overlapping approval thresholds.
- Duplicate or conflicting approval requirements.
- Compiler schema violations.
- Missing or mismatched provenance lineage.

`governance-ledger check generated/` exits non-zero when validation contains error-severity diagnostics.

## Lineage and Integrity

Published authority contracts include lineage:

```json
{
  "lineage": {
    "schema_version": "governance_authority_lineage.v1",
    "source_hash": "sha256:...",
    "compilation_report_hash": "sha256:...",
    "review_id": "review-finance_policy"
  }
}
```

Publication manifests, receipts, and registries carry source and report hashes so consumers can verify the authority chain without trusting local build state.

Semantic artifacts also carry immutable input hashes. Authority bundles bind contract, manifest, preview, optional diff impact, and optional review packets into a single publishable governance object that Cloud can ingest, validate, store, replay, and operate without reconstructing governance context. Local publication receipts are deterministic Ledger evidence for the publication record; hosted Cloud receipts can preserve the same authority durably but are not interchangeable with local publication state.

## Schemas

Canonical schemas live in [schemas/](schemas/), including:

- [policy_translation_capability_catalog.v1.json](schemas/policy_translation_capability_catalog.v1.json): immutable finite coding-agent capability boundary.
- [policy_translation_proposal.v1.json](schemas/policy_translation_proposal.v1.json): strict exact-source-bound untrusted translation proposal.
- [policy_translation_confirmation.v1.json](schemas/policy_translation_confirmation.v1.json): bounded human bindings, per-control confirmations, clause coverage decisions, acknowledgements, and coverage.
- [policy_translation_approval.v1.json](schemas/policy_translation_approval.v1.json): approval binding proposal, confirmation, review, source, catalog, authority, and coverage.
- [domain_pack.v1.json](schemas/domain_pack.v1.json): immutable, versioned deterministic domain-pack contracts.
- [runtime_fact_schema.v1.json](schemas/runtime_fact_schema.v1.json): exact proposal/derived runtime fact contracts.
- [constraint_ir.v1.json](schemas/constraint_ir.v1.json): Waveframe-owned typed enforcement Constraint IR.
- [policy_mapping_decision.v1.json](schemas/policy_mapping_decision.v1.json): exact-source-bound human mapping decisions.
- [compiled_authority_contract.v2.json](schemas/compiled_authority_contract.v2.json): strict compiled repository surface used by the v2 domain-pack publication path.
- [authority_bundle.v2.json](schemas/authority_bundle.v2.json): complete native domain-pack authority bundle with strict component bindings.
- [publication_receipt.v2.json](schemas/publication_receipt.v2.json): receipt binding the complete v2 authority bundle.
- [policy_translation_commitment.v1.json](schemas/policy_translation_commitment.v1.json): provider-free confirmed-control and acknowledged-residual commitment.
- [authority_bundle.v3.json](schemas/authority_bundle.v3.json): additive native multi-control and partial-coverage authority bundle.
- [publication_receipt.v3.json](schemas/publication_receipt.v3.json): receipt binding the complete v3 authority bundle.

- [governance_source.v1.json](schemas/governance_source.v1.json): governance source identity.
- [governance_diagnostic.v1.json](schemas/governance_diagnostic.v1.json): governance diagnostics.
- [governance_quality_diagnostic.v1.json](schemas/governance_quality_diagnostic.v1.json): advisory governance quality diagnostics.
- [governance_compilation_report.v1.json](schemas/governance_compilation_report.v1.json): governance compilation reports.
- [governance_impact_preview.v1.json](schemas/governance_impact_preview.v1.json): governance impact previews.
- [authority_diff_impact.v1.json](schemas/authority_diff_impact.v1.json): authority diff impacts.
- [governance_review_packet.v1.json](schemas/governance_review_packet.v1.json): governance review packets.
- [authority_bundle.v1.json](schemas/authority_bundle.v1.json): authority bundles.
- [publication_receipt.v1.json](schemas/publication_receipt.v1.json): publication receipts.
- [policy_translation_capability_catalog.v1.json](schemas/policy_translation_capability_catalog.v1.json): finite coding-agent translation capabilities.
- [policy_translation_proposal.v1.json](schemas/policy_translation_proposal.v1.json): exact-source, ordered-run untrusted proposals.
- [policy_translation_run_evidence.v1.json](schemas/policy_translation_run_evidence.v1.json): optional private raw run evidence.
- [policy_translation_confirmation.v1.json](schemas/policy_translation_confirmation.v1.json): bounded human confirmations.
- [policy_translation_review.v1.json](schemas/policy_translation_review.v1.json): deterministic approval-bound reviews.
- [policy_translation_approval.v1.json](schemas/policy_translation_approval.v1.json): proposal publication approvals.
- [authority_lifecycle_event.v1.json](schemas/authority_lifecycle_event.v1.json): append-only authority lifecycle events.
- [governance_semantic_extraction.v1.json](schemas/governance_semantic_extraction.v1.json): deterministic semantic extraction artifacts.
- [governance_semantic_provenance.v1.json](schemas/governance_semantic_provenance.v1.json): semantic provenance and source-span bindings.
- [governance_semantic_reconciliation.v1.json](schemas/governance_semantic_reconciliation.v1.json): semantic reconciliation artifacts.
- [semantic_conflict.v1.json](schemas/semantic_conflict.v1.json): semantic conflicts.
- [semantic_ambiguity.v1.json](schemas/semantic_ambiguity.v1.json): semantic ambiguities.
- [semantic_interpretation_decision.v1.json](schemas/semantic_interpretation_decision.v1.json): operator interpretation decisions.
- [semantic_reconciliation_projection.v1.json](schemas/semantic_reconciliation_projection.v1.json): reconciliation projections.
- [semantic_stability_projection.v1.json](schemas/semantic_stability_projection.v1.json): semantic stability projections.
- [semantic_commit_bundle.v1.json](schemas/semantic_commit_bundle.v1.json): committed semantic interpretation bundles.
- [semantic_authority_diff.v1.json](schemas/semantic_authority_diff.v1.json): semantic authority diffs.
- [semantic_lifecycle_enforcement_projection.v1.json](schemas/semantic_lifecycle_enforcement_projection.v1.json): lifecycle enforcement consequence projections.
- [compiled_authority_contract.v1.json](schemas/compiled_authority_contract.v1.json): released v1 compiled authority contract schema.
- [authority_execution_projection.v1.json](schemas/authority_execution_projection.v1.json): authority execution projections.
- [execution_requirement_projection.v1.json](schemas/execution_requirement_projection.v1.json): execution requirement projections.
- [execution_admissibility_projection.v1.json](schemas/execution_admissibility_projection.v1.json): execution admissibility projections.
- [runtime_consequence_projection.v1.json](schemas/runtime_consequence_projection.v1.json): runtime consequence projections.
- [guard_enforcement_projection.v1.json](schemas/guard_enforcement_projection.v1.json): Guard enforcement projections.
- [governance_capability.v1.json](schemas/governance_capability.v1.json): governance capabilities.
- [capability_requirement.v1.json](schemas/capability_requirement.v1.json): capability requirements.
- [capability_continuity_semantics.v1.json](schemas/capability_continuity_semantics.v1.json): capability continuity semantics.
- [capability_evidence_requirement.v1.json](schemas/capability_evidence_requirement.v1.json): capability evidence requirements.
- [capability_execution_constraint.v1.json](schemas/capability_execution_constraint.v1.json): capability execution constraints.
- [capability_identity_requirement.v1.json](schemas/capability_identity_requirement.v1.json): capability identity requirements.
- [temporal_authority_semantics.v1.json](schemas/temporal_authority_semantics.v1.json): temporal authority semantics.
- [state_posture_snapshot_semantics.v1.json](schemas/state_posture_snapshot_semantics.v1.json): state posture snapshot semantics.
- [execution_context_semantics.v1.json](schemas/execution_context_semantics.v1.json): execution context semantics.
- [governance_actor.v1.json](schemas/governance_actor.v1.json): governance actors.
- [authority_role_binding.v1.json](schemas/authority_role_binding.v1.json): authority role bindings.
- [approval_chain_semantics.v1.json](schemas/approval_chain_semantics.v1.json): approval chain semantics.
- [identity_continuity_semantics.v1.json](schemas/identity_continuity_semantics.v1.json): identity continuity semantics.
- [governance_event.v1.json](schemas/governance_event.v1.json): base governance event envelope.
- [projection_generation_event.v1.json](schemas/projection_generation_event.v1.json): projection generation events.
- [projection_invalidation_event.v1.json](schemas/projection_invalidation_event.v1.json): projection invalidation events.
- [continuity_transition_event.v1.json](schemas/continuity_transition_event.v1.json): continuity transition events.
- [governance_replay_state.v1.json](schemas/governance_replay_state.v1.json): governance chronology replay state.
- [governance_replay_diff.v1.json](schemas/governance_replay_diff.v1.json): governance replay state diffs.
- [governance_lineage_verification.v1.json](schemas/governance_lineage_verification.v1.json): lineage verification artifacts.
- [replay_authority_request.v1.json](schemas/replay_authority_request.v1.json): replay authority requests.
- [replay_execution_request.v1.json](schemas/replay_execution_request.v1.json): replay execution requests.
- [publication_manifest.v1.json](schemas/publication_manifest.v1.json): publication manifests.
- [publication_manifest.schema.json](schemas/publication_manifest.schema.json): publication manifest schema compatibility.
- [contract_registry.schema.json](schemas/contract_registry.schema.json): contract registries.
- [deployment.schema.json](schemas/deployment.schema.json): deployment records.
- [cricore_policy.schema.json](schemas/cricore_policy.schema.json): CRI-CORE policy compatibility.
- [review.schema.json](schemas/review.schema.json): reviews.
- [snapshot.schema.json](schemas/snapshot.schema.json): snapshots.

## Documentation

- [CHANGELOG.md](CHANGELOG.md)
- [PROJECTION_OWNERSHIP.md](PROJECTION_OWNERSHIP.md)
- [PROJECTION_DEPENDENCY_GRAPH.md](PROJECTION_DEPENDENCY_GRAPH.md)
- [SEMANTIC_GOVERNANCE_MODEL.md](SEMANTIC_GOVERNANCE_MODEL.md)
- [GOVERNANCE_EVENT_MODEL.md](GOVERNANCE_EVENT_MODEL.md)
- [GOVERNANCE_CHRONOLOGY_REPLAY.md](GOVERNANCE_CHRONOLOGY_REPLAY.md)
- [EVENT_ORDERING_SEMANTICS.md](EVENT_ORDERING_SEMANTICS.md)
- [GOVERNANCE_SEMANTIC_RECONCILIATION.md](GOVERNANCE_SEMANTIC_RECONCILIATION.md)
- [TEMPORAL_AND_STATE_CONTINUITY.md](TEMPORAL_AND_STATE_CONTINUITY.md)
- [EXECUTION_CONTEXT_MODEL.md](EXECUTION_CONTEXT_MODEL.md)
- [IDENTITY_AND_RESPONSIBILITY_MODEL.md](IDENTITY_AND_RESPONSIBILITY_MODEL.md)
- [GOVERNANCE_OBJECT_MODEL.md](GOVERNANCE_OBJECT_MODEL.md)
- [SEMANTICS.md](SEMANTICS.md)
- [LIFECYCLE.md](LIFECYCLE.md)
- [PROVENANCE.md](PROVENANCE.md)
- [NON_GOALS.md](NON_GOALS.md)
- [schemas/](schemas/)

---

<div align="center">
  <sub>© 2026 Waveframe Labs — Independent Open-Science Research Entity</sub>
</div>

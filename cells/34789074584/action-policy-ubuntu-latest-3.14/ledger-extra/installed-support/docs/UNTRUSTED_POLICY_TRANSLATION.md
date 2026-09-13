# Untrusted policy translation proposals

`policy_translation_proposal.v1` is a model-agnostic authoring boundary for engineering
policy. A model may propose a bounded interpretation, but it never decides what is
authorized:

1. A model or deterministic form proposes.
2. A human supplies organizational bindings, confirms executable controls, and
   acknowledges every unenforced clause.
3. Ledger validates, deterministically renders the review, reconstructs the result from
   the exact embedded source bytes, and compiles the confirmed controls.
4. Ledger publishes the provider-free commitment through the additive v3 authority
   path, while retaining the released v2 compiled-contract format.
5. Guard 0.17.0 verifies the native v3 publication and enforces the compiled authority
   without a model or private translation evidence.

Ledger does not call a provider, load provider credentials, access the network, or use a
provider explanation as approval text. The proposal contains an ordered, non-empty,
hash-chained `translation_runs` collection. Each descriptor binds the exact source,
catalog, provider class and model/deployment attribution, template, request
configuration, request hash, response hash, optional explanation hash, canonical
timestamps, sequence, and prior run hash. A chained run cannot start before its
predecessor completes, and every run must complete before human confirmation and
approval. The proposal contains no raw request, response, or provider-written
explanation. Schema validity proves only
structural and capability confinement; it does not prove that a provider understood the
policy.

Optional raw bytes belong in a separate private
`policy_translation_run_evidence.v1` artifact. That artifact validates independently
against one run descriptor and may be deleted under retention policy without changing
the proposal, confirmation, approval, bundle, receipt, or Guard verification. Runtime
authority never depends on it.

## Exact source and authority chain

The proposal embeds canonical base64 of the original bytes, a byte-for-byte SHA-256,
source identity and revision, authority identity and version, and the complete ordered
clause partition. Each non-empty byte belongs to exactly one clause produced by the
released deterministic partitioner. Missing, duplicate, overlapping, reordered, or
modified clauses fail validation.

Human confirmation and approval bind the proposal hash, source snapshot hash, authority
reference, capability-catalog hash, deterministic review hash, exact coverage counts,
and every binding/disposition. The additive public approval identity binds the
provider-free commitment, Constraint IR, semantic commit, approver, and chronology. The
approved executable meaning follows this normative chain:

`exact bytes -> snapshot hash/spans -> confirmed controls and acknowledged residuals -> policy_translation_commitment.v1 -> Constraint IR -> semantic commit -> compiled_authority_contract.v2 -> authority_bundle.v3 -> publication_receipt.v3`

The v3 bundle independently reconstructs the exact source partition, confirmed controls,
acknowledged residuals, customer bindings, trusted catalog, compiler identities,
Constraint IR, semantic commitment, compiled contract, approval, and receipt. The
proposal and all provider evidence are deliberately absent. Runtime authority therefore
never depends on retained provider evidence.

Changing one source byte changes the snapshot hash, every bound translation-run
descriptor, clause identities, proposal, confirmation and approval identities, semantic
commitment, compiled contract, bundle, and receipt.

## Public trust stages

The public APIs keep trust transitions explicit:

- `get_policy_translation_capability_catalog()` returns the aggregate immutable catalog
  currently enforceable by Waveframe. Customers do not choose a catalog or profile.
- `resolve_policy_translation_capability_catalog(...)` resolves an exact catalog
  ID/version/hash only from Ledger's trusted registry. Callers cannot inject catalogs.
- `validate_policy_translation_capability_catalog(...)` rejects unreachable or
  internally inconsistent advertised capabilities.
- `create_policy_translation_run(...)` creates one ordered hash-only attribution
  descriptor against Ledger's aggregate trusted catalog; it accepts no caller-selected
  catalog.
- `create_policy_translation_run_evidence(...)` and
  `validate_policy_translation_run_evidence(...)` manage optional private raw evidence
  outside the proposal.
- `create_policy_translation_proposal(...)` canonicalizes exact source, clauses, and
  ordered run descriptors; it performs no inference.
- `validate_policy_translation_proposal(...)` validates structure, exact coverage,
  hashes, source/authority identity, and capability confinement. It returns
  `semantic_validity: not_established`.
- `inspect_policy_translation_proposal(...)` reports exact coverage and unresolved work.
- `apply_policy_translation_binding(...)` accepts one human answer of a declared bounded
  type.
- `apply_policy_translation_control_confirmation(...)` confirms one candidate control;
  every control in a clause requires its own confirmation.
- `apply_policy_translation_disposition(...)` confirms the clause-level semantic
  coverage decision and explicitly acknowledges any residual unsupported meaning.
- `render_policy_translation_review(...)` derives operational text from the validated
  control. Provider explanations are never included.
- `validate_policy_translation_review(...)` validates the strict
  `policy_translation_review.v1` artifact that approval hash-binds.
- `approve_policy_translation_proposal(...)` binds the completed confirmation,
  deterministic review, catalog, source, authority, and enforced/unenforced counts.
- `finalize_policy_translation_authority(...)` replays everything from source bytes and
  lowers only cases truthfully representable by the released v2 publication format.
- `inspect_policy_translation_customer_coverage(...)` renders the six customer states:
  Ready to enforce, Needs an answer, Needs a connection, Partially enforceable, Not
  currently enforceable, and Informational.
- `build_policy_translation_commitment(...)` creates the provider-free normative
  commitment containing confirmed controls and acknowledged residuals.
- `validate_policy_translation_commitment(...)` reconstructs a standalone commitment
  against its exact source and approval time.
- `finalize_policy_translation_authority_v3(...)` emits the native multi-control and
  partial-coverage publication.
- `validate_authority_bundle_v3(...)` and `validate_publication_receipt_v3(...)`
  independently reconstruct the additive publication chain. The version-dispatched
  public validators reject cross-version bundle/receipt pairs.

Proposal, confirmation, and approval objects are immutable canonical values. Applying a
binding, control confirmation, or coverage decision returns a new confirmation rather
than mutating its input.

## Current truthful capability coverage

The built-in `waveframe.coding-agent.repository-change@1.0.0` catalog is the exact
intersection of Ledger's `repository-changes@1.0.0` lowering and Guard 0.17.0's trusted
repository-change runtime-fact boundary. It supports only:

- actor kind `autonomous_agent` (lowered to the released `agent` subject);
- action `modify`;
- repository-scoped acting roles from the released role enum;
- exact repository-path allow/deny;
- repository-path-prefix allow/deny;
- the released actor/action/resource/path runtime facts and their exact supported
  equality/prefix operators;
- enforcement at `waveframe.guard.repository-change.v1`.

Source literals carry an absolute byte span, exact UTF-8 surface value, byte-slice hash,
and deterministic canonical value. Their spans must stay inside the clause and cover a
whole lexical token: substrings such as `README.md` from `README.md.bak`, `deploy/` from
`predeploy/`, and role names inside larger identifiers fail closed. Quotes and backticks
at both edges remain valid lexical boundaries; when accepted by the released path
grammar, their bytes remain part of the exact path literal rather than being silently
stripped. Repository-role surface synonyms are canonicalized only by the released
domain-pack vocabulary.
Organizational roles or paths not literally established by the source remain typed,
unresolved questions until a human supplies a value accepted by the catalog.

The proposal schema uses portable structural identifiers; it does not encode the three
current control types, fact IDs, operators, effects, binding types, or enforcement point.
Semantic availability comes only from resolving the proposal's exact catalog reference
through Ledger's internal trusted registry. The initial registry contains only the
built-in repository catalog. The catalog derives its advertised facts, operators,
effects, binding types, and enforcement points from reachable control definitions. It
advertises only `==` and `starts_with`; `!=` is absent because no candidate control and
v2 lowering use it. Adding a trusted capability later therefore does not require
`policy_translation_proposal.v2`, but it still requires released compiler lowering and
Guard runtime support before the aggregate catalog may advertise it.

The current catalog fails closed for human/service actors, repository identity, branch,
push, pull-request open/approve/merge, changed-file count, reviewer identity/team,
approval counts and thresholds, requester/approver separation of duties, environment,
evidence requirements, external scanner findings, IaC plans, cloud provisioning, and
financial systems. Constraint IR can represent some of these concepts, but the released
v2 repository lowering cannot; representation is not treated as support.

Those capabilities require separately released Contract Compiler/domain-pack lowerings
and matching Guard runtime fact providers/evaluators. They must not be added to a Ledger
catalog until both sides exist under immutable identities and hashes.

Guard 0.17.0 independently validates native v2 and v3 publications. Its published
Python metadata accepts `governance-ledger>=0.7.0,<0.9.0`; Ledger 0.8.0's optional
`guard` extra pins the exact release-tested `waveframe-guard==0.17.0`. Guard requires
Ledger 0.8 or later for native v3 and fails closed rather than downgrading a v3 bundle
when an older Ledger is installed. Existing v1/v2 loading, verification, caching,
runtime-fact, and enforcement behavior remains unchanged.

Hosted Cloud authoring and native v3 serving are not yet available. Local publication,
local registry resolution, and Guard enforcement do not depend on hosted Cloud.

## Coverage and partial publication

Every clause has an ordered `candidate_controls` array containing zero or more controls.
Each control carries its own exact source-literal span and hash. Duplicate or
contradictory controls fail validation. Every clause also has exactly one proposal
coverage decision:

- `fully_represented`;
- `partially_represented`, with exact residual unsupported spans;
- `entirely_unsupported`, with exact residual unsupported spans;
- `informational`.

Proposal validation reconstructs deterministic domain interpretation. A clause already
recognized as direct must contain every corresponding control in deterministic order
and exact executable semantics; neither provider output nor a human decision may omit
one or downgrade the clause. For arbitrary English outside that deterministic grammar,
Ledger cannot mathematically prove that an untrusted translator extracted every
meaning. Ledger proves source preservation, capability confinement, and the exact
mapping the human reviewed; semantic completeness is explicitly human-confirmed.

A clause is not fully represented merely because one meaning was mapped. Partial
publication requires exact residual spans and the approver's explicit acknowledgement.
Publication fails if a binding, control confirmation, or clause decision is unresolved,
if there is no confirmed enforceable control, or if residual/unsupported meaning lacks
acknowledgement. Coverage reports exact clause and control totals and identities.
Because a partially represented clause contains both enforced and residual unenforced
meaning, it truthfully appears in both the enforced-clause and unenforced-clause sets;
the dedicated partial count removes any ambiguity.

The unchanged v2 path can publish a deterministic source statement that produces
multiple native constraints (for example, `Agents may modify README.md and
CHANGELOG.md.`). Released `policy_mapping_decision.v1` can encode only one human-mapped
control for an otherwise pending statement. Consequently, finalization fails closed if
an arbitrary pending clause contains multiple human-mapped controls; representing that
approval meaning requires a separately reviewed normative publication extension, not a
silent change to v2.

The same v2 limitation applies to a pending clause that mixes an enforced mapping with
residual unsupported meaning: released `policy_mapping_decision.v1` classifies the whole
statement with one disposition. Ledger can validate, render, and approve the explicit
partial boundary, but v2 finalization fails closed because v2 cannot truthfully preserve
that mixed normative meaning. `policy_translation_commitment.v1`,
`authority_bundle.v3`, and `publication_receipt.v3` provide the additive path. They
publish each independently confirmed control plus every exact acknowledged residual;
they never relabel the whole clause enforced.

Released `authority_bundle.v2`, `publication_receipt.v2`,
`compiled_authority_contract.v2`, all v1 schemas, and the v0.6 compatibility path are
unchanged. No v3 runtime artifact is introduced merely to retain model output.
Native v3 is selected only by the new finalizer; old artifacts are never silently
upgraded. No provider evidence is embedded in v3.

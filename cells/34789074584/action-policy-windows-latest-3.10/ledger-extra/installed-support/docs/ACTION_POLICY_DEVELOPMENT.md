# Action policy development path (issue #17)

The distinct release catalog 3.0.0 is documented in [the issue #21 Guard/Cloud
handoff](RELEASE_CATALOG_3.md). It requires fresh approval and does not change this
development catalog's identity, wording or opt-in requirements.

This is an opt-in Ledger development implementation, not a released creation capability.
The default catalog remains `1.0.0`, with only `modify`; ordinary authoring and v2/v3
publication workflows retain their existing defaults. Issue #23 prepares the
unpublished package **0.9.0**; see [base and combined acceptance](LEDGER_090_ACCEPTANCE.md).
Runtime metadata now requires `cricore-contract-compiler>=0.5.0,<0.6.0`.
No hosted Cloud feature is activated.

The implementation follows [Ledger #17](https://github.com/Waveframe-Labs/Waveframe-Ledger/issues/17),
with dependency/acceptance preparation in [Ledger #19](https://github.com/Waveframe-Labs/Waveframe-Ledger/issues/19).
Install the **exact candidate package** in a separate environment:

```powershell
python -m venv .venv/issue19
.venv/issue19/Scripts/python -m pip install -r requirements-ci.txt -e '.[dev]' -r requirements-action-policy-dev.txt
.venv/issue19/Scripts/python -m pip check
$env:WAVEFRAME_LEDGER_ACTION_POLICY_DEV = '1'
.venv/issue19/Scripts/python -m pytest tests/test_action_policy_v4.py -q
.venv/issue19/Scripts/python -m pytest -q
```

`requirements-action-policy-dev.txt` pins repository
`Waveframe-Labs/cricore-contract-compiler` at commit
`ae590dee058d3481e384dea850d5b7d980f533ff` from Compiler PR #8. Its distribution
reports `0.5.0`; this remains an **unpublished candidate**, with no PyPI availability
claim or fallback. Acceptance checks its installed
PEP 610 `direct_url.json` commit and uses `from compiler import compile_action_policy`.
Published PyPI 0.4.0 lacks that API. There is no legacy compiler fallback and no
vendored compiler implementation. Candidate provenance is development evidence only,
not a published Git package dependency. See [current acceptance procedure](acceptance/issue19/README.md).
The original [issue #17 evidence](acceptance/issue17/README.md), including its earlier
Compiler candidate and archive hash, is immutable historical evidence.

## Explicit authoring and publication

Set `WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1`, obtain
`governance_ledger.action_policy.get_development_capability_catalog()`, and pass
`catalog_version="2.0.0"` explicitly to translation run/proposal creation.
Use `repository-changes@2.0.0` for domain interpretation and
`governance_ledger.action_policy_publication.finalize_policy_translation_authority_v4`
for publication. Current finalizers reject this catalog. The environment opt-in
alone never changes the default catalog or default proposal/run version.

The new immutable catalog uses `policy_translation_capability_catalog.v2` and has
six controls indexed by `(control_type, action)`. Pack, runtime schema, grammar,
each emitter, and lowering have separately versioned identities. The runtime
instance is `repository-changes-runtime@2.0.0`. Its facts contain no caller-asserted
filesystem existence or file-creation preconditions.

The bounded grammar recognizes explicit statements such as:

* `Agents may create generated/new.md and modify README.md.`
* `Agents must not create files under generated/private/.`
* `Agents must use role repository-maintainer to create repository files.`

Each resulting control needs its own confirmation, including both controls in a
mixed clause. Exact source byte spans, control identities, confirmed coverage,
review, and approval remain bound throughout publication. `write` and `change` do
not infer create/modify permission in catalog 2.0.0. Path-dependent role clauses,
conditional clauses, and other unmatched wording cannot produce controls in this
bounded path; they must remain explicitly unsupported or be rewritten and reviewed
as a new source revision. Organizational role/path inference is not added here.

An action has its own scalar `required_role`, `allow`, and `deny`. No action or no
matching allow means no permission; roles only restrict an action. Same-action
identical allow/deny selectors and duplicate selectors reject. Distinct overlapping
selectors retain explicit deny precedence. Cross-action selectors and roles never
conflict or leak. Publication requires at least one path allow overall. A deny-only
or role-only action can accompany another action with an allow; it grants no operation.
Review explicitly describes those non-grants and creation preconditions. Development
customer coverage says `Not currently enforceable`, even for completely represented
meaning. Reused confirmation coverage fields named `enforced_*` describe represented
policy meaning, not a claim of deployed runtime availability.

## Public verification and historical compatibility

Ledger lowers validated `constraint_ir.v1` to compiler-owned `action_policy.v1`.
It checks the raw output's **exact** five-field shape, `compiled_action_contract.v1`
discriminator, authority identities, full action-block equivalence, and unsigned
canonical SHA-256 before building `compiled_authority_contract.v3`. Raw compiler
hashes are unprefixed. Ledger's authority hash is separately computed over its
schema, retained raw output, actions, and source/IR/semantic/compiler provenance.

Native `authority_bundle.v4`/`publication_receipt.v4` are built directly from the
new meaning; no v3 bundle is relabeled. Validators reconstruct the source partition,
controls, individual confirmations, IR, runtime/pack/emitter bindings, normalized
compiler input, semantic commitment, authority, approval, manifest, provenance,
bundle, and receipt. Retained compiler output is compared to this independently
derived input. Verification needs no compiler package, model response, private
provider identity, or provider explanation. Hashes provide content integrity and
binding, not identity authentication against an attacker able to replace all trusted
approval and registry commitments.

Translation proposal, confirmation, approval, review, and commitment v1 structures
are reused without changing historical schemas. All three new fixture chains pass
those existing JSON schemas. Recorded catalog identity selects the trusted parser,
comparison, rendering, and emitter set; default/historical wording is unchanged.
`domain_pack.v1`, `runtime_fact_schema.v1`, and `constraint_ir.v1` validators support
the new instance vocabulary without widening the historical instance.

Explicit unknown bundle/receipt/compiled-contract versions and mixed or downgraded
envelopes reject. Established absent-version legacy envelopes remain recognized;
explicit null versions are not absent versions. Public v4 validators themselves
require the development opt-in. No historical authority is upgraded to create.

Fixtures in `tests/fixtures/action_policy_v4/{create-only,modify-only,mixed}` retain
exact source, interpretation, proposal, confirmations, review, approval, IR, input,
raw output, enriched authority, bundle, and receipt. Acceptance reproduces these
in memory with the real candidate and compares full content without rewriting fixtures.

## Validation and activation gates

`tools/check_action_policy_history.py` compares canonical historical artifacts with
published Ledger 0.8.0. `tools/check_action_policy_old_runtime.py` runs under `python -I`
in separate ordinary published-package environments (`waveframe-guard==0.18.0` with
`governance-ledger==0.7.0` or `==0.8.0`). It tests native fixtures, discriminator
downgrades, unknown versions, and mixed receipt/bundle pairs. It does not bypass
Guard's Ledger `<0.9` constraint. `tools/check_action_policy_legacy_operations.py`
checks an allowed modify callback, blocked unlisted modify, and blocked create on a
historical authority using published Ledger 0.8/Guard 0.18. Callbacks do not write bytes.

`tools/check_action_policy_package.py` runs under `python -I` against the installed
Ledger wheel plus pinned compiler, reproduces all three fixtures, and verifies the
public artifacts with the compiler import unavailable. The sdist includes schemas,
fixtures, examples, and acceptance tools; runtime wheel validation uses packaged
Python validators and does not require source-tree schemas.

Remaining gates are deliberate:

* Compiler merge/release and publication of 0.5.0; exact candidate CI acceptance
  does not publish that dependency. Proposed Ledger 0.9.0 remains unapproved.
* Joint Ledger/Guard metadata: Guard's current Ledger `>=0.7.0,<0.9.0`
  constraint, compiler-0.4.0 test/dev pins, final versions, ordinary installation of
  the complete wheel set including `Ledger[guard]`, and staged publication of the
  optional dependency cycle. `[guard]` now requires `>=0.19.0,<0.20.0`; combined
  acceptance is pending the separate Guard candidate. Published 0.17/0.18 checks
  remain in independent historical environments.
* Production catalog and approval transition. Catalog 2.0.0 and the development
  enforcement-point identity stay immutable; existing review wording and approval
  are not approval of a production catalog.
* Future Guard action-aware native v4 validation and runtime creation support,
  including actual bytes, existing parent, no overwrite/parent creation, workspace
  containment, collisions, races, unsupported operations, and truthful partial-write
  failure evidence. Logical authorization and operation failure remain distinct.
* Actual cross-package release compatibility, including forged legacy-envelope
  defenses in downstream readers. Native rejection tests do not prove arbitrary
  relabeling attacks safe in released readers.
* Cloud integration, explicit customer acceptance, and a separate activation decision
  before advertising the catalog as currently enforceable. No mandatory content
  capture or content hash is introduced; content stays trusted callback input.

The automatic `action-policy-development.yml` gates PRs targeting main or the stacked
base, main pushes, and manual runs with an explicit full commit. It tests Windows/Linux
on Python 3.10/3.14, verifies the actual checkout head, and retains source/installed
default/native counts, exact compiler provenance, resolver and published-runtime
results, import paths, strict wheel/sdist checks and hashes, and failure diagnostics.
Base jobs resolve the exact compiler candidate; the separate combined gate records
pending status until an exact Guard candidate is supplied.
This change does not merge, tag,
release, publish a package, operate on another repository, or implement filesystem
operations.

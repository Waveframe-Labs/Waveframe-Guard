# Release catalog 3: Ledger handoff

This is the Ledger semantic transition in issue #21, stacked on PR #20 at
`4dbdfbaee92d43b888cae751ecaee5d9e4ec20b7`. It adds an explicitly selected release
catalog, not a deployment or activation. Catalog 1.0.0 remains the no-argument
default. Catalog 2.0.0 retains its exact development data, hashes, descriptions,
review wording, fixtures and `WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1` requirements.

Issue #23 prepares package **0.9.0** with `[guard]` requiring
`waveframe-guard>=0.19.0,<0.20.0`. The intended 0.9.0/0.19.0 pair has **pending**
installation and execution compatibility until the separate Guard candidate exists
and passes the [combined gate](LEDGER_090_ACCEPTANCE.md). Runtime metadata requires
Compiler `>=0.5.0,<0.6.0`; development/CI installs unchanged Compiler #8 at
`ae590dee058d3481e384dea850d5b7d980f533ff`. There is no fallback or PyPI availability claim.

## Exact trusted identities

| Artifact | Identity | Canonical SHA-256 |
| --- | --- | --- |
| Catalog | `waveframe.coding-agent.repository-change@3.0.0` | `sha256:bd7fd23eb59b5521ef6780edec0667ce9b7ba9b5738dfa2701a575fb3efce930` |
| Domain pack | `repository-changes@3.0.0` | `sha256:78783654a8131cb7a6547ee2ed9507e1dced640aebe32d35057c385bb1dc4459` |
| Runtime facts | `repository-changes-runtime@3.0.0` | `sha256:3fcf3af0a61f91a78b171ccd6247db9f0f908e1baf44aa50ece12349c44bb582` |

The enforcement point is **`waveframe.guard.repository-change.v2`**, distinct from
`waveframe.guard.repository-change.v2-development`. Serialized catalog, domain pack
and runtime artifacts are under `tests/fixtures/action_policy_release_v4`.

Grammar `waveframe.repository-changes.grammar.v2@2.0.0`, lowering
`waveframe.repository-changes.lowering.v2@2.0.0`, and the six
`waveframe.repository-changes.emitter.{create,modify}-{acting-role,exact-path-access,prefix-path-access}.v2`
identities are reused because their contracts have not changed. The trusted grammar
table explicitly registers the new pack. The release pack is separately constructed
from historical v1 building blocks; the serialized development pack is not edited.

Envelope structures stay `policy_translation_capability_catalog.v2`,
`compiled_authority_contract.v3`, `authority_bundle.v4`, and `publication_receipt.v4`.
Proposal, confirmation, review, approval and commitment v1 structures are reused.
The commitment schema accepts two additional catalog-3 coverage labels; deterministic
validation still requires the exact label selected by the registered catalog, so
these labels cannot be injected into historical commitments.

## Public authoring and verification

All release calls work with development environment flags absent:

```python
from governance_ledger.policy_translation import (
    get_policy_translation_capability_catalog,
    create_policy_translation_run, create_policy_translation_proposal,
    apply_policy_translation_control_confirmation,
    apply_policy_translation_disposition, render_policy_translation_review,
    approve_policy_translation_proposal,
)
from governance_ledger.action_policy_publication import (
    finalize_policy_translation_authority_v4,
    validate_compiled_authority_contract_v3,
)
from governance_ledger.publication_provenance import validate_publication_receipt

catalog = get_policy_translation_capability_catalog(catalog_version="3.0.0")
# Pass catalog_version="3.0.0" to both create_policy_translation_run and
# create_policy_translation_proposal. Supply exact source bytes, explicitly
# reviewed controls, and a NEW authority version or identity.
# Apply individual human confirmations and required coverage acknowledgments,
# render the new review, then call approve_policy_translation_proposal with
# the actual approving actor and timestamp. Finalize that fresh approved chain.
```

`get_policy_translation_capability_catalog()` still returns 1.0.0. Explicit 2.0.0
selection still requires the development opt-in. Unknown catalog/pack identities
or hashes reject. Cloud will select supported catalogs internally; these APIs do
not introduce customer pack/version configuration.

`examples/native_v4_release.py` is a readable complete example of source → proposal
→ individual confirmation/coverage → review → fresh approval → native publication
→ public validation. Its actors and timestamps are explicitly **example fixtures**.
It never sets environment flags or silently approves policy in a production API.
Run `python examples/native_v4_release.py` to display the example reviews/approvals
and validate all three chains. Fixture-writing requires an explicit `--write-fixtures`.

The v4 finalizer returns `result_type="action_policy_publication"` and
`status={"publication_ready": True, "runtime_activation_ready": False}` for 3.0.0.
Catalog 2.0.0 retains its historical development result exactly. Public bundle and
receipt verification use retained public meaning and never import the compiler or
need private provider evidence. Standalone compiled validation resolves the exact
trusted pack/runtime hash pair and applies its generation's gate; it verifies
structure/provenance, **not approval or activation**. Approval verification requires
the complete bundle/receipt chain, independently reconstructed against source,
confirmed controls, deterministic explanations, approval, IR and compiler bindings.

## Fresh approval and coverage

The transition may reuse source bytes, as all three example chains do, but creates
new catalog-bound proposals, individual confirmations, coverage decisions, review
hashes, approvals and publication identities. Examples move each authority from
version 2.0.0 to 3.0.0. No migration API, reused approval or relabeling path is added.
Finalization is pure artifact construction; persistent publication must use the
existing immutable registry/output checks. `validate_registry_identity` rejects a
different contract/bundle under an existing authority reference. A finalizer alone
cannot know which versions have already been stored by a caller.

Catalog 3 review describes independent actions, action-wide roles, missing-allow
denial, same-action deny precedence, and exclusive creation under an existing
parent without overwrite or parent creation. Filesystem existence is a Guard
precondition, never a caller-asserted policy fact. Roles and deny-only blocks remain
restrictions/non-grants. No operations or grammar are added; path-conditioned roles,
ambiguous change/write wording, deletion and rename cannot become action controls.

Catalog 3 coverage is `Prepared for a compatible Guard runtime` or
`Partially prepared for a compatible Guard runtime`, not evidence of deployment,
connection, successful execution or control over changes outside Guard. Unsupported
residuals stay visible and require explicit acknowledgments. The closed action
grammar is unchanged: a recognized clause cannot be downgraded to partial meaning,
and unrecognized clauses cannot supply inferred controls. Overall policy coverage
can retain recognized controls alongside acknowledged unsupported clauses. Catalog
2.0.0 keeps the exact `Not currently enforceable` output.

## Acceptance and evidence

The existing `tools/run_action_policy_acceptance.py` now covers #21 on Windows/Linux
× Python 3.10/3.14, including PRs targeting `feat/issue-19-compiler-acceptance`.
The former no-runtime-change assertion is replaced by immutable historical fixture,
original evidence, development example, dependency and package-metadata checks.
Historical canonical catalog/pack/approval/publication hashes still compare to real
published Ledger 0.8/Compiler 0.4 and the retained #17 evidence.

All 70 release tests must execute in both default and native source/installed suites;
only the inherited 44 development cases may skip when the opt-in is absent, plus
three optional Guard entries in environments without Guard. The legacy Guard 0.17
extra is resolved normally and tested separately; its pass does not establish
catalog-3 native execution. Real published Ledger 0.7/0.8 + Guard 0.18 + Compiler 0.4
environments run 24 rejection probes for each of the retained development and new
release fixture sets, with actual reasons retained. Historical operation probes stay.

Fresh sdist/wheel, strict checks, every packaged acceptance resource, source and
isolated installed module paths, exact compiler PEP 610 provenance, full fixtures,
CLI/API checks, resolver rejection and `pip check` remain required. Per-environment
JUnit counts/skip reasons, install reports, hashes, compiler archive origin, all
diagnostics and archives are uploaded even after failure. Compiler wheel hashes
identify local VCS builds, not a supplied upstream archive; compiled outputs must
match retained fixtures exactly. `release-package.json` records all catalog/runtime
identities, complete fixture hashes, fresh approval IDs and bundle/receipt hashes.

## Guard and Cloud next steps

Guard must consume this reviewed Ledger candidate and explicitly register the
catalog/pack/runtime identities and hashes above. It must validate complete native
v4 bundles/receipts, verify/evaluate the action requirements, and execute supported
create/modify calls with development flags absent. Catalog 2.0.0 must retain its
development-only handling. Do not infer support from populated action fields or
from the shared envelope/compiler formats. Preserve action isolation, default deny,
deny precedence, exclusive creation preconditions and truthful operation reports.

Accepted development work in Guard #45/#47 and Cloud #149 remains accepted at its
original pins. The remaining filesystem evidence is specifically the real
same-device bind-mount/mount-namespace case and final release-candidate validation;
this task does not imply that creation has never been implemented.

The joint release-metadata step must address Guard's Ledger `>=0.7.0,<0.9.0`
constraint, compiler-0.4.0 test/dev pins, final package versions, ordinary installation
of the complete wheel set including `Ledger[guard]`, and staged optional-cycle
publication. Cloud then integrates the compatible set, selects the supported catalog
internally, obtains **new customer approval**, and separately authorizes activation.
Ledger publication alone never enables Cloud availability or a connected runtime.

The entire PR stack stays draft. No merge, tag, package publication, deployment,
default Cloud catalog change or customer activation. Deletion, rename and macOS
remain later work.

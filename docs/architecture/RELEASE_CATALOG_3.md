# Catalog 3 SDK and Cloud handoff

Issue #48 stacks on `feat/46-native-cloud-connection` at
`0d678db7c2f4c57de47955b83d2a1d72b01b2b42`. PRs #45 and #47 retain their heads.
This change supports verified catalog-3 create/modify in the Guard SDK without
development flags. It does not activate or deploy Cloud.

## Exact candidates and approval

Client installation uses `.github/requirements/action-policy-release.txt`:
Ledger `40e0875ee9a973254bb3a4d0c228cad4fdce2bc0`, Compiler
`ae590dee058d3481e384dea850d5b7d980f533ff`, CRI-CORE 0.14.0 and Normalizer 0.2.0.
Ordinary resolution includes Guard's test extra; Compiler permits
`>=0.4.0,<0.6.0`. Independent historical environments explicitly pin Compiler
0.4.0 and published Ledger 0.8.0. Runtime requirements and temporary Guard
0.18.0 metadata are unchanged. **These contents must never be published as
another 0.18.0.** Joint release metadata is a separate step.

| Binding | Version | SHA-256 |
| --- | --- | --- |
| waveframe.coding-agent.repository-change | 3.0.0 | bd7fd23eb59b5521ef6780edec0667ce9b7ba9b5738dfa2701a575fb3efce930 |
| repository-changes | 3.0.0 | 78783654a8131cb7a6547ee2ed9507e1dced640aebe32d35057c385bb1dc4459 |
| repository-changes-runtime | 3.0.0 | 3fcf3af0a61f91a78b171ccd6247db9f0f908e1baf44aa50ece12349c44bb582 |

The enforcement point is `waveframe.guard.repository-change.v2`. Ledger's
complete public bundle and receipt validators reconstruct approval. Shared v4
envelopes and standalone compiled-contract validation cannot establish approval.
Guard's exact generation check supplies SDK support, separately from Ledger's
unchanged `runtime_activation_ready=False`. Catalog 2 and its development
enforcement point continue to require both existing opt-ins, including warm use
and revocation inside callbacks. Unknown, mixed and substituted bindings reject.

`tests/fixtures/action_policy_release_v4` retains every supplied release JSON
artifact, with raw upstream bytes recorded in `SHA256SUMS`. The original
`action_policy_v4` fixture bytes, README and checksum manifest are unchanged.
Their original Ledger/Compiler provenance remains in that README; reproducing
their compiler outputs with the new client candidates is recorded separately.
No approval wording, actor, timestamp or identity is migrated or rewritten.

## Working public example

Install in a virtual environment with ordinary pip resolution:

```sh
python -m pip install -e '.[test]' -r .github/requirements/action-policy-release.txt
python -m pip check
python -c "from pathlib import Path; Path('acceptance-output/example-workspace/generated').mkdir(parents=True, exist_ok=True)"
python examples/sdk/repository_creation_release.py --repository-root acceptance-output/example-workspace --evidence-root acceptance-output/example-evidence
```

Use a fresh workspace for each run. The example prints the saved proof and replay
result and retains the complete saved run. It uses `Guard.local`,
`repository_tool(action="create", target="path", return_result=True)` and
`path.create_bytes`. There is no customer catalog selector or release flag.
Raw compiled authority cannot authorize creation. Creation requires one new
regular file, an existing parent and exclusive no-overwrite access; Guard does
not create missing parents. Historical modify-only authorities remain unable to
create. All workspace identity, alias, escape and namespace checks still apply.

## Acceptance evidence

The action-policy workflow targets the stacked base and checks out the actual
PR head. Each Windows/Linux × Python 3.10/3.14 cell runs the full source suite
with flags absent and with explicit development opt-ins, then fresh sdist/wheel
inspection, Twine checks, ordinary installed-wheel resolution and `pip check`.
Isolated installed tests assert that both SDK modules reside in that environment.
The release cases must execute; JUnit summaries enumerate every optional or
platform skip. Historical installed acceptance uses independent published pins.

Artifacts contain `guard-head.txt`, source/install reports, JUnit and skip
summaries, distribution hashes, `release-evidence.json`, `release-http.json`,
`retained-development-evidence.json`, and real-server `connected/` results.
Saved evidence includes the exact original request, approval/publication pair,
authority, actor/runtime/run identities, local decision receipt and attestation.
Replay reconstructs the decision without recreating filesystem state.

| Case | Authorization | Terminal report | Mutation |
| --- | --- | --- | --- |
| Create, including empty bytes | allow | succeeded | true |
| Exclusive collision | allow | failed | false |
| Known partial write | allow | failed | true |
| Unknown callback outcome | allow | failed | omitted/unknown |
| Missing parent | allow | not_executed | false |
| Denied path/action/role | deny | blocked | false |
| Evaluation only | evaluated | absent | no operation |

Historical local proofs may retain unknown mutation status on failures; validated
operation evidence supplies the more precise automatic runtime report. Rehashed
contradictory proofs reject. Preservation/report failure or timeout never retries
the mutation and never establishes confirmed preservation.

## Cloud next task and remaining release gates

`Guard.cloud` validates the native catalog-3 pair through the existing loader.
Local HTTP contract evidence exercises real publication, preservation and report
transport, tenant/runtime binding and failure behavior. Its example acknowledgments
are explicitly a client contract test, not production Cloud acceptance.

The retained 23-case connected regression uses unchanged Cloud
`547291b525e2f1d05d92ed65b6058c4ca91588a8` and its original server dependency pins,
in a separate Python 3.14 environment. The client uses the newer candidates.
Its catalog-2 wire hashes must still agree; `summary.json` records server and
client provenance separately. CI uses the existing read-only
`CLOUD_TEST_READ_TOKEN`. Missing credentials never count as a connected pass.

Cloud has not adopted catalog 3. Its next task is to consume this exact reviewed
Guard head and compatible candidates, select catalog support internally, obtain
fresh customer approval, and validate real catalog-3 service/sandbox/browser
execution and preservation before separately authorized activation. The real
same-device mount-namespace result must be reviewed alongside the CI platform
skips; an unavailable mount test is never a pass. Final coordinated package
versions/ranges and complete `Ledger[guard]` installation remain release gates.
No merge, tag, publication, deployment or activation is included here.

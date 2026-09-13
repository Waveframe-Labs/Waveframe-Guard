Catalog-3 approved publication pairs now authorize supported repository create/modify through the installed Guard SDK with both development flags absent. Exact generation checks and Ledger's complete public approval validators protect cold, cached and warm execution; filesystem mutation still uses the existing guarded boundary.

Closes #48. Stacked draft targeting `feat/46-native-cloud-connection`.

**Exact head:** `473422b1220fa621cb7895d54f1e18e72ffaba58`
**Exact base/start:** `0d678db7c2f4c57de47955b83d2a1d72b01b2b42`.
PR #45 remains `5e41e454ccd54d7dcce34ecacb41b2ea20cf73b1`; PR #47 remains the base above. Both remain open drafts.

Client candidates: Ledger `40e0875ee9a973254bb3a4d0c228cad4fdce2bc0`, Compiler `ae590dee058d3481e384dea850d5b7d980f533ff`, CRI-CORE 0.14.0 and Normalizer 0.2.0. Test/dev Compiler constraints permit `>=0.4.0,<0.6.0`; independent historical installations explicitly use Compiler 0.4.0 and published Ledger 0.8.0. All installs use ordinary resolution. Runtime Ledger range and temporary Guard version are unchanged; these contents must never be published as another 0.18.0.

## Final-head acceptance

[All four CI cells passed](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/34731676416). Each downloaded `guard-head.txt` equals the exact head above. Counts below are passed/skipped; no tests failed.

| Environment | Source flags absent | Source opted in | Installed release | Installed opted in | Installed historical | Real Cloud |
| --- | --- | --- | --- | --- | --- | --- |
| ubuntu / Python 3.10 | 1423/146 | 1561/8 | 589/146 | 727/8 | 440/295 | 23/23 |
| ubuntu / Python 3.14 | 1423/146 | 1561/8 | 589/146 | 727/8 | 440/295 | 23/23 |
| windows / Python 3.10 | 1417/152 | 1555/14 | 583/152 | 721/14 | 434/301 | 23/23 |
| windows / Python 3.14 | 1417/152 | 1555/14 | 583/152 | 721/14 | 434/301 | 23/23 |

All **150 release cases execute without skips** in every release/default and opted-in source/installed suite. Skips are enumerated in retained JUnit and summary files: catalog-2 cases without explicit opt-ins, unavailable historical/release dependency counterparts, Windows/Linux-specific filesystem cases and runner mount-namespace restrictions. The historical baseline intentionally cannot execute catalog 3.

Fresh sdist/wheel, package metadata/content inspection, Twine checks, installed module-path assertions, exact PEP 610 dependency provenance, compiler-output reproduction and ordinary `pip check` passed. Distribution hashes in each artifact were recomputed successfully. Source/default and isolated release execution use both development flags absent.

The existing real same-device bind-mount test also passed **1 test, 0 skips** against the final installed Linux Python 3.14 CI wheel and the exact new Ledger/Compiler candidates; `pip check` passed. Environment: Linux `6.6.114.1-microsoft-standard-WSL2`, Python 3.14.7, Docker `python:3.14-slim` digest `sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9`, supported tmpfs `/tmp`, `SYS_ADMIN`, seccomp unconfined, isolated child user/mount namespace. Wheel SHA-256: `e220fd198f9b2106243346b110aea21ace56164ec048d49fc177c55d06601bc0`. An earlier overlay attempt was rejected as an unsupported filesystem and is not counted as a mount pass.

## Working example and saved evidence

[Public example](https://github.com/Waveframe-Labs/Waveframe-Guard/blob/473422b1220fa621cb7895d54f1e18e72ffaba58/examples/sdk/repository_creation_release.py) uses `Guard.local`, `repository_tool(action="create", target="path", return_result=True)` and `path.create_bytes`. It was executed outside the checkout using the final Windows CI wheel in a fresh environment, with both flags absent. Creation, public saved-proof loading and replay succeeded. Example run: `guard_run_4af912ff6512e9d517ff89f0`; proof hash: `sha256:c15097679372ba869b10fe9dee5b02c0bfe6a278160f62fe5f3ef9cc00071e49`.

Each CI artifact contains `package/release-evidence.json`, `package/release-http.json`, `package/retained-development-evidence.json`, fresh distributions, hashes, installation reports, JUnit/skip summaries and `connected/{summary,http,cloud-source}.json`. The complete saved run includes original requests, exact source/approval/publication pair, actor/runtime/run identities and decision receipt; replay matches without recreating filesystem state.

Example saved identities from the final Linux Python 3.14 installed acceptance:

- Run: `guard_run_c8cff5507a89c202d260aa37`.
- Local decision receipt: `sha256:9e05dd6b1c081eea07267b62bd86e79ea92438c0b04417062931f05effb8165f`.
- Local execution attestation: `sha256:19d034bd8a092813b950edface4b710521ed5011a0177a24e393ec7f488107c2`.
- Approved authority: `repository-create-only@3.0.0`.
- Approval: `publication-approval-v4-667eebeec0218e5bdf6fe76ab4b627d61a19ab6e91dd1821bfa86708132b17dc`.
- Bundle: `sha256:52ee5594c92d37ccaf9c46c4f9b9072d254636a52c5eb1efa8851d9102aff66f`.
- Publication receipt: `receipt-v4-52ee5594c92d37ccaf9c46c4f9b9072d254636a52c5eb1efa8851d9102aff66f`; hash `sha256:daf28dc75e5cf5b3efc6d25dbe4748e48b5c0fc06d9d6756021d54407fd354f0`.

Observed outcomes: empty creation succeeds with mutation; exclusive collision fails without mutation; known partial write fails with mutation; unknown callback outcome remains unknown; denied actions/roles/paths invoke zero callbacks and write nothing; evaluation-only emits no terminal report. Historical local failure proofs may retain unknown mutation status while validated operation evidence supplies the more precise runtime report. Rehashed contradictory proofs reject. Preservation/report errors and timeouts never rerun a mutation or imply confirmed preservation.

## Provenance and Cloud handoff

Original catalog-2 fixture bytes, checksum manifest, provenance README and prior acceptance records are unchanged. Release fixture JSON/source bytes and the supplied fixture author come from the exact Ledger candidate and are recorded separately. Their example approval wording/actors/timestamps were not rewritten. New-client reproduction of retained development outputs is distinguished from their original compiler provenance.

[Detailed Cloud handoff](https://github.com/Waveframe-Labs/Waveframe-Guard/blob/473422b1220fa621cb7895d54f1e18e72ffaba58/docs/architecture/RELEASE_CATALOG_3.md). The 23-case connected regression passed in all four cells against unchanged Cloud `547291b525e2f1d05d92ed65b6058c4ca91588a8`, with original isolated server pins (Ledger `54379d9c8044544fc1b8f32109bdfce35c1c6a05`, Compiler `3b91fcc03c804804b2ace7302f37340a787496d9`) and explicit development flags. Server and client provenance are separate and the retained catalog-2 wire artifacts still agree. The existing `CLOUD_TEST_READ_TOKEN` fetched the exact server; no credential skip is counted as a pass.

Catalog-3 HTTP artifacts establish client transport/serialization, complete-pair loading, tenant/runtime/lifecycle binding and failure behavior. They do **not** establish production Cloud support. Cloud next consumes this exact Guard head and compatible candidates, selects catalog 3 internally, obtains fresh customer approval and runs actual catalog-3 service/sandbox/browser acceptance before separately authorized activation. Coordinated release versions/ranges and complete `Ledger[guard]` package-set acceptance remain separate release work.

No merge, tag, package publication, deployment, Cloud implementation or activation was performed.

Local retained files: `final-evidence.json`, `final-ci/`, `final-candidate-mount.log`, `final-installed-example.json`, `final-installed-evidence/`.

# Guard issue #52: final wheel-set handoff

Guard head: `afe5093e39bdd132bfb4da2a45e3199f1f6eca16`. Base: `0161ef8a52e052d1bc1366cdc93ce13a9bd535ed` on `feat/50-guard-019-release`.
[Stacked draft PR #53](https://github.com/Waveframe-Labs/Waveframe-Guard/pull/53). Existing #45/#47/#49/#51 heads remain unchanged; see [stack.json](stack.json).

Ledger #26: `a34c11d81b85963794cf28b4adad091fac15e130`. Compiler #8: `ae590dee058d3481e384dea850d5b7d980f533ff`.
Guard remains 0.19.0 (proposed v0.19.0). `release_ready=false`; no merge, tag, release, package upload, deployment or activation.

## Cloud package selection

Use [package-set.json](package-set.json), with [handoff digest](handoff.json) and [SHA256SUMS](SHA256SUMS). The recommended set is the final Ubuntu/Python 3.14 build. Download its archive from this immutable evidence commit, verify the archive digest, then extract and verify the selected package members. Do not substitute an older 0.19.0 wheel by version alone.

Archive: [artifacts/34789074584/action-policy-ubuntu-latest-3.14.zip](artifacts/34789074584/action-policy-ubuntu-latest-3.14.zip)
SHA-256: `0494f05dfac98b9a400caee2495c6eb3c899b491a4810a5cdccf2b0412bed900`.

| Selected package | SHA-256 |
| --- | --- |
| governance_ledger-0.9.0-py3-none-any.whl | `6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4` |
| governance_ledger-0.9.0.tar.gz | `8ceb328437c794a3306d22ca82e99787f3bf4ff0d0281b4e245d7d0b29c42c2c` |
| cricore_contract_compiler-0.5.0-py3-none-any.whl | `1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44` |
| waveframe_guard-0.19.0-py3-none-any.whl | `e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f` |
| waveframe_guard-0.19.0.tar.gz | `e4230ad2ca9d6f01a24ac5c2e74064079fff531bb981682960143cdf767f19e3` |

The same ZIP retains original accepted Ledger/Compiler archive/build provenance, Guard clean-build inputs and build log, current installed bytes/import paths, actual pip reports, all tests/probes/HTTP evidence, and original historical Ledger/#51 records. Those historical records are not current Guard results. Per-environment packages and hashes are explicit in the manifest; source-built dependencies have separate origins and verified runtime/resource equivalence to the accepted wheel set.

## Final-head CI and results

- [4 passing jobs](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/34789074584) at `afe5093e39bdd132bfb4da2a45e3199f1f6eca16`.
- [7 passing jobs](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/34789074621) at `afe5093e39bdd132bfb4da2a45e3199f1f6eca16`.

All 11 required jobs completed successfully. No queued, skipped or earlier-head job is substituted. Counts below are passed / skipped, with zero failures/errors. All **150 Guard release cases execute in every source and installed suite**.

| Cell | Source default | Source development | Installed default | Installed development | Real Cloud cases |
| --- | --- | --- | --- | --- | --- |
| ubuntu-3.10 | 1422 / 146 | 1560 / 8 | 589 / 146 | 727 / 8 | 23 / 23 |
| ubuntu-3.14 | 1422 / 146 | 1560 / 8 | 589 / 146 | 727 / 8 | 23 / 23 |
| windows-3.10 | 1416 / 152 | 1554 / 14 | 583 / 152 | 721 / 14 | 23 / 23 |
| windows-3.14 | 1416 / 152 | 1554 / 14 | 583 / 152 | 721 / 14 | 23 / 23 |

In every cell, the unchanged packaged Ledger suites pass **678 / 44** default and **722 / 0** development. All 70 release cases, all 44 development cases, every optional integration, the mediated v3 example, release/development package probes, and all 56 catalog-3 execution cases are required. The Guard-entry upgrade repeats execution probes after ordinary resolution from released Guard 0.18 / Ledger 0.8 / Compiler 0.4. Both old-Ledger rejection commands retain nonzero status and actual ResolutionImpossible output. Current installed provenance and pip check pass for both package entry paths.

Expected skips remain explicit in JUnit and summary files: catalog-2 default opt-outs, independent released-Ledger coverage and platform/namespace restrictions. Credentials were available and all **92 real connected cases** executed.

The connected server is unchanged Cloud #147 `547291b525e2f1d05d92ed65b6058c4ca91588a8`, with original Ledger `54379d9c8044544fc1b8f32109bdfce35c1c6a05` and Compiler `3b91fcc03c804804b2ace7302f37340a787496d9` in its independent Python 3.14 environment. These are catalog-2 regression results.

## Mount scope and preserved behavior

All Guard runtime, tests, contracts, dependency metadata and original fixture bytes are unchanged from #51. [Source audit](source-audit.json), [Guard diff](guard-change.patch), and [Ledger runtime delta](ledger-runtime-change.patch) retain that scope. Ledger #26 changes CLI/legacy replay compatibility, not Guard filesystem enforcement. Canonical fixture outputs are reproduced by Ledger’s unchanged packaged probes; Windows sdist line endings are distinguished from canonical values.

The reviewed #51 same-device bind-mount result is retained with its original command, verified runner, raw output and build record under [retained-mount](retained-mount). Its exact tested wheel is `2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e` at Guard `0161ef8a52e052d1bc1366cdc93ce13a9bd535ed`: one test passed, zero skips. The current Linux/Python 3.14 runtime bytes and 190 relevant build inputs match the old proof; see [mount input comparison](mount-build-input-equivalence.json) and each cell’s wrapper report. **The current wheel was not newly mount-tested.**

## Failure retention and reproductions

All CI command logs are retained under `ci/<run-id>/logs.zip`, with job/step outcomes and head metadata. Packaged Ledger Acceptance records retain exact command arrays, cwd, output and exit codes. Guard builds retain tracked input hashes, interpreter, command and build exit code. Source and connected pip installation reports keep their real Git/archive origins. Python 3.10 connected installs have empty direct_url archive hashes; the actual pip install reports supply the checked SHA-256 and matching file URL. Those original reports are retained unchanged.

The initial head `004f959f6d46a40b34a10ca3a789afff8aed7d74` failed in all four combined wrappers because shallow checkouts lacked the base commit needed for ancestry verification. [Historical CI status](historical-ci-status.json) and run `34788632771` retain those failures. Fetching comparison history fixed the harness setup. Earlier green Guard jobs are retained but excluded from final results.

The original mixed-line-ending local checkout failed strict historical byte equality; [historical-local](historical-local) retains the failure, actual archives and the PowerShell exit-code limitation. A fresh local worktree then passed both producers with captured native exit codes zero; [clean-local](clean-local) retains the complete supplemental run. Neither local artifact is selected for Cloud.

Reproduction commands are in [Guard acceptance documentation](https://github.com/Waveframe-Labs/Waveframe-Guard/blob/afe5093e39bdd132bfb4da2a45e3199f1f6eca16/docs/RELEASE_019_ACCEPTANCE.md). [collect_ci.py](collect_ci.py), [finalize.py](finalize.py) and [document.py](document.py) record collection/verification/index generation. Actions artifact digests are checked against actual downloaded ZIP bytes. All retained files are indexed without newline conversion.

## Next owner and release limits

Cloud must consume this reviewed final set and complete package, Console and production-image acceptance above #151 `8552aad2fc4fcf861cc2205ebce70a5b486534e6`. This task does not change or activate Cloud.

Release order remains Compiler 0.5.0 → Ledger 0.9.0 → Guard 0.19.0, ordinary index checks, then separately authorized Cloud rollout/activation. Deletion, rename and macOS remain later scope.

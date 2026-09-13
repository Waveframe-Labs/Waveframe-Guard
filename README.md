# Guard 0.19.0 candidate evidence

**Guard-owned acceptance passed; Ledger combined-extra acceptance failed in all four cells. This is not release approval.**

Draft [PR #51](https://github.com/Waveframe-Labs/Waveframe-Guard/pull/51) implements issue #50. Exact head: `0161ef8a52e052d1bc1366cdc93ce13a9bd535ed`. Exact base: `473422b1220fa621cb7895d54f1e18e72ffaba58` on `feat/48-release-catalog-3`. Proposed tag: **v0.19.0** (not created). PRs #45/#47/#49 retain their original heads and remain draft; [stack and complete machine-readable results](handoff.json).

## Runtime and exact candidates

Runtime requirements: `cricore>=0.13.0,<0.15.0`, `cricore-proposal-normalizer>=0.2.0,<0.3.0`, `governance-ledger>=0.9.0,<0.10.0`, `requests>=2.33.0,<3.0.0`. Python >=3.10. Test/dev Compiler requirement: `>=0.5.0,<0.6.0`.

Ledger 0.9.0: `3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f`. Compiler 0.5.0: `ae590dee058d3481e384dea850d5b7d980f533ff`. CRI 0.14.0 and proposal normalizer 0.2.0 are used in every primary cell; the main workflow separately retains CRI 0.13.0 minimum-boundary checks. Runtime metadata contains no Git dependencies.

## Final-head Guard results

[Main validation](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/34772598548): **success** (all seven jobs). [Release/connected/combined workflow](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/34772598555): **failure only at the supplied Ledger gate**. Actual checkout heads, source/build provenance and all package hashes were independently verified after downloading. No missing credential is counted as connected acceptance.

Counts are passed / skipped; zero Guard test failures.

| Cell | Source default | Source opted in | Installed default | Installed opted in | Native Cloud |
| --- | --- | --- | --- | --- | --- |
| ubuntu-3.10 | 1422 / 146 | 1560 / 8 | 589 / 146 | 727 / 8 | 23 / 23 |
| ubuntu-3.14 | 1422 / 146 | 1560 / 8 | 589 / 146 | 727 / 8 | 23 / 23 |
| windows-3.10 | 1416 / 152 | 1554 / 14 | 583 / 152 | 721 / 14 | 23 / 23 |
| windows-3.14 | 1416 / 152 | 1554 / 14 | 583 / 152 | 721 / 14 | 23 / 23 |

All **150 collected release cases execute without skips in every required source and installed mode**. Fresh wheel/sdist, strict metadata/content/Twine checks, installed API and CLI, the public repository-creation example, saved proof/replay, exact client provenance and `pip check` passed. The final source/install reports verify Guard 0.19.0, Ledger 0.9.0, Compiler 0.5.0, CRI 0.14.0 and normalizer 0.2.0.

Default mode adds 138 explicitly opted-out catalog-2 cases to platform/historical skips. Opted-in Linux skips: one independent published-Ledger case, six Windows/case-sensitivity cases and one unavailable unprivileged mount namespace. Opted-in Windows skips: one independent published-Ledger case and thirteen Linux/namespace-replacement cases. Every skip name/reason is in JUnit and [handoff.json](handoff.json). The old-runtime cases are independently retained in the matching Ledger base archives, not forced into the new Guard installation.

## Downloadable distributions and manifests

Each archive includes the actual Compiler/Ledger/Guard packages, build records, install reports, complete HTTP results, saved evidence, JUnit and combined failure logs. Curated extracted files below make the reports directly browsable. These are candidate build hashes, not selected release artifacts or reproducible-build claims.

| Cell | Wheel SHA-256 | Sdist SHA-256 | Downloads |
| --- | --- | --- | --- |
| ubuntu-3.10 | `34181026b13e5a60c8ec7370dda875c911ef762903865db25705c73872f330e9` | `b10c69b5c8aff0936b741ca54bfc8be5a636a85297606e49f79859df0ac23581` | [wheel](cells/ubuntu-3.10/package/waveframe_guard-0.19.0-py3-none-any.whl), [sdist](cells/ubuntu-3.10/package/waveframe_guard-0.19.0.tar.gz), [manifest](cells/ubuntu-3.10/package/guard-candidate.json), [all evidence](artifacts/final-action-policy-ubuntu-latest-3.10.zip) |
| ubuntu-3.14 | `2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e` | `fe4f3eeb250b5713eef3116a3dbd8c1ebc00e67287edd89dab73c3fdbb57aa70` | [wheel](cells/ubuntu-3.14/package/waveframe_guard-0.19.0-py3-none-any.whl), [sdist](cells/ubuntu-3.14/package/waveframe_guard-0.19.0.tar.gz), [manifest](cells/ubuntu-3.14/package/guard-candidate.json), [all evidence](artifacts/final-action-policy-ubuntu-latest-3.14.zip) |
| windows-3.10 | `e7cb9aae6a27437d809d5d72e0225536c4ac0ab729ad9cae162c4417c24d4ba4` | `9c8c614ccb67a664e534ba8925e76c0394a5470cb7957349b472aec204189074` | [wheel](cells/windows-3.10/package/waveframe_guard-0.19.0-py3-none-any.whl), [sdist](cells/windows-3.10/package/waveframe_guard-0.19.0.tar.gz), [manifest](cells/windows-3.10/package/guard-candidate.json), [all evidence](artifacts/final-action-policy-windows-latest-3.10.zip) |
| windows-3.14 | `57e3a468c1708fb32de8907d8cdc0d0612a551195eb5d0db43334a98917cddab` | `29ae0f22bc059b7543f41d515c5026a37e97ac392bc9e5d346c73b54264c4207` | [wheel](cells/windows-3.14/package/waveframe_guard-0.19.0-py3-none-any.whl), [sdist](cells/windows-3.14/package/waveframe_guard-0.19.0.tar.gz), [manifest](cells/windows-3.14/package/guard-candidate.json), [all evidence](artifacts/final-action-policy-windows-latest-3.14.zip) |

Per-cell Compiler/Ledger archive hashes and exact origins are in [handoff.json](handoff.json) and each `ledger-extra/combined/wheelhouse/`. Python 3.10 pip 23 omits the local-wheel archive digest in connected PEP 610; that absence is preserved. The exact wheel install URL, module-location assertions and HTTP `runtime_version=guard-0.19.0` establish the connected package identity. Separate combined/upgrade checks verify all installed Python bytes and archive digests, accepting both genuine pip report hash formats.

## Ledger combined-extra owner gate

The unchanged supplied entry point ran against the actual final-head wheel in **all four cells**, with the matching retained base evidence from Ledger evidence commit `44552c3fbedfffcc480c294d0b381eaecbc5017d`. Interpreter patch versions matched in final CI. A separate preliminary local Python 3.14.0 run correctly reran the unchanged base harness rather than relabeling its Python 3.14.7 evidence.

| Check | Each of all four cells |
| --- | --- |
| Ordinary real `governance-ledger[dev,guard]` installation, pip check, installed bytes/versions/paths | Passed |
| Supplied installed default suite | 656 passed / 2 failed / 44 development skips |
| Supplemental unchanged installed development suite | 699 passed / 3 failed / 0 skips |
| Supplemental unchanged release/development package checks | Passed |
| Supplemental unchanged legacy v3 candidate example | Failed |
| Supplemental unchanged real catalog-3 execution | 56 cases passed, development flags absent |
| Guard-entry upgrade from installed Ledger 0.8, resolver rejection, installed-byte checks, pip check | Passed |

The supplied combined gate remains failed; supplemental commands never overwrite its status. All Ledger tracked checkouts remained clean. Failures needing the Ledger owner:

1. `tests/test_guard_optional_compatibility.py::test_released_guard_integration_preserves_allowed_and_blocked_replay` reaches `governance_ledger/replay.py:110`, which calls retired `waveframe_guard.evaluate_admissibility()`. Guard correctly raises `GUARD_LEGACY_EXECUTION_UNSUPPORTED`.
2. `tests/test_policy_translation_publication_v3.py::test_guard_0170_loads_native_v3_after_private_evidence_deletion_and_enforces` and `examples/native_v3_multi_control.py --candidate` use a repository authority without `repository_root` and `repository_tool()`. Guard correctly raises `RepositoryBoundaryError`.
3. `tests/test_action_policy_v4.py::test_candidate_package_provenance` requires a Git PEP 610 URL, contradicting the combined entry point's verified local Compiler wheel installation. Its archive bytes and base-recorded exact Compiler origin are independently verified.

No Ledger code, fixtures, tests, metadata or acceptance scripts were patched, and no Guard fallback or permissive runtime change was introduced. Exact reproduction from a clean checkout of the supplied Ledger head and matching interpreter:

```text
python tools/run_guard_extra_acceptance.py --expected-head 3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f --base-evidence CELL/ledger-extra/retained-base --guard-candidate CELL/package/guard-candidate.json --output NEW_OUTPUT
```

Extract `CELL` from the corresponding full evidence archive. The Guard-owned wrapper in the candidate repository reproduces base selection, the unchanged supplied command, supplemental probes and the independent upgrade. Exact executed commands, working directories and exit codes are retained per cell in `ledger-extra/guard-coordination.json`; the original gate is in `ledger-extra/combined/acceptance.json`.

## Mount and historical evidence follow-up

The final Linux/Python 3.14 CI wheel (`2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e`) passed the real isolated same-device bind-mount test: **1 passed, 0 skipped**. [Complete mount evidence](artifacts/final-head-mount.zip), [exact Docker command](final-mount-command.json), [actual CI build provenance](final-mount-build-record.json). Environment: Linux 6.6.114.1-microsoft-standard-WSL2, Python 3.14.7, Docker image `python@sha256:656d12e70054d5fda18a045e2494c96701e9792dd1445f95b3d038df954f57e9`, tmpfs `/tmp`, `SYS_ADMIN`, seccomp unconfined, child user/mount namespace. The main CI namespace skips are not counted as passes.

[Prior #49 final-evidence document](prior-mount/final-evidence.md), [raw original final output](prior-mount/final-candidate-mount.log), [original inner command runner](prior-mount/original-mount-runner.py), [prior wheel](prior-mount/waveframe_guard-0.18.0-py3-none-any.whl), and [unchanged boundary/test mapping](prior-mount/mapping.json) are retained. That result belongs to the original 0.18.0 wheel at head `473422b1220fa621cb7895d54f1e18e72ffaba58`, not to 0.19. Its outer Docker invocation was not recoverable; the new final-head run supplies a complete independently recorded invocation, environment and package provenance. The failed historical overlay attempt remains a failure.

[Source audit](source-audit.json) and [runtime diff](runtime-version-only.patch) distinguish new producer version reporting from unchanged authority/catalog/schema identities and original development/release fixture hashes. Preliminary local archives and unprefixed CI archives are retained as **pre-final evidence only**; they do not establish the final matrix above.

## Cloud/release handoff and remaining gates

All 23 connected cases per cell used unchanged Cloud #147 `547291b525e2f1d05d92ed65b6058c4ca91588a8` with its original Ledger `54379d9c8044544fc1b8f32109bdfce35c1c6a05` and Compiler `3b91fcc03c804804b2ace7302f37340a787496d9` in a separate Python 3.14 server environment. The newer client package set was installed separately. HTTP and saved attestation/report results are retained in each cell's `connected/` directory.

Remaining: Ledger-owned replay/test/example/provenance repairs and a newly approved exact candidate with all four combined gates passing; final Cloud #151 `8552aad2fc4fcf861cc2205ebce70a5b486534e6` package-set/pin promotion and complete Console acceptance; coordinated review, artifact selection, index/tag recheck and publication authorization; Compiler 0.5.0 -> Ledger 0.9.0 -> Guard 0.19.0 publication followed by ordinary PyPI base/extra installation and `pip check`; separately authorized rollout and activation. Do not advertise Ledger's new extra during the interval before Guard upload and verification.

**No merge, tag, GitHub release, PyPI publication, Cloud pin promotion, deployment or activation was performed. All PRs remain draft.**

## Archive integrity

| Archive | SHA-256 |
| --- | --- |
| [action-policy-ubuntu-latest-3.10.zip](artifacts/action-policy-ubuntu-latest-3.10.zip) | `0bf8e5555a429f5f44b00effce082ea4f72b438cd0a7693a54bf4b03d41eb26e` |
| [action-policy-ubuntu-latest-3.14.zip](artifacts/action-policy-ubuntu-latest-3.14.zip) | `a8d9fd6004acc19de9a4d299524f8294223d0eb7546c640af88f932f7122ab2d` |
| [final-action-policy-ubuntu-latest-3.10.zip](artifacts/final-action-policy-ubuntu-latest-3.10.zip) | `fced7cad0b90ac7c0d238056466bdd6b8f1895eb53cfc2c5b0733ae465562d7e` |
| [final-action-policy-ubuntu-latest-3.14.zip](artifacts/final-action-policy-ubuntu-latest-3.14.zip) | `e7da1b4d84c706503d55758aa83c9537eea6b794bae0159baa62541b9a537270` |
| [final-action-policy-windows-latest-3.10.zip](artifacts/final-action-policy-windows-latest-3.10.zip) | `88ae2b1295e3433bca440361971aaea4810c69f0bda5f51b85a41e30ef9d96b4` |
| [final-action-policy-windows-latest-3.14.zip](artifacts/final-action-policy-windows-latest-3.14.zip) | `a8e4ff0670056461be5aa7d8f71e460af43daf1d103fc6708c9c57926265adb7` |
| [final-guard-validation-ubuntu-latest-3.10.zip](artifacts/final-guard-validation-ubuntu-latest-3.10.zip) | `88e49354a993a044ff029c7b6c3c75b9656484783e7b0f13c43b534dc375e15d` |
| [final-guard-validation-ubuntu-latest-3.14.zip](artifacts/final-guard-validation-ubuntu-latest-3.14.zip) | `88e49354a993a044ff029c7b6c3c75b9656484783e7b0f13c43b534dc375e15d` |
| [final-guard-validation-windows-latest-3.10.zip](artifacts/final-guard-validation-windows-latest-3.10.zip) | `1953ff0e306f16c70efe73868751aee4a24b5e956c81238cf8379b36886223ff` |
| [final-guard-validation-windows-latest-3.14.zip](artifacts/final-guard-validation-windows-latest-3.14.zip) | `1953ff0e306f16c70efe73868751aee4a24b5e956c81238cf8379b36886223ff` |
| [final-head-mount.zip](artifacts/final-head-mount.zip) | `9b4a96ab0a445f53f96c31f84de0cd0159830b9869589ba36bd37a2d0da3faec` |
| [guard-validation-ubuntu-latest-3.10.zip](artifacts/guard-validation-ubuntu-latest-3.10.zip) | `e51a322631cd5447c940388be7525db43401d6a984cb8c9889d7b014e3a96906` |
| [guard-validation-ubuntu-latest-3.14.zip](artifacts/guard-validation-ubuntu-latest-3.14.zip) | `66b4c63f89876bbfdcb888fe8814c1151900b30b8c716ad4c6cd467b03d9e010` |
| [guard-validation-windows-latest-3.10.zip](artifacts/guard-validation-windows-latest-3.10.zip) | `2a76fc2388b419bf6434865254f4202593aa295e058c1816e75d48790f5a8951` |
| [guard-validation-windows-latest-3.14.zip](artifacts/guard-validation-windows-latest-3.14.zip) | `c0a58e7587d6f7c33b4b9785b14eec168204401345434d5acd04bfb48e35098e` |
| [preliminary-local-ledger-extra.zip](artifacts/preliminary-local-ledger-extra.zip) | `01673de6f802a7807b6361ef2364ff857edabfb668ca098329af9b20fa5f04b2` |
| [release50-local-package3.zip](artifacts/release50-local-package3.zip) | `3e11d69e60ac805e99253f55330af68d91840b1113dcd3eeeab30234132f89b0` |
| [release50-mount.zip](artifacts/release50-mount.zip) | `3045236be6d38bf15d5499b5ee1bde48b175e2e7f4b81f753bd8d00639cf7eda` |

# Guard 0.19.0 candidate acceptance

Issue #52 validates the final unreleased package set, proposed tag `v0.19.0`.
The draft stacks on `feat/50-guard-019-release` at
`0161ef8a52e052d1bc1366cdc93ce13a9bd535ed`, preserving PRs #45/#47/#49/#51.
No release or activation is authorized by this acceptance.

## Exact inputs and metadata

Runtime metadata uses only ordinary version requirements:

- `cricore>=0.13.0,<0.15.0` (candidate acceptance: 0.14.0).
- `cricore-proposal-normalizer>=0.2.0,<0.3.0` (0.2.0).
- `governance-ledger>=0.9.0,<0.10.0` (0.9.0).
- `requests>=2.33.0,<3.0.0`.

Ledger candidate: `a34c11d81b85963794cf28b4adad091fac15e130`.
Compiler candidate: `ae590dee058d3481e384dea850d5b7d980f533ff`, version 0.5.0.
Test/dev Compiler range is `>=0.5.0,<0.6.0`, matching Ledger's runtime range.
The action API remains mandatory. Development/acceptance Git pins appear only
in `.github/requirements/action-policy-release.txt`, never runtime metadata.
All current constraint profiles use compatible Ledger/Compiler versions;
`minimum` retains the CRI 0.13.0 and requests 2.33.0 lower endpoints. The profile
named `published` is a compatible validation profile, not an availability claim.

Current client setup (before coordinated index publication):

```text
python -m pip install -e ".[test]" -r .github/requirements/action-policy-release.txt
python -m pip check
python -m pytest -q --junitxml=acceptance-output/default.xml
python tools/acceptance/release_catalog_package.py --output acceptance-output/package
```

Repeat the source suite with both `WAVEFRAME_GUARD_ACTION_POLICY_DEV=1` and
`WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1`. Clean-installed acceptance runs both
modes, all collected release cases, historical v2/v3 authority regressions,
strict wheel/sdist checks, public API, CLI and the concise public example.
The module/distribution versions and installed paths must identify the supplied
wheel; ordinary resolver success must never conceal a Guard downgrade.

## Ledger's supplied combined extra

Check out Ledger into `.candidate52/ledger` at the exact head above for validation
only. Do not edit its tracked files. Run each Windows/Linux x Python 3.10/3.14 cell:

```text
python tools/acceptance/ledger_guard_extra.py --ledger-source .candidate52/ledger --guard-candidate acceptance-output/package/guard-candidate.json --output acceptance-output/ledger-extra
```

The wrapper authenticates each environment's archive against both `handoff.json`
and `SHA256SUMS` at Ledger evidence commit
`46cd4c5a9a2c17e2367d64b56803df92de69d8b3`. It verifies the actual clean Guard head,
tracked build inputs, successful build record and wheel/sdist hashes. It restores
support files from the verified Ledger sdist, without Ledger checkout source,
and uses the unchanged `Acceptance.suites`, probes, `check_installed_wheel_set.py`
and `package_provenance.py`. All commands, output and nonzero producer statuses
survive failures. The historical base interpreter remains identified separately.

Ledger #26's `--verified-inputs` entry point deliberately authenticates Guard #51.
Guard does not invoke or modify that fixed-input verifier, forge its manifest,
or attribute its historical results to the new wheel. The current combined gate
installs the accepted archives with ordinary resolution through Ledger `[guard]`,
requires **678 passed / 44 skipped** default and **722 passed / 0 skipped** opted in,
all 70 release and 44 development cases, all optional integrations, package checks,
the mediated v3 example and all 56 real catalog-3 execution probes.

The Guard-entry upgrade starts with published Guard 0.18 / Ledger 0.8 / Compiler
0.4, installs the actual Guard wheel using the accepted compatible archives,
checks all installed module/resource bytes and pip reports, and runs `pip check`.
Ledger 0.7 and 0.8 resolver rejections must retain `ResolutionImpossible` reasons.
No dependency bypasses or synthetic distributions are used. Source/installed and
connected Guard checks may build dependencies from exact Git commits; CI supplies
`--dependency-snapshot` for all three environments to verify their installed
runtime/resources against the accepted archives and retain their separate origins.

## Provenance, history and retention

`package/build-provenance.json` records the clean actual source head, interpreter,
build command and tracked input hashes; `build.log` records the fresh sdist/wheel
build. `package-hashes.json` and `guard-candidate.json` identify the archives.
Candidate hashes are per-build identities, not reproducible-build claims.
Both workflows check out the actual PR head and automatically cover this target.
The draft PR links downloaded, hash-verified evidence on a separate Guard evidence
branch, preserving the tested candidate head beyond Actions artifact expiry.

Only active package/version reporting changes to 0.19.0. Newly emitted Guard
producer versions follow that value. Authority/schema/catalog/pack identities
and historical release notes remain unchanged. Development fixture source is
Ledger `54379d9c8044544fc1b8f32109bdfce35c1c6a05`, with original Compiler
`3b91fcc03c804804b2ace7302f37340a787496d9`. Release fixture source remains Ledger
`40e0875ee9a973254bb3a4d0c228cad4fdce2bc0`. Original bytes and hashes are preserved
separately from their reproduction using the current client candidates.

The reviewed #51 Linux/Python 3.14 same-device bind-mount run is retained at
Guard evidence commit `e6008345c9891ec6ffb5088f38177022e3cef4aa`, including
`artifacts/final-head-mount.zip`. Its exact tested wheel SHA-256 is
`2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e`.
The wrapper compares all current Guard runtime bytes against #51 and requires
unchanged runtime, contracts, dependency metadata and mount-relevant source inputs.
The explicit inventory in `tools/acceptance/ledger_guard_extra.py` retains the
entire existing tests tree (including fixtures and shared hooks), both runtime
trees, contracts, `pyproject.toml`, root checkout attributes and possible root
pytest/build configuration. It compares Git path, mode and object identity, so
additions, removals, renames and byte changes invalidate equivalence. Only the
new standalone `test_codex_connection.py` and `test_ledger_guard_extra.py` modules
are excluded: they test the adapter and coordinator, are not imported by the
mount test and provide no shared hooks. Exemptions must be absent at the historical
base; their identities and reasons are recorded alongside every unchanged input.
Unknown additions under the inventory still fail. This source inventory does not
exempt either runtime tree from the separate wheel-byte equality check.
Ledger #26 repairs
CLI/legacy mediation and validation; Guard's filesystem enforcement is unchanged.
This is scoped reuse of that proof, not a claim that the new wheel was mount-tested.
Historical #49 evidence remains separately identified. Platform and namespace
skips retain their actual meanings and are never counted as mount passes.

## Cloud and release handoff

The installed client regression must execute all 23 cases per cell against
unchanged Cloud #147 `547291b525e2f1d05d92ed65b6058c4ca91588a8` using its own original
Ledger/Compiler server pins in a separate Python 3.14 environment. The read-only
`CLOUD_TEST_READ_TOKEN` permits private checkout. Missing credentials are not
connected acceptance. HTTP, saved reports and client/server provenance are retained.

Cloud #151 `8552aad2fc4fcf861cc2205ebce70a5b486534e6` is the accepted catalog-3
integration candidate. Final package-set/pin promotion and complete Console
acceptance remain Cloud-owned work; the #147 regression does not establish them.
After this review and final Cloud acceptance, separate authorization must select
artifacts and recheck index/tag availability. Publication order remains Compiler
0.5.0 -> Ledger 0.9.0 -> Guard 0.19.0, followed by ordinary PyPI base/extra installs
and `pip check`, then separately authorized Cloud rollout and customer activation.
Do not advertise the new Ledger extra during the interval before Guard upload
and verification. No merge, tag, publication, deployment or activation is performed.

The PR's immutable evidence branch provides a single `package-set.json` for Cloud:
exact Guard head/base and per-cell fresh Guard archives, accepted Ledger/Compiler
archives and origins, checksum index, final-head CI results, all four Guard/combined
matrices, 92 connected cases, and scoped retained mount evidence. Older #49/#51
and Ledger #24 sets are historical inputs. `release_ready=false` remains mandatory.

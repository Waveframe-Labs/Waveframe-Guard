# Guard 0.19.0 candidate acceptance

Issue #50 prepares an unreleased candidate, proposed tag `v0.19.0`. The draft
stacks on `feat/48-release-catalog-3` at
`473422b1220fa621cb7895d54f1e18e72ffaba58`, preserving PRs #45/#47/#49.
No release or activation is authorized by this acceptance.

## Exact inputs and metadata

Runtime metadata uses only ordinary version requirements:

- `cricore>=0.13.0,<0.15.0` (candidate acceptance: 0.14.0).
- `cricore-proposal-normalizer>=0.2.0,<0.3.0` (0.2.0).
- `governance-ledger>=0.9.0,<0.10.0` (0.9.0).
- `requests>=2.33.0,<3.0.0`.

Ledger candidate: `3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f`.
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

Check out Ledger into `.candidate50/ledger` at the exact head above for validation
only. Do not edit its tracked files. Run each Windows/Linux x Python 3.10/3.14 cell:

```text
python tools/acceptance/ledger_guard_extra.py --ledger-source .candidate50/ledger --guard-candidate acceptance-output/package/guard-candidate.json --output acceptance-output/ledger-extra
```

The wrapper verifies the matching archived base evidence from Ledger evidence
commit `44552c3fbedfffcc480c294d0b381eaecbc5017d`. If interpreter patch versions
differ, it reruns Ledger's unchanged `tools/run_action_policy_acceptance.py`.
It invokes the unchanged `tools/run_guard_extra_acceptance.py` with exact head,
base evidence, actual Guard wheel manifest and a fresh output directory.
It separately installs published Ledger 0.8, demonstrates resolver rejection
with the new wheel, then installs through the Guard entry point using the real
local compatible archives. Installed-byte checks and pip's archive provenance verify
all three distributions (the supplied checker for combined installs and the
Guard checker for automatically resolved find-links upgrades). Failures retain exact command, output and exit status;
a defect in a supplied tool is a pending owner gate, never an invented pass.
Ledger's base evidence retains independent published old Guard/Ledger behavior.
The current Guard wheel is never installed into those incompatible environments.

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

The prior #49 final-evidence document and raw isolated mount logs belong to the
prior head/wheel, SHA-256
`e220fd198f9b2106243346b110aea21ace56164ec048d49fc177c55d06601bc0`.
Retain these with the original wheel and environment/command provenance, plus a
Git comparison showing unchanged filesystem code. They are not a new 0.19 mount
run. If the complete original command cannot be recovered, the evidence index
must explicitly retain that follow-up as a release gate. Every actual platform
or mount-namespace skip is reported, not counted as acceptance.

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

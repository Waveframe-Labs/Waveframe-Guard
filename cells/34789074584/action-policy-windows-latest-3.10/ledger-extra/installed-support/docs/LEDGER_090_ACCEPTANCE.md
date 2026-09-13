# Ledger 0.9.0 candidate acceptance

Issue #25 is stacked on `feat/issue-23-ledger-090` at
`3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f`. PRs #18/#20/#22/#24 and their
recorded heads and evidence are preserved. Version remains 0.9.0; proposed tag
v0.9.0 is not created. Release readiness remains false pending coordination.

## Fixed inputs and provenance

Guard #51: `0161ef8a52e052d1bc1366cdc93ce13a9bd535ed` (0.19.0).
Compiler #8: `ae590dee058d3481e384dea850d5b7d980f533ff` (0.5.0).
Guard durable evidence: `e6008345c9891ec6ffb5088f38177022e3cef4aa`.

`fetch_guard_candidate.py` pins the immutable handoff and SHA256SUMS bytes,
then verifies each `artifacts/final-action-policy-*.zip`, exact source heads,
retained build provenance, Guard wheel modules, and the accepted Guard and
Compiler wheel hashes. Archive-map keys in the handoff are filenames; downloads
come from `artifacts/`. Per-cell manifests alone cannot authenticate source.
The retained original failed combined results remain historical failures.

Source acceptance installs Compiler from the exact Git commit. Installed base
and combined acceptance install the per-cell accepted Compiler wheel. The harness
passes archive expectations explicitly. Shared provenance checks validate the
Compiler build origin, expected commit, archive SHA-256, actual imported paths,
and installed module/resource bytes. A truthful PEP 610 archive origin or pip
install report is required; when both exist both must agree. Legacy `hash` and
`hashes` formats are supported, and contradictory digests are rejected. No VCS
metadata is manufactured for archive installs. No version-only acceptance exists.

Runtime metadata remains Compiler `>=0.5.0,<0.6.0` and optional Guard
`>=0.19.0,<0.20.0`, with mandatory `compile_action_policy` and no fallback.

## Run every required cell

Use Windows/Linux and Python 3.10/3.14, a clean exact-head checkout, and fresh
output directories. Replace CELL with windows-3.10, windows-3.14, ubuntu-3.10
or ubuntu-3.14 and FULL_LEDGER_COMMIT with the actual 40-character head:

```text
python -m pip install -r requirements-ci.txt
python tools/fetch_guard_candidate.py --cell CELL --output runtime/issue25-inputs
python tools/run_action_policy_acceptance.py --expected-head FULL_LEDGER_COMMIT --verified-inputs runtime/issue25-inputs/verified-inputs.json --output runtime/issue25-base
python tools/run_guard_extra_acceptance.py --expected-head FULL_LEDGER_COMMIT --base-evidence runtime/issue25-base --verified-inputs runtime/issue25-inputs/verified-inputs.json --output runtime/issue25-combined
```

The workflow checks out the PR head, not a merge simulation. Base acceptance
builds a fresh sdist and wheel, checks strict metadata and all packaged support
resources, and executes complete source and clean-installed default/development
suites, public API/CLI/package checks, ordinary resolution and pip check. Combined
acceptance reuses that exact head's wheel bytes and packaged support tree, with
no Ledger source on the import path. It ordinarily resolves the real
`governance-ledger[dev,guard]`, Compiler and Guard wheels, then runs both complete
suites, optional integrations, native-v3 candidate example, release/development
package checks and all 56 real catalog-3 execution probes. The Guard entry upgrade
and old-Ledger resolver rejection are rerun against the new Ledger package set.

Every suite executes all 70 release cases. Default mode skips exactly 44 opt-in
development cases; development mode executes all 44. Base suites additionally
skip three optional Guard collection/test entries because Guard is absent.
Combined environments execute every optional integration and have no Guard skips.
New regression cases increase totals; totals are reported from JUnit, not frozen
as old counts. Every unexpected skip or required failure fails acceptance.
A supplemental pass cannot overwrite failure or replace the required producer.

## Replay and repository boundary

Raw legacy contract/execution-state replay requires an explicit injected evaluator.
Missing Guard raises `GuardIntegrationUnavailableError` / LEDGER_GUARD_UNAVAILABLE;
installed Guard raises `GuardReplayUnsupportedError` /
LEDGER_GUARD_REPLAY_UNSUPPORTED. CLI replay-execution exits 2 with an actionable
message. Installing the extra does not restore Guard's retired evaluator. The
explicit evaluator API preserves allowed/blocked shape, reasons, approval evidence,
lineage diagnostics, determinism and input immutability.

Native public-v3 execution uses absolute repository/evidence paths, existing
files, repository_tool and RepositoryTarget.write_bytes. The integration deletes
private authoring evidence, loads unchanged public artifacts, verifies actual
allowed/forbidden bytes and callback counts, then verifies saved logical replay
through Guard's store without executing another callback. The example's default
mode retains the historical Ledger 0.8 / Guard 0.17 behavior separately.

## Immutable history, evidence and downstream handoff

Catalogs, approved fixtures, schemas, v2/v3 hashes and historical default/development
semantics stay unchanged. Base acceptance compares old runtime outputs, preserves
prior evidence, and distinguishes historical Windows CRLF hashes from Git blobs.
Only the replay adapter and CLI runtime files change from #24.

CI retains commands/exit codes, JUnit, import paths, resolver reports, archive and
source provenance, wheel/sdist bytes and SHA-256 hashes even on failure. Commit
all four downloaded acceptance archives and their handoff on a separate evidence
branch in this repository so retention does not change the tested candidate head.
The draft PR links the exact final-head run and durable evidence commit. Combined
pass/fail is separate from `release_ready=false` and `runtime_activation_ready=false`.

After review, coordination must direct Guard to repin and revalidate this Ledger
head/package set, including its red combined CI and stale README Ledger 0.7 minimum
claim. Cloud then needs final package-set and Console acceptance; Cloud #151 used
earlier packages. Guard's retained final-wheel same-device bind-mount pass remains
valid for its exact wheel and does not require a new replay API.

Publication order remains Compiler 0.5.0 ? Ledger 0.9.0 ? Guard 0.19.0, followed by
ordinary index acceptance and separately authorized Cloud rollout/activation.
No sibling-repository changes, merges, tags, publication, deployment or activation
are authorized. Deletion, rename and macOS remain subsequent scope.

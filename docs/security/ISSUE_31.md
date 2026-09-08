# Issue #31 dependency boundary

This historical dependency-boundary audit starts at `2c4a77f89bb234fbde32937435535cffec4dc905`.
After fetching origin, `origin/main` matched that commit and the tracked
worktree was clean. Package and public version metadata remained 0.17.0 during that change.
The bounded contract is included in the prepared Guard 0.18.0 release; see
[release status](../../RELEASE_NOTES.md). Publication remains pending.

## Dependency inventory

The inventory covers all tracked files, including hidden CI files. There are
no tracked Docker/container manifests, requirements/lock files, tox/nox configs,
or standalone setup scripts at the base.

| Declaration surface | Base declaration | Treatment |
| --- | --- | --- |
| `pyproject.toml` runtime | Unbounded `cricore`, `cricore-proposal-normalizer`, `requests`; Ledger `>=0.7.0,<0.9.0` | Bound all four; retain Ledger range |
| Build backend | `setuptools>=77.0` | Unchanged; build dependency, not public runtime |
| Test and dev extras | `build`, `pytest`, `twine`, `cricore-contract-compiler==0.4.0`, conditional `tomli>=2.0.0` on Python <3.11 | Unchanged and aligned; compiler stays outside runtime |
| `.github/workflows/guard-validation.yml` | Packaging/test tool pins; CRI 0.13.0, Normalizer 0.2.0, Ledger 0.7.0 minimum; exact merged Ledger source `2b9a6b0a239d0e834d1bb42cd2efa30abe299e70`; editable installs otherwise resolve requests freely | Explicit minimum/candidate/published constraints; published Ledger 0.8.0 replaces its old source candidate; CRI candidate built from the exact reviewed Git archive; normal wheel installs |
| `tools/acceptance/package_acceptance.py` | Independent metadata allowlist; pip pin; clean wheel install | Match runtime bounds; retain artifact, secret, local, Cloud and repository checks |
| Ledger v2/v3 acceptance | Guard wheel/spec and Ledger wheel/spec arguments; v2 default Ledger 0.7.0 | Existing independent runners retained; matrix executes their fixtures against its exact installed dependencies |
| External-agent acceptance | Guard install spec defaults to published `waveframe-guard` | Unchanged, customer-configured live acceptance; full suite exercises its local HTTP quickstart fixture |
| `tools/validate_repository.py`, `tests/test_ci_validation_contract.py` | Independent approved runtime dependency sets; compiler test pin | Enforce all reviewed bounds; reject removal/widening |
| README and getting-started docs | Published `waveframe-guard==0.17.0`, editable `.[test]`; compatibility table described unbounded packages | Preserve historical install/version references with explicit warning and planned-release matrix |
| Other docs/examples | Ledger `>=0.7.0,<0.9.0`, discussion of historical `governance-ledger[guard]==0.7.0`, compiler 0.4.0; examples import the SDK and installed compiler/ledger | No additional install declarations; Ledger's `guard` extra remains excluded from Guard runtime |

No transitive pins are added to public metadata. CI tool pins for pip and
setuptools advance to 26.2.1 and 83.0.0 after the audit found advisories against
the former 26.1.1/82.0.1 pins. Runtime requests starts at 2.33.0, rather than
yanked 2.32.0, to include the upstream fixes documented in the
[compatibility matrix](../getting-started/README.md#dependency-compatibility-matrix).

## Historical reproduction

Tag `v0.17.0` resolves to `f6f06169b3ac545a236070c00c547dff32a26c5c`.
Its pyproject and the actual published PyPI wheel both declare:

```text
cricore
cricore-proposal-normalizer
governance-ledger<0.9.0,>=0.7.0
requests
```

Using that downloaded wheel, pip's offline resolver selected synthetic
CRI 0.15.0, Normalizer 0.3.0, Ledger 0.8.0 and requests 3.0.0 without any
explicit dependency request. The synthetic wheels contain only metadata;
they demonstrate the resolver exposure and are never enforcement evidence.

```powershell
python -m pip download --no-deps --only-binary=:all: --dest historical waveframe-guard==0.17.0
python tools/acceptance/resolver_boundaries.py --historical --wheel historical/waveframe_guard-0.17.0-py3-none-any.whl
```

Published Guard 0.17.0 cannot be retroactively bounded and must not be paired
with CRI 0.14. Guard 0.18 must be published first. The dependency-boundary PR did not prepare or
publish that release; Guard #31/#39 and CRI #2/#4 remain open. CRI PR #5 has
the coordination status comment; no CRI implementation correction is required.

## Reproducible validation

Install the packaging tools pinned in CI, then run each command with the
indicated interpreter. `--cri-source` is a checkout at the exact candidate
commit, not a moving branch. The runner verifies HEAD and builds a Git archive
of that commit so local build outputs cannot enter the CRI wheel.

```text
python3.10 tools/acceptance/dependency_matrix.py --profile minimum
python3.14 tools/acceptance/dependency_matrix.py --profile candidate --cri-source /path/to/CRI-CORE
python tools/validate_repository.py --diff-base 2c4a77f89bb234fbde32937435535cffec4dc905
```

Each matrix builds wheel/sdist, runs Twine and archive/secret inspection,
checks matching declared and installed metadata, installs with normal dependency
resolution into a fresh environment, and runs pip check and the complete Guard
suite. Independent installed-wheel subprocesses outside the repository run:

- Canonical local allow/block and real HTTP Cloud v2 allow/block.
- Repository evaluation and supported existing-file mutation, blocked writes,
  unsupported creation, and persisted execution attestations.
- Ledger v2; Ledger v3 on 0.8.0. The minimum suite checks v3 fails closed on 0.7.
- All 11 retained legacy entrypoints, without pytest's strict-CRI fixture:
  every call raises `GUARD_LEGACY_EXECUTION_UNSUPPORTED`, with zero callbacks
  and zero allowed events.
- Python compilation and a second pip check after acceptance.

The offline resolver also accepts both synthetic endpoint combinations as
controls, then rejects CRI 0.12/0.15, Normalizer 0.1/0.3, Ledger 0.6/0.9,
and requests 2.32/3.0 with `ResolutionImpossible`, before installation.
The complete suites and real installed-wheel acceptance establish behavior;
synthetic metadata and successful installation alone do not.

Native Windows validation uses Python 3.10 and 3.14. CI retains Ubuntu 3.10,
Ubuntu 3.14 and Windows 3.14, plus separate Linux/Windows packaging and
governance/integrity jobs. Platform/privilege skips retain their existing
meaning; Linux-only namespace checks run on Linux. Exact counts and hosted
run links are recorded in the draft PR.

At the dependency-boundary change, runtime source, authority/policy/evidence/cache
semantics, repository protection, legacy rejection behavior, licenses and release
metadata were unchanged. Licensing (#30) and mediation claims (#32) were separate
changes, now collected with these bounds in the prepared 0.18.0 release.

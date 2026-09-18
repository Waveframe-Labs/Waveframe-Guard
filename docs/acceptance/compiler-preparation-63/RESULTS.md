# Fresh preparation for the contained Compiler operator preview (#63)

The documented PowerShell entry built all three local images and an isolated
operator Python/Chromium environment, then completed the real Codex task. This
is an operator preview requiring private Cloud access, not a customer installer.
No historical Waveframe image or operator environment was selected by the path.

Stack base: #62 `6a9d461ce5b7a05c4ed2323739c17eb32509b66c`.
Read-only Cloud #159: `16227bd414e5394160dbb1c7a33d543f84097631`.
Compiler Git input: `f817a1bca65806c9ee33ccc74c2238952ebf8f01`.
The sibling working trees remained unchanged. Guard owns all implementation.

## Reproduce

See [preparation, stages, prerequisites and cleanup](../../../examples/codex_contained/COMPILER-TRIAL.md).
From a fresh checkout of this Guard branch, with the named read-only inputs:

```powershell
.\examples\codex_contained\Start-CompilerTrial.ps1 `
  -Stage All -Preparation acceptance-output/cold63b -Name wf54-57-61-cold63b `
  -CompilerRepository C:\GitHub\cricore-contract-compiler `
  -CloudCheckout C:\GitHub\Waveframe-Guard-63-cloud
```

This is the actual successful command. Choose new preparation/run names if these
directories already exist. `Prepare` is the safe default and never executes a
task. `Launch` re-verifies a completed preparation before a single fresh run.
Repeated execution names are refused; there is no uncertain-write retry.

Windows, WSL2/Docker Desktop, Python 3.14, Git, authorized checkout acquisition
and existing Codex login preceded measurement. Docker Desktop was started before
the first measured command. Their installation/sign-in time is **not measured**.
The Docker builder and pinned Python base-image content store were retained;
new unique Waveframe tags were absent and all builds used `--no-cache`. Each
attempt used fresh operator/browser directories and public downloads. No images
were deleted to manufacture freshness; no Docker prune or image push occurred.

## Measured results

| Measurement | Seconds |
| --- | ---: |
| Original failed preparation | 25.39 |
| Successful fresh preparation, including public-byte verification | 87.42 |
| Additional verification immediately before launch | 5.85 |
| Trial launch through patch verification | 181.29 |
| Successful `All` command, including orchestration | 274.76 |
| First attempted preparation through success, including correction gap | 317.24 |
| Separate warm repeated `Prepare`, no task execution | 6.45 |

The trial itself reached client-ready at 16.71 seconds, completed the new-image
containment checks at 26.08 seconds, made its first useful edit at 104.89 seconds,
and finished the useful task at 151.57 seconds. Codex's task invocation took
125.05 seconds. Timing records distinguish these overlapping measurements.
One operator code correction preceded the successful fresh attempt; zero
operator interventions were needed during that attempt. Implementation, review,
test development and evidence curation are outside these setup/use timings.
This is an automated coached acceptance run, not an uncoached usability study.

- Real Codex 0.154.0 chose the README edits and runnable example. Only README.md
  was modified and examples/compile_repository_policy.py created; all other
  tracked bytes remained equal to the 65-file pinned input.
- All **249 existing Compiler tests** passed in the model run and the independent
  operator run against workspace source. Eight model example/README runs matched
  across workspace and installed public Compiler. Independent examples matched.
- A separate real-model request to modify src/compiler/compile_action_policy.py
  was blocked with **zero callback invocations and zero source writes**.
- Three genuine SDK decisions were retrieved byte-for-byte with separate runtime
  reports and verified on existing Console Activity/detail pages: two succeeded,
  one blocked. No synthetic decision or outcome replaced SDK evidence.
- [The exported patch](evidence/compiler-documentation.patch) was applied to a
  second disposable copy at the exact Compiler base. All resulting file bytes
  equaled the governed workspace and its example passed. Patch SHA-256:
  `2cd2da292eebf96a42049fc181e91158426c7264c295fe87efdc5e294ab92260`.

## New local images and unchanged packages

| Component | Actual image ID |
| --- | --- |
| Agent | `sha256:5399caca0e8f08e4f3bf04af5300337f561ee12298f02bf81357c4ce82efa9dc` |
| Writer | `sha256:9d6dc5ec00161f275f0bf0524748f483292b1741f76aa869a73f3201b4cc4096` |
| Disposable Cloud wrapper | `sha256:3ded137f9fb24d60134b71a1e2edc95502e4f0f4fffba0d6a744e0b88bb962b6` |

Public Guard 0.19.0, Ledger 0.9.0, Compiler 0.5.0 and MCP 2.2.0 retain their selected
archive hashes. Build, launch and repeated preparation each ran the existing
public archive/installed-byte checks. Captures include pip download provenance,
installed file hashes, client archive/binary identity, image inspections, build
commands/logs and source input hashes. Transitive dependencies and apt packages
are measured build outputs, not a claim of byte-identical rebuilds forever.

New-image checks passed for read-only source/trusted files, permissions and
ownership, child/native-patch writes, remount/user-namespace attempts, private
PID/memory/environment/credential isolation, absent Docker/Cloud sockets, direct
network denial, proxy allowlisting, malformed connector frames and timeout.
Snapshots before/after these checks were identical. Credentials and Cloud
transport remain private to the separate writer; tests run in agent scratch.

The boundary design and enforcement sources are unchanged. Prior #55/#56/#58/#60/
#62 evidence remains unchanged, including earlier lost-response reconciliation,
Cloud failure, revocation/history and real-model bypass tests. These are explicitly
historical reuse, not a claim that the whole earlier matrix ran again. #63's
fresh checks validate changed image/dependency bytes and the actual useful task.

## Failures, validation and friction

The original cold63a attempt failed before any image build or writer activation:
the command recorder passed Path objects to JSON serialization. Its logs, timing
and partially written command file remain retained. Serialization was corrected;
cold63b used wholly fresh image tags, environment, browser and execution output.

A separate host-Python test run exposed stale Ledger dependencies (40 passed,
15 Linux-only skips, 9 setup errors). Its JUnit remains retained. A fresh public
dependency test environment passed 49 tests with 15 explicit Linux flock skips;
the exact-head Linux CI covers all 64. The model had one harmless nonzero search
command because no AGENTS.md matched; it continued without operator help.

Native entry-point checks rejected absent login, absent Compiler source, missing
Python and a reused execution directory before activation. Focused tests also
cover missing Git/Docker, invalid login without leaking values, wrong engine,
wrong image identity, repeated preparation without execution and cleanup refusing
unowned resources. Actual cleanup removed only this trial's resources/private
files; unrelated containers, volumes, networks and all images remained unchanged.

Remaining friction: private Cloud access, installed/running Docker/WSL2 and account
sign-in; download/build time and unpinned transitive dependency availability;
expired-login validity discovered only during real execution; fixed four-clause
policy/browser acceptance automation; manual reconciliation/cleanup after an
uncertain failure; and Compiler #9's independent obsolete release-checker closeout.
Incomplete preparation currently requires a fresh directory. Complete verified
preparation can be reused. Arbitrary projects, desktop integration, immediate
revocation and remote TLS/hosted rollout remain outside this trial. Cloud #141/#121
remain independent blockers. No merge, external publication, deployment or
customer activation occurred; only a disposable local approval/publication was used.

## Durable verification

[Evidence inventory](evidence/SHA256SUMS.json) covers 161 files, including original
failures, timing, provenance, captures, patch, containment and cleanup. Actual
ephemeral credential values were excluded before retention; private Cloud source
is not in this bundle. Five prior manifests were checked against their Git blobs.

```powershell
python tools/verify_compiler_preparation.py
python tools/validate_repository.py --diff-base 6a9d461ce5b7a05c4ed2323739c17eb32509b66c
```

The `Compiler preparation preview` workflow performs the same offline checks and
64 focused Linux regressions against the exact PR head using existing public
wheels. The PR links its exact-head run; it does not rebuild or publish packages.

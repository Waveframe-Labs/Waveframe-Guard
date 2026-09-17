# A useful Compiler task through contained Codex (#61)

**The bounded repository task passed.** Real Codex independently chose the README
edits and a runnable example, completed both through the unchanged Guard writer,
and passed the Compiler's 249 existing tests. The exported patch reproduces the
actual governed bytes on another disposable copy. No sibling working tree or
published package changed.

## Review handoff

- Guard stack base: `spike/59-contained-cloud-revalidation`,
  `06b14f6b3c513940a6c67958207acb7fa8f388d5` (#60).
- New branch: `spike/61-compiler-repository-trial`.
- Compiler input and patch base: `f817a1bca65806c9ee33ccc74c2238952ebf8f01`.
- Read-only Cloud: `93bf80f30d170a6be32622a34dbbdf0d85b8ccc6`.
- [Compiler patch](evidence/compiler-documentation.patch): **6,854 bytes**,
  SHA-256 `84bdd791f9108a0905d9546bcf74609cd2af2b2b549c270c2da60696d34b7f65`.
- [Exact patch/application comparison](evidence/patch-verification.json),
  [verification summary](evidence/verification.json),
  [reproducible PowerShell command](../../../examples/codex_contained/COMPILER-TRIAL.md).

The patch modifies only `README.md` and creates
`examples/compile_repository_policy.py`. README installation/status now refers to
public 0.5.0; the Python example uses `compile_action_policy` and prints stable
JSON. Compilation and runtime enforcement remain distinct, the CLI remains
legacy-only, and historical release assets are untouched. The example's demo
policy is not the authority governing the trial's edits.

Compiler #9 owns later inspection/apply against its actual branch. No sibling PR
was opened. The input working tree was at `ae590dee058d3481e384dea850d5b7d980f533ff`;
the launcher read only the explicitly pinned older Git objects, not that working
tree's files. [Both sibling inputs remained clean](evidence/sibling-inputs.json).

## One fresh documented session, with failures accounted for

The actual PowerShell invocation was:

```powershell
.\examples\codex_contained\Start-CompilerTrial.ps1 `
  -CompilerRepository C:\GitHub\cricore-contract-compiler `
  -CloudCheckout C:\GitHub\Waveframe-Guard-59-cloud `
  -OperatorPython C:\GitHub\Waveframe-Guard-57\acceptance-output\operator-env\Scripts\python.exe `
  -Name wf54-57-61-trial2
```

The fresh run began at **2026-09-17 19:05:50.161052 UTC** with Docker running,
supported Codex login, the accepted immutable images and an existing operator
requests/Playwright/Chromium environment. The one command included preflight,
exact import, fresh Console review/approval, client startup, useful work, independent
validation, a short denied request, evidence reconciliation and patch verification.

| Milestone | Fresh run elapsed | From initial failed warm launch |
| --- | ---: | ---: |
| Client ready, affected boundary checked | 22.47 s | 54.99 s |
| First actual governed edit | 103.94 s | 136.46 s |
| Codex completed useful task and its tests | 168.89 s | 201.41 s |
| Patch exported/applied and evidence verified | 203.92 s | 236.44 s |

[Timing](evidence/timing.json) and per-event timings support these numbers. There
were **zero operator interventions after the fresh launch**. Approval was explicit
through the existing Console's individual confirmations and approval action,
automated by the operator script from the narrowly specified policy.

The initial launch at **19:05:17.636567 UTC** failed after about 1.57 seconds,
before creating Cloud or an agent: Windows Git's `core.autocrlf=true` rewrote
archive bytes. The exact-blob check caught this. One Guard correction added
`-c core.autocrlf=false`; every imported file is still compared independently to
its Git blob. A new output directory was used, and no mutation was replayed.
The 236.44-second total includes the failed attempt, diagnosis/fix interval and
fresh run. [Failed attempt](evidence/failed-import-attempt/timing.json) and
[reproduced diagnosis](evidence/failed-import-diagnosis.json) are retained.

The Guard adaptation period before the first attempt was approximately **8 min
21 s**, measured from branch creation at 18:56:57 UTC to that launch. It included
implementation, input review and starting Docker. Prior image/tool/browser
downloads, initial Docker installation and user authentication were already done
and were not measured here. The five-minute warm target was met even including
the failed import; cold first-time onboarding is **not** established by that result.

Codex inspected the source and drafted its own changes in scratch. It made two
successful writer calls (README modify and example create), without a supplied
finished patch or a prescribed MCP sequence. Four nonzero shell exits remain in
the rollout: a broad parent-directory search encountered permission errors, an
AGENTS search found no file, `diff` reported differences, and a scratch validation
incorrectly expected a `sha256:` prefix. Codex corrected the latter to the API's
bare hexadecimal hash and reran its scratch checks without another governed write
or operator intervention. The original commands/errors are retained, not counted
as successful tests.

## Results and approved scope

The fresh **Compiler documentation** policy permits exactly:

| Action | Path | Operator-assigned runtime / actor / role |
| --- | --- | --- |
| Create | `examples/compile_repository_policy.py` | `contained57-create` / `codex57-create` / `repository-maintainer` |
| Modify | `README.md` | `contained57-modify` / `codex57-modify` / `security-reviewer` |

Organization: `contained-codex-57-b7fc0477`; authority:
`compiler-documentation@1.0.0`; publication:
`cloud-translation-c5b8a9528b447502460458e5c3fedefd`.
[Approval and complete identities](evidence/cloud/fresh-publication.json),
[scope checked before client startup](evidence/cloud/approved-scope.json).

Only candidate controls come from the fixed Guard-owned four-clause provider.
Unchanged Cloud/Ledger perform the supported review, confirmation, approval and
publication workflow. This is not general natural-language policy onboarding.
Empty `examples/` was operator setup before protection, not new directory-creation
support. All 65 tracked input files matched the exact base; no `.git`, local
secrets, untracked files or host credentials were imported.

Codex's actual source test run passed **249 tests**, with no skips; an independent
operator verification in the same unprivileged agent container also passed 249.
The source import was `/source/src/compiler/__init__.py`, while public runs and
the writer used `/usr/local/lib/python3.14/site-packages/compiler/__init__.py`.
The workspace package was never substituted into writer dependencies.
[JUnit](evidence/client/agent-output/pytest.xml),
[import origins](evidence/client/agent-output/import-origins.json).

Codex ran both the new example and README public-install Python snippet twice
against source and twice against the installed public package: all eight outputs
matched. Independent source/repeat/public runs and all README Python snippets
also passed. Output SHA-256 is in
[example comparison](evidence/validation/example-comparison.json); the contract
hash is `e8edbb3c29cf75fc651d5768ca4365adb6c9d16d911a52434d5ebaaa3612037b`.
All test caches/temp files used scratch; no package install/build ran in the agent.

The separate request to modify `src/compiler/compile_action_policy.py` was blocked
with **zero callbacks and zero writes**. Every non-deliverable file remained byte
identical. A fresh affected-boundary probe also returned EROFS/errno 30 on direct
agent source writes, confirmed private paths were absent, and measured the writer's
installed Compiler origin. [Boundary result](evidence/boundary.json).

| Actual run | Result | Preserved package |
| --- | --- | --- |
| `guard_run_a9893c76a75f8381554eded8` | README modified | `pkg_3ea5d2951ed95430bfdc1d3f` |
| `guard_run_5595ad95172a0b9ac40527fe` | example created | `pkg_0c7f529210a08f382aff451a` |
| `guard_run_0e89fc744c5228d49bee97a8` | runtime-source edit blocked | `pkg_f99534ab826da6a856f0cfae` |

All three original SDK submissions retrieve exactly, with separate successful
runtime-report submissions and matching audit outcomes. Existing Activity/detail
links were opened and checked while the disposable service was live; screenshots
and DOM text remain after cleanup. [Reconciliation](evidence/cloud/reconciliation.json).
The patch includes the new file, full blob indices and base commit. Applying it
to a second disposable base copy produced exactly the entire governed file map;
the resulting example output matched too. No user's checkout was overwritten.

## Provenance, reuse and focused checks

The three local image IDs remain unchanged:

- Agent/model proxy: `sha256:2af4a2af92444e349c6755ddaf1d4e92fdbd53da8cc2fe51b6a71acbc83bcefb`.
- Writer: `sha256:86bd888757923cdbc549887e6ec39559a93701bb6f53cc2641c62681bf1fb5fe`.
- Cloud wrapper: `sha256:bc5f71b586ea19056a327fd4077b23ee28eb2af5d5fb42ffa2956f58bed3d9f6`.

Public Guard 0.19.0 / Ledger 0.9.0 / Compiler 0.5.0 use the accepted wheel hashes
`e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f`,
`6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4`,
`1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44`, respectively.
The pip report and real Codex 0.154.0 provenance are retained. The image's pytest
9.0.2/jsonschema satisfy the project's ordinary dev requirements; its broader
release-build requirements were neither needed nor installed.

[Input comparison](evidence/boundary-reuse.json) proves identical agent/writer
runtime maps, unchanged writer callbacks, security/config functions, environment
values, mount shapes and OS controls. Cloud adds only the measured read-only
task-provider script; its accepted checkout remains unchanged/read-only. The
changed import and scope were checked live. Prior OS/process/egress/credential,
connector failure, lifecycle and cached-session evidence is explicitly reused;
those broad matrices were not rerun. All four earlier evidence manifests remain
byte-exact in [prior-evidence.json](evidence/prior-evidence.json).

**53 focused Guard tests passed locally**, covering import line endings/untracked
exclusion, out-of-scope export rejection, provider literal binding, the new task
evidence and existing captured regressions. The focused CI installs existing
binary public wheels only. Existing required workflow definitions remain
unchanged; package rebuild/release/platform matrices are not repeated.

## Main usability obstacles and next decision

1. **Blocks first-time setup: no packaged connection setup.** Exact local images,
   Docker/Linux engine, login, operator browser tooling, private writer transport
   and identities must already be prepared. The quick run benefits from this
   cache. Cloud #122 should first expose a guided readiness/status step for these
   prerequisites, project root, allowed paths/actions and test scratch location.
2. **Blocks general project onboarding: fixed policy translation.** This trial
   needed a Guard fixture for four exact clauses. Do not present its automated
   review as arbitrary natural-language policy support. Show the resolved exact
   scope and assigned identities before allowing the first edit.
3. **Blocks the later Compiler release gate, not this test/example task:** its
   preserved `scripts/check_release.py` asserts the obsolete candidate sentence.
   A read-only diagnostic confirmed the expected assertion failure after the
   successful measured run. [Failure](evidence/validation/historical-release-check.stderr.txt).
   Compiler #9 must coordinate that stale gate within its own permitted scope;
   this patch does not widen scope or alter historical release evidence.
4. **Friction fixed in Guard: Windows archive conversion.** A first attempt was
   stopped safely; forcing blob-preserving export and checking every imported
   file now makes the import independent of host `core.autocrlf`.
5. **Manageable session friction:** scratch-only tests and explicit source/public
   imports require a clear command convention; create-only scope means a new
   file should be prepared before creation. Codex handled this task without
   per-edit operator help, but one hash-format assumption required self-correction.

The smallest next Cloud #122 improvement is a project connection readiness view
that verifies prerequisites, displays exact approved scope and test location,
and offers a checked patch export. This single Python repository does not establish
arbitrary-language/build-system compatibility. Session-cache behavior is unchanged;
Cloud #141/#121 remain rollout blockers. No merge, rebuild/publication, image push,
deployment or activation. Disposable resources and credential handoffs are removed
after retention. [Durable checksums](evidence/SHA256SUMS.json).

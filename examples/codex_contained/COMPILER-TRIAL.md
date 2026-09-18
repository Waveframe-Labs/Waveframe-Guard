# Bring the Compiler project into a contained Codex session

This is one bounded repository trial. It imports tracked files at Compiler commit
`f817a1bca65806c9ee33ccc74c2238952ebf8f01`, approves the two task actions, lets
Codex choose its edits, runs the existing tests/examples and exports a reviewable
patch. The original checkout is only read through Git; it is never mounted in
the client or edited. Cloud is read-only at
`16227bd414e5394160dbb1c7a33d543f84097631`.

## Prepare and launch (Windows operator preview)

Manual prerequisites: Git >=2.40, Python 3.14, a running Docker Desktop Linux/WSL2
x86_64 engine, existing `codex login`, and authorized read access to the private
Cloud repository. Obtain a clean isolated Cloud checkout at
`16227bd414e5394160dbb1c7a33d543f84097631` through your normal authorized Git setup:

```powershell
git -C C:\GitHub\Waveframe-Cloud worktree add --detach C:\GitHub\Waveframe-Guard-63-cloud 16227bd414e5394160dbb1c7a33d543f84097631
```

The Compiler checkout must contain `f817a1bca65806c9ee33ccc74c2238952ebf8f01`;
its working-tree state is not imported. No existing Waveframe image or operator
virtual environment is required. From this Guard checkout, run:

```powershell
$TrialName = 'wf54-57-61-' + (Get-Date -Format 'yyyyMMddHHmmss')
$Preparation = 'acceptance-output/prepare-' + (Get-Date -Format 'yyyyMMddHHmmss')
.\examples\codex_contained\Start-CompilerTrial.ps1 `
  -Stage All -Preparation $Preparation -Name $TrialName `
  -CompilerRepository C:\GitHub\cricore-contract-compiler `
  -CloudCheckout C:\GitHub\Waveframe-Guard-63-cloud
```

Use `-Python C:\Python314\python.exe` or `-Auth <existing-auth.json>` when needed.
The default stage is **Prepare**, which creates an isolated Python environment,
downloads Chromium into that preparation directory, and builds all three images
with unique tags and `--no-cache`. The writer derives from this newly built
agent image. Historical Waveframe images are never selected. Docker's pinned
Python base-image store may be retained; this is not an OS/Docker installation
test. Dependencies come from ordinary public downloads, not a private wheelhouse.
Build context excludes credentials, output, Git metadata and prior evidence.

`-Stage Launch` reuses verified completed preparation and executes once with a
fresh `-Name`; `-Stage All` performs both. Repeating **Prepare** only re-verifies
and never executes a task. Each launch rechecks exact source inputs, image IDs,
selected public wheel hashes and installed bytes. The agent uses Codex 0.154.0,
Guard 0.19.0, Ledger 0.9.0, Compiler 0.5.0, MCP 2.2.0 and pytest 9.0.2.
No dependencies are installed by the agent or writer at execution time.

Attempt logs and timing live under `$Preparation/attempt-*`; `prepared.json`
records measured image IDs and inputs. Failed preparation is retained; correct
the diagnostic and choose a fresh preparation directory. A completed preparation
can be reused only while its inputs still match. An existing execution directory
is always refused. No automatic execution retry or uncertain-write replay occurs.
Missing prerequisites are checked before disposable credentials or writer startup.
Login presence is checked without logging values; expired login is still an
execution-time failure requiring operator sign-in. Machine-wide auth is unchanged.

This remains an **operator preview**, not a customer installer: private Cloud
access, Docker/WSL installation and account sign-in remain manual. Approval below
is driven by the existing acceptance browser automation against a fresh disposable
local Cloud, not a customer authority. General projects and translation are unsupported.

## Approval and bounded work

Before the client starts, the script drives the existing Console review, confirms
each control and explicitly approves a fresh **Compiler documentation** policy:

| Action | Permitted path | Required role |
| --- | --- | --- |
| Create | `examples/compile_repository_policy.py` | `repository-maintainer` |
| Modify | `README.md` | `security-reviewer` |

The provider recognizes only the documented four-clause policy; this does not
demonstrate general natural-language onboarding. Only candidate controls come
from the Guard-owned fixture. Unchanged Cloud and Ledger perform validation,
review, approval, compilation and publication through their supported APIs.
The returned publication's exact scope is checked before exposing the writer.
Organization, runtime, actor, publication and hash identities are retained in
the evidence. Credentials remain in private operator files and the writer volume.

Import uses `git -c core.autocrlf=false archive` and checks every file against its
pinned Git blob. No untracked files, Git metadata or credentials are imported.
The operator provisions empty `examples/` before protection; this is not runtime
directory creation support. The agent receives read-only `/source`, writable
`/scratch`, and the same restricted model relay and writer connector as #60.
The separate writer retains its installed trusted dependencies and never runs
project code, shell commands or tests.

Codex receives the ordinary README/example task, scope and testing conventions;
it is not given a completed patch or scripted MCP sequence. It can prepare and
check drafts in scratch. An ambiguous/lost write response stops the procedure
for reconciliation; the launcher never automatically retries a mutation. A failed
attempt's output directory cannot be reused as a fresh run.

The script runs a separate short out-of-scope request, verifies original and
final file hashes, retrieves exact SDK packages/reports, checks existing Activity
links, exports the patch and applies it to a second disposable base copy.
All tests and example execution occur in unprivileged containers with scratch
output. The writer's Compiler import stays in `site-packages`; repository tests
use `/source/src/compiler`. Public-package examples run with `python -I`.

## Review the result

The output directory contains `compiler-documentation.patch`,
`patch-verification.json`, `timing.json`, captured CLI events, existing test JUnit
reports, exact source hashes, preserved decision/report records and Activity
captures. Verify it without invoking mutations:

```powershell
python examples/codex_contained/verify_compiler_trial.py --output "acceptance-output/$TrialName"
```

The patch embeds its exact base commit and full blob indices, including the new
file. A later **Compiler-owned** task must inspect it and check the actual base
before applying it. This trial applies only to a second disposable copy. It does
not silently overwrite a user's checkout or open a sibling implementation PR.
The example policy illustrates compilation; it is separate from the narrow
authority governing these two task writes.

The retained Compiler release checker still asserts obsolete candidate README
wording. Its diagnostic failure belongs in the Compiler review handoff; it is not
fixed by widening this task's approved paths. Full release validation would also
build packages and is deliberately outside this trial.

## Cleanup

Retain and secret-scan the selected evidence before cleanup. The repository's
`retain_compiler_trial.py` curates the task cohort; preparation and boundary records
are retained separately in the #63 acceptance bundle. Never copy operator-private
or writer-private files into durable evidence. After retention:

```powershell
python examples/codex_contained/run.py cleanup --name $TrialName --output "acceptance-output/$TrialName/client"
python examples/codex_contained/run_cloud.py cleanup --name $TrialName --output "acceptance-output/$TrialName/cloud"
Remove-Item -LiteralPath "acceptance-output/$TrialName/cloud/operator-private.json","acceptance-output/$TrialName/cloud/writer-private.json"
```

Cleanup checks exact attempt resource names and ownership labels. It removes only
that trial's containers, volumes and network. It leaves prepared images, logs and
the isolated environment for inspection; it never prunes Docker or changes sibling
repositories. Remove your explicitly named preparation directory only after retention.

No merge, package rebuild/publication, image push, deployment or activation.
Cached-session revocation semantics are unchanged. Cloud #141/#121 remain rollout
blockers; arbitrary build systems, new filesystem actions, desktop-app support,
macOS and remote TLS are not established by this trial.

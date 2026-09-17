# Bring the Compiler project into a contained Codex session

This is one bounded repository trial. It imports tracked files at Compiler commit
`f817a1bca65806c9ee33ccc74c2238952ebf8f01`, approves the two task actions, lets
Codex choose its edits, runs the existing tests/examples and exports a reviewable
patch. The original checkout is only read through Git; it is never mounted in
the client or edited. Cloud is read-only at
`93bf80f30d170a6be32622a34dbbdf0d85b8ccc6`.

## Explicit prerequisites

- Git, Python and Docker Desktop's running Linux/WSL2 engine.
- Existing supported Codex login at `$env:USERPROFILE/.codex/auth.json`.
- The three accepted local images from #58/#60. The launcher checks their exact
  digests, not just tags. No image was pushed; a first-time machine without those
  images needs the earlier local setup and validation of any changed inputs.
- An operator Python environment containing `requests==2.34.2`,
  `playwright==1.63.0` and its Chromium browser. These are host-side Console tools,
  never mounted into the client. A new environment can be prepared with:

```powershell
python -m venv acceptance-output/operator61
& acceptance-output/operator61/Scripts/python.exe -m pip install requests==2.34.2 playwright==1.63.0
& acceptance-output/operator61/Scripts/python.exe -m playwright install chromium
```

Record this preparation separately when it is needed; the reported warm trial
used an existing environment. The agent image already contains pytest 9.0.2 and
jsonschema, satisfying the Compiler's ordinary test dependencies. No project
dependency install, package rebuild or additional agent network access is needed.
The pinned Compiler repository may be checked out at another commit: only its
named Git objects are read. It must contain the exact pinned commit.

## Launch and approval

From this Guard branch, one PowerShell command runs the documented sequence:

```powershell
$TrialName = 'wf54-57-61-' + (Get-Date -Format 'yyyyMMddHHmmss')
.\examples\codex_contained\Start-CompilerTrial.ps1 `
  -CompilerRepository C:\GitHub\cricore-contract-compiler `
  -CloudCheckout C:\GitHub\Waveframe-Guard-59-cloud `
  -OperatorPython C:\GitHub\Waveframe-Guard-57\acceptance-output\operator-env\Scripts\python.exe `
  -Name $TrialName
```

Adjust the operator environment path to the explicit prerequisite you prepared.
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
`retain_compiler_trial.py` records the successful cohort and its initial failed
import attempt; its CLI takes explicit input/output directories and does not
overwrite prior evidence. After retention:

```powershell
python examples/codex_contained/run.py cleanup --name $TrialName --output "acceptance-output/$TrialName/client"
python examples/codex_contained/run_cloud.py cleanup --name $TrialName --output "acceptance-output/$TrialName/cloud"
Remove-Item -LiteralPath "acceptance-output/$TrialName/cloud/operator-private.json","acceptance-output/$TrialName/cloud/writer-private.json"
```

No merge, package rebuild/publication, image push, deployment or activation.
Cached-session revocation semantics are unchanged. Cloud #141/#121 remain rollout
blockers; arbitrary build systems, new filesystem actions, desktop-app support,
macOS and remote TLS are not established by this trial.

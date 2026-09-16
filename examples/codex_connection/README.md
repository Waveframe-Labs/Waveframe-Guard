# Codex CLI connection experiment (#54)

This is a runnable **local proof, not a supported workspace-enforcement plugin**.
The native Windows CLI successfully used released Guard create/modify APIs and
ran a doctest while ordinary source writes were denied. The full product gate is
**not met**: the MCP writer retains the operator's broad rights and its process
memory is readable from the tested restricted environment. See the
[measured results and exact boundary](../../docs/acceptance/codex-54/RESULTS.md).

Only `writer.py` is the adapter. It exposes `connection_status` and
`repository_write` over stdio MCP. The other files prepare disposable data,
launch the real installed CLI, inject transport faults, or collect diagnostics.
There is no custom agent loop, hook-based command authorization, compiler,
policy evaluator, Cloud resolver imitation, or generic privileged shell.

## Copyable Windows setup

Run from this checkout in an operator PowerShell terminal. Prerequisites are
Python, the authenticated **Codex CLI 0.154.0**, and its already initialized
`elevated` Windows sandbox. This proof reused that sandbox's local accounts;
it did not measure a fresh administrator-approved sandbox installation.
Do not use the writer with real credentials or a real customer workspace.

```powershell
$proof = Join-Path $env:LOCALAPPDATA ('Waveframe/codex54-' + (Get-Date -Format yyyyMMdd-HHmmss))
$venv = Join-Path $proof 'venv'
python -m venv $venv
$python = Join-Path $venv 'Scripts/python.exe'
& $python -m pip install -r examples/codex_connection/requirements.txt
$codexExe = Join-Path (npm root -g) '@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe'
& $codexExe --version
& $python examples/codex_connection/prepare.py (Join-Path $proof 'run') --codex $codexExe --model gpt-6-astra
$connection = Join-Path $proof 'run/connection.json'
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/allowed.txt --name allowed
```

Use the model available in your installed configuration if it differs; that is
a new configuration to verify. `prepare.py` refuses to overwrite an existing
run directory. The writer, fixture, configuration, and Python imports stay
outside the explicitly writable scratch directory. `-I` and an operator-owned
working directory keep workspace Python imports out of the writer.

The launch uses `codex exec --ignore-user-config --ignore-rules`, reusing the
existing login without copying it. All configuration is per invocation; the
normal global configuration is not overwritten. Shell approvals remain
`never`. Only the two MCP tools receive explicit `approval_mode="approve"`.
`auto` did **not** authorize these calls in the measured CLI.

No hooks are installed or trusted. Other MCP servers, plugins, apps, browsers,
computer use, and subagents are excluded by the invocation. The experimental
`skip_host_skill_discovery` flag emits a warning; it is not an enforcement
mechanism. Complete arguments are saved in each capture's `argv.json`.

## Real-chat walkthrough

The first prompt says, in ordinary language: read the project, show the loaded
policy, fix the README's incorrect addition example, create a note, and run
Python doctest. You can put another prompt in a text file and pass it to
`launch.py`. This calls the real CLI once and records its actual tools and
output. The interactive Codex TUI and desktop application were **not tested**.
The interactive shell-input probe is a separate test of an enabled CLI tool.

This uses the **unchanged synthetic approval fixture**
`tests/fixtures/action_policy_release_v4/mixed`, not fresh customer approval.
The applied publication is `repository-mixed@3.0.0`, catalog 3. Its operator-fixed
identities are:

| Operation | Runtime identity | Role | Allowed path |
| --- | --- | --- | --- |
| create | `codex-54-create` | `repository-maintainer` | `generated/new.md` |
| modify | `codex-54-modify` | `security-reviewer` | `README.md` |

Two Guard runtimes are necessary for this fixture's two roles. The model cannot
choose the role, identity, publication, repository root, or callback. A request
contains exactly `action`, `path`, and `content`; requests outside those fields
are rejected. This is not a single-role customer identity integration.

Status displays the actually loaded publication ID, contract/bundle hashes,
operation identities, and observation time. `responding` means that call got a
response. `workspace_enforcement=not_established` prevents confusing it with
the stronger, unproven promise. Each mutation returns its saved run ID and
existing SDK attestation. Evidence remains local; nothing is uploaded to Cloud.

## Reproduce the negative cases

Use the same connection after the allowed walkthrough:

```powershell
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/denied.txt --name denied
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/bypass.txt --name bypass
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/bypass.txt --name disconnected --disconnected
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/fault.txt --name malformed --fault malformed
& $python examples/codex_connection/launch.py $connection examples/codex_connection/prompts/fault.txt --name timeout --fault timeout
```

The probe is intentionally capable of attempting writes and token reuse:
run it **inside the sandbox against disposable targets only**. It never reads
real credentials; its memory-read target is a fixed, synthetic marker. A model
may refuse that diagnostic, as one measured run did. A refused request is not a
passed OS test. The retained native-token follow-up records the exact
`codex sandbox -P waveframe ...` command used to resolve the token-level result.

For a live stop, use `prompts/live-stop.txt` and stop only the writer PID returned
by status while the CLI performs its 20-second pause. Verify that process's
command line identifies this disposable run before stopping it. The retained
`operator-stop.json` records the measured stop. No mutation was in flight.

`launch.py` independently saves before/after source bytes and hashes, control
hashes, CLI events, stderr, arguments, prompt, and elapsed time. It does not retry
mutations. On a lost response, inspect bytes and saved attestations with the
operator; do not assume a failed response means no write or that disconnect
rolls a write back. A Guard create collision retains `mutation_status=unknown`
even when its operation record says `created=false`, `bytes_written=0`.

## Checks and bounded alternative

```powershell
& $python -m pip install pytest
& $python -I -m pytest --noconftest --import-mode=importlib tests/test_codex_connection.py -q
& $python -I examples/codex_connection/verify_evidence.py docs/acceptance/codex-54/evidence
```

The first command tests the adapter against installed wheels without the repo's
`conftest.py` replacing imports. Verification reloads SDK artifacts and replays
logical decisions; it does not recreate historical filesystem state.

If Docker Desktop's Linux engine is available, the bounded comparison is:

```powershell
& $python examples/codex_connection/compare_container.py (Join-Path $proof 'container-comparison')
```

This builds one local image and creates a uniquely named, labeled disposable
volume, listed in `resources.json`. It runs Guard in a container with a writable
volume, then a separate container with the same volume read-only after the
writer exits. Both have read-only root filesystems, no capabilities, no new
privileges, no network, separate PID namespaces, and no Docker socket. Matching
UID 10001 is needed to read the SDK's mode-0600 creations; read-only mounts
enforce the write distinction. It is **Linux/WSL2**, with no Codex model in the
container test. See the report for the unproven client/transport handoff.

Disposable run directories, captured evidence, Docker image, and named volumes
are retained for inspection. No release tag, package version, global Codex
configuration, or sibling repository is changed.

# Issue #54 — contained real-Codex experiment

**Technical verdict: pass for the declared Linux/WSL2 arrangement. Usability
verdict: pass for this fixture-sized edit/test cycle; broader repository onboarding
remains unproven.** This is the second, stacked proof after draft #55 at
`2352ab222fded209287dc1074dd63f024e1cf429`. It preserves #55, all 119 original
evidence objects, historical failed CI and the previously retained mount proof.
It does not change SDK behavior, package versions or published artifacts.

[Copyable PowerShell setup and walkthrough](../../../examples/codex_contained/README.md)
run the entire real Codex CLI/tool host inside the agent container. A separate
writer performs released Guard operations. Both run concurrently through MCP
stdio relayed over a private Unix socket. There is no custom agent loop.

## Tested platform and provenance

- Windows host: the existing Docker Desktop Linux/WSL2 installation; Docker Engine
  29.5.3, kernel `6.6.114.1-microsoft-standard-WSL2`. This is **not native Windows
  enforcement**, desktop-app acceptance or a new #51 bind-mount run.
- Real native Codex CLI **0.154.0**, `x86_64-unknown-linux-musl`, model
  `gpt-6-astra`. Binary SHA-256:
  `3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022`.
- Final local image:
  `sha256:2af4a2af92444e349c6755ddaf1d4e92fdbd53da8cc2fe51b6a71acbc83bcefb`.
  Pinned Python 3.14.7 base:
  `sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6`.
- Public wheels: Guard **0.19.0**, Ledger **0.9.0**, Compiler **0.5.0**, MCP
  **2.2.0**. Independently downloaded archives matched the image's pip-report
  hashes; **278 installed files**, including metadata and packaged resources,
  matched their wheel members. The generated RECORD files were excluded from
  byte comparison. No verifier or package was edited.

Exact [image/container configuration](evidence/final/setup.json),
[runtime/policy input hashes](evidence/final/image-inputs.json),
[client provenance](evidence/final/client-provenance.json),
[pip archive report](evidence/final/pip-report.json),
[installed-byte verification](evidence/final/installed-bytes.json),
[OS package inventory](evidence/final/os-packages.txt), and
[Python inventory](evidence/final/python-packages.txt) are retained.
The image was built during investigation over the recorded base worktree with
new prototype files; its source status and per-file fingerprints are explicit.
Every runtime/protection/fixture image input was compared with the final source
bytes. This is not a claim that an uncommitted image build was a clean release
build. New builds must record their own resolved packages and image identity.

## Real-client results

Every phase has actual CLI arguments, prompt, event output, original Codex
rollout, elapsed observations and an independent operator source snapshot. The
verifier recomputes captured byte hashes and differences; it does not trust the
agent's narrative. Exact Docker controls are compared before/after, ignoring only
the ordering of the inspect mount array. All mount fields and duplicates remain
checked. Writer stop/restart and fault selection are explicitly operator actions.

| Phase | Observed result | Source changes | Evidence |
| --- | --- | --- | --- |
| Allowed chat | Loaded fixture policy; create and modify succeeded; doctest passed | README.md, generated/new.md | [capture](evidence/final/allowed/inspection.json), [chat](evidence/final/allowed/events.jsonl) |
| Denied/action separation/collision | Four policy denials, one collision, one invalid selector injection | None | [chat](evidence/final/denied/events.jsonl) |
| Alternate writes | Native patch failed; shell, Python, child and live interactive writes denied | None | [rollout](evidence/final/bypass/rollout.jsonl), [inspection](evidence/final/bypass/inspection.json) |
| Missing socket | Connection unavailable; direct and interactive writes still denied | None | [capture](evidence/final/missing/inspection.json) |
| Live writer stop | First status responded; operator stopped writer; next status reported Transport closed | None | [stop trigger](evidence/final/live-stop/operator-stop.json), [chat](evidence/final/live-stop/events.jsonl) |
| MCP disabled, hooks disabled | No writer tool available; same direct-write denials | None | [capture](evidence/final/disabled/inspection.json) |
| Malformed response | Corrected peer sent malformed wire bytes; client tool failed; direct writes stayed denied | None | [raw frames](evidence/final/raw-transport.json), [chat](evidence/final/malformed/events.jsonl) |
| Timeout | tools/call timed out after 3 seconds; no mutation or retry | None | [chat](evidence/final/timeout/events.jsonl) |
| Response lost after mutation | Exactly one requested modification; delivery failed; actual SDK success retained | Authorized README marker only | [chat](evidence/final/lost/events.jsonl), [reconciliation](evidence/final/verification.json) |

The actually loaded publication was `release-example-mixed`, authority
`repository-mixed@3.0.0`. The server fixed create to `codex-54-create` /
`repository-maintainer`, and modify to `codex-54-modify` / `security-reviewer`.
Only create `generated/new.md` and modify `README.md` are fixture-approved. Raw
socket requests cannot override identity, authority or root.

The eight saved SDK attestations comprise **three successful operations, four
not-run denials and one failed collision**. The collision truthfully retains
`mutation_status=unknown`, failed creation and zero bytes written; independent
inspection shows the existing file unchanged. Invalid request-shape/selector
injections are adapter rejections, not invented SDK decisions.

For the lost response, Codex called repository_write once, received Transport
closed, observed the authorized 66-byte README and passed its doctest. It reported
the delivery outcome as unknown and requested operator reconciliation. The
writer had already saved successful run
`guard_run_04aae6fa696261c845cee137`, then exited before replying. The retained
[transport outcomes](evidence/final/guard/transport-outcomes.jsonl) contain exactly
one lost-mode operation. There was no automatic mutation replay or invented
rollback. The adapter has no retry loop; this does not add an at-most-once API
across arbitrary future model calls or reconnects.

The [independent verification](evidence/final/verification.json) reloads each
saved run with released Guard and logically replays decisions on temporary
copies. Original evidence remains unchanged. This checks local evidence; no
Cloud evidence delivery or preservation is claimed.

## Enforcement and credential boundary

Both agent and writer use network mode `none`, separate PID/mount namespaces,
UID/GID 10001, zero effective and bounding capabilities, no-new-privileges,
Docker default seccomp and read-only image filesystems. The agent has only
loopback and no external route. Its source and socket volumes are read-only;
scratch/cache/test output is separately writable. The writer alone has source
and evidence write mounts, plus its necessary socket and temporary state.
The shared numeric UID permits reading SDK-created mode-0600 files and does not
make the writer's PID namespace or private secret volume visible.

Actual source-write syscalls returned **EROFS (30)**; immutable code/configuration
access returned **EACCES (13)**. chmod/chown/socket replacement attempts did not
change controls or protected bytes. New user/mount namespace creation returned
EPERM; the mount command refused remount. The native patch tool reports only
"Failed to write file", so that message is not presented as an errno capture.
It ran with Codex's own sandbox/approval policy bypassed inside Docker; the
independent syscall and mount observations establish the OS boundary.

Live interactive input was exercised through the actual client tools: the
process printed READY, then `write_stdin` sent `blocked` plus newline to the same
session, followed by an EROFS write failure. Raw rollouts retain the real
`tools.exec_command`, `tools.write_stdin` and patch calls, including the client's
JavaScript tool-orchestration wrapper. That wrapper is inside the contained
Codex host. No model refusal is counted as a kernel denial.

The [live separation probe](evidence/final/live-separation.json) is clearly labeled
a deterministic supplement. While a real MCP writer process held the synthetic
credential, the agent was given its VM PID and exact marker address. Its
`process_vm_readv` returned **ESRCH (3)**; writer `/proc` memory, environment and
root paths were absent in the agent namespace. The PID-namespace identities
differed. The private credential/evidence volumes were absent from agent mounts;
an invented credential-reading MCP tool failed, and a direct identity-injection
request was rejected. Actual synthetic credential values and model-login tokens
were checked against the capture set and were not present.

Direct Docker-control/network attempts returned **ENETUNREACH (101)**, missing
socket paths or connection refusal. The narrow Squid endpoint rejected attempted
host/control and unapproved-domain CONNECT requests. Model traffic traversed its
separate Unix socket with only three approved HTTPS destinations and private-IP
rejection. The proxy has no source, evidence or secret mounts, no published port
and no Docker management interface.

Hooks, apps/plugins, browser/computer tools, web search and delegated-agent tools
were disabled. These excluded tools are not counted as tested passes. Arbitrary
ordinary child processes remain inside the same Docker boundary. Missing or
untrusted hooks cannot enforce this arrangement because hooks are disabled.
No anti-admin, kernel-vulnerability or all-software-defects guarantee is made.
Operator Docker access and intentional reconfiguration are outside the agent
scope. Authorized code may still be incorrect or unsafe.

## Usability, friction and retained unsuccessful attempts

The [measurements](evidence/measurement.json) distinguish prerequisites from
execution. Docker Desktop, host Python/Git, an existing Codex login and the pinned
Python base image were already available. Fresh Docker installation, base-image
download and fresh account login were **not timed**.

- Initial proof-image build with the cached base took about **42 seconds**;
  corrected cached builds took about two seconds. Full package/image identities
  are recorded, not inferred from tag names.
- Cached final setup, including recorded capability checks, took **3.56 seconds**.
  In the final automated chat the create completed at **17.42 seconds**, modify
  at **23.27 seconds**, and doctest at **28.88 seconds** after CLI launch.
- The actual PowerShell-to-interactive-TUI walkthrough required **one trust
  confirmation** and completed its first useful governed edit/test turn in
  **67.83 seconds from setup-directory creation**. The TUI's first turn took
  **35.35 seconds after the session began**. A second ordinary conversation turn
  checked live policy/identities and saved test output without changing source.
  [TUI rollout](evidence/interactive/rollout.jsonl),
  [independent inspection](evidence/interactive/ui-inspection.json).
- The two-document doctest passes with output in `/scratch/output`. This is a
  practical small documentation cycle, not proof of arbitrary dependency
  installation, in-source builds or a large repository's test suite. Model
  latency, fresh login and broader build requirements remain usability variables.

The investigation retained its friction rather than replacing unsuccessful
observations. The operator volume initializer initially tried chmod after
transferring ownership; Docker's copied WORKDIR ownership also required taking
ownership before initialization. The corrected short initializer uses only
CHOWN before the unprivileged services start. No running service gained a
capability. The process probe initially matched the relay command line as well
as its Python child; selecting the actual executable fixed the observer.

Most significantly, MCP 2.2 redirects handler fd 1 to stderr. The first malformed
injector therefore produced a disconnect, **not a malformed wire response**.
That [preliminary raw capture](evidence/preliminary/raw-transport-first.json),
[original server source](evidence/preliminary/first-server.py.txt) and complete
[preliminary chat captures](evidence/preliminary/malformed/events.jsonl) remain.
The corrected injector duplicates the transport descriptor before MCP claims
stdio. Its raw peer observed `not-json` on the actual wire, and the complete
nine-phase real-client sequence was repeated on the corrected image.

Codex 0.154.0's TUI does not accept exec's `--ignore-user-config` or
`--ignore-rules` flags. The TUI instead uses only the disposable CODEX_HOME and
explicit settings; the original configuration remains untouched. An experimental
skip-host-skill-discovery warning and rejected optional `ab.chatgpt.com` traffic
were visible but did not prevent the tested edit/test cycle. No trust prompt,
warning, excluded path or preliminary disconnect is relabeled as an OS denial.

The host's default Python had an older Ledger lacking the required publication
module: its exploratory focused run retained 17 passes and 9 setup errors.
The isolated released-package environment passed all **26** focused adapter,
launch-contract and evidence checks. Both outcomes are retained in
[the host check](evidence/host-environment-check.txt) and
[the released-environment check](evidence/released-environment-check.txt).
The global Python environment was not changed.

All experiment containers and volumes, including the copied login caches and
synthetic credentials, were removed through the matching-label cleanup path.
[Cleanup observations](evidence/resource-cleanup.json) retain the exact names
and commands. The local proof image remains cached; Docker Desktop was stopped
again after confirming no containers remained running, restoring its initial state.

## Handoff

Keep #55 and this follow-up draft. Required final-head CI results and artifact
links are recorded in the new PR. The existing mount-equivalence gate remains
unchanged: no runtime, root tests or original evidence was modified.

The bounded technical/usability result supports review of a next integration
step. Cloud #122 may design guided connection and loaded-policy provenance using
existing review, fresh approval, publication and Activity surfaces. A real
Guard.cloud connection would need separately authorized activation/identities,
writer-held credentials, scoped network access and real evidence-preservation
tests. Fixture approval here supplies none of those. Cloud #143's completed
package milestone remains complete; public-package/image/Console acceptance and
any rollout remain separate. No sibling implementation, package publication or
deployment was performed.

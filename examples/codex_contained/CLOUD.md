# Contained Codex with disposable Cloud — issues #57 / #59

This is a Guard-owned integration proof using released Guard 0.19.0, Ledger
0.9.0 and Compiler 0.5.0. Cloud is an unchanged, isolated integration dependency
at `93bf80f30d170a6be32622a34dbbdf0d85b8ccc6`. The prior #55/#56/#58 source and
archived evidence remain part of this stack. No package or image is published.

For the focused #59 handoff use [CLOUD-REVALIDATION.md](CLOUD-REVALIDATION.md)
and `Start-CloudRevalidation.ps1`. It reuses the accepted images and runs the
changed enrollment/history interactions. The broader #57 fault procedure below
is historical setup documentation, not a requirement to repeat that investigation.

## PowerShell setup

Prerequisites: Git, Python 3.10+, Docker Desktop's running Linux/WSL2 engine,
and an existing supported Codex login at `$env:USERPROFILE/.codex/auth.json`.
Run from the new Guard checkout. Authentication, initial Docker installation,
image/package/browser downloads and policy approval are separate from edit time.

```powershell
git -C C:\GitHub\Waveframe-Cloud worktree add --detach C:\GitHub\Cloud-57-isolated 93bf80f30d170a6be32622a34dbbdf0d85b8ccc6
.\examples\codex_contained\Start-CloudProof.ps1 -CloudCheckout C:\GitHub\Cloud-57-isolated -Name wf54-57-mine
```

Use `-NoBuild` only with locally built, independently measured images. The script
uses the existing Console to register a disposable organization, review all five
policy clauses, confirm each control, approve the current review hash and publish.
Cloud's explicitly identified `ExampleProvider` translates only this exact policy;
arbitrary policy ingestion is unproven. Runtime enrollment uses the same public
`/v1/api-keys` contract as Console, with two explicit `runtime:<id>` credentials
scoped to `authorities:read`, `audit:write`, `continuity:write`. Actor/role mapping
is operator configuration: create requires `repository-maintainer`, modify requires
`security-reviewer`. The agent cannot select a runtime, role, endpoint or authority.

The two `*-private.json` files are operator secret handoff files in ignored
`acceptance-output`. Never commit them or mount them in the agent. Only the writer
receives its configuration via stdin into its private read-only secret volume.
Console login remains operator-only. The original Codex auth file is copied only
to the disposable client scratch volume; global user configuration is unchanged.

## Boundary and observations

The complete Codex host and its children retain the #56 controls: network none,
read-only `/source`, writable `/scratch`, private process namespace, read-only
root, all capabilities dropped, no-new-privileges, no Docker/host mounts. Hooks,
apps, plugins, delegated agents and browser tools stay disabled. Tests run in the
agent with byproducts in scratch. Model HTTPS still uses the separate restricted
Squid socket relay.

The writer also has network none. Its loopback port 18081 relays to one
operator-selected private `/cloud-transport/cloud.sock`; the socket peer is the
disposable Cloud service, never an arbitrary forwarding proxy. The agent has no
transport mount. Cloud has its own bridge and host-loopback Console port; its
pinned source is mounted read-only. This is local plaintext socket/loopback
transport inside Docker Desktop, **not a remote TLS validation claim**. Public
SDK clients reject redirects. A different Cloud endpoint requires a separately
reviewed transport implementation; there is no configurable model egress escape.

Each MCP connection creates a writer session with two `Guard.cloud` instances.
Their actually loaded publication IDs and contract/bundle hashes must match
operator selection. Registration failure prevents adapter activation. Status
reports authority version, load/observation timestamps, runtime and actor bindings,
and last successful preservation in that session. It does not probe current Cloud
availability. Authority is cached for the session; startup is the online validation
boundary. Already loaded authority does not gain immediate revocation or outage
enforcement. Cloud preservation and runtime reporting are observational SDK calls.

Requests contain exactly `action`, canonical relative `path`, UTF-8 `content`
(at most 64 KiB). Fixed writer callbacks call `create_bytes` or `write_bytes`;
they never execute workspace code. A filesystem lock serializes requests across
MCP sessions. This is not an exactly-once service: neither locks nor journal IDs
prevent an operator/model from submitting a new request later.

Decision preservation, terminal report submission, SDK local attestation, and
independent observed bytes are separate evidence. In particular, upload failure
does not prove zero writes. Unknown, empty successful creation, collision, partial
failure and absent report must remain distinct.

## Fault acceptance and reconciliation

Use `run.py chat` and the existing prompts for direct patch/shell/child/interactive
writes, `--missing`, `--disconnected`, and `--stop-after-status`. Select Cloud writer
faults with `run_cloud.py writer --mode malformed|timeout|lost`. Never use the old
`run.py writer` command in connected acceptance: that starts the fixture writer.
Operator Cloud faults use `run_cloud.py fault --mode unavailable|preservation|report|redirect`;
`--mode normal` restores the disposable wrapper. No fault interface is exposed to
the client or Cloud HTTP callers.

```powershell
python examples/codex_contained/separation.py --cloud --name wf54-57-mine --output acceptance-output/wf54-57-mine/client/separation.json
python examples/codex_contained/raw_transport.py --cloud --name wf54-57-mine --output acceptance-output/wf54-57-mine/client/raw-transport.json
# Run only after real-client phases: this intentionally supersedes and revokes the disposable authority.
& acceptance-output/wf54-57-mine/operator/Scripts/python examples/codex_contained/cloud_fault_acceptance.py --name wf54-57-mine --output acceptance-output/wf54-57-mine/cloud
```

After a lost write response: stop new mutations, retain the rollout and
`/evidence/requests.jsonl`, identify the single request and terminal local run,
independently read protected bytes, retrieve `/v1/package/<package_id>` and
`/v1/audit-events?event_id=<run_id>`, compare the exact submitted decision package
and separate report. `reconcile_cloud.py` performs only reads for this acceptance.
If any record is absent or contradictory, retain uncertainty; do not automatically
execute again, invent rollback or claim exactly-once delivery.

Capture using both `run.py capture` and `run_cloud.py capture`. The latter measures
all `/opt` files in all three images, including `/opt/proof/original_writer.py`,
and retains sanitized native HTTP. Independently run `verify_installed.py` to
authenticate selected public wheel hashes and installed bytes. Replay SDK stores
on temporary copies only; logical replay does not perform repository mutations.

## Scope and handoff

See the [acceptance report](../../docs/acceptance/codex-cloud-57/RESULTS.md) for
executed checks, failures, identities and durable evidence. The broader repository,
native Windows writer protection, desktop app, remote TLS, and customer activation
are unproven. Cloud #141/#121 remain separate rollout blockers.

Cloud #122 needs these existing connection fields: organization, selected authority
reference/version, publication ID, contract/bundle hashes, loaded-at observation,
runtime/environment, separate scoped create/modify actor-role bindings, writer
endpoint/transport scope, repository/evidence roots, per-session last successful
preservation, decision package/run/request IDs, terminal-report status, and explicit
unknown/reconciliation state. No Console redesign or heartbeat API is introduced.

After captures and comparisons, remove only the labeled disposable resources:

```powershell
python examples/codex_contained/run.py cleanup --name wf54-57-mine --output acceptance-output/wf54-57-mine/client
python examples/codex_contained/run_cloud.py cleanup --name wf54-57-mine --output acceptance-output/wf54-57-mine/cloud
Remove-Item -LiteralPath acceptance-output/wf54-57-mine/cloud/operator-private.json,acceptance-output/wf54-57-mine/cloud/writer-private.json
```

Preserve sanitized evidence first. The local images remain cached.

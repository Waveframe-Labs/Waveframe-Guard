<p align="center">
  <img src="https://raw.githubusercontent.com/Waveframe-Labs/.github/main/assets/branding/canon_wf_logo_extended.png" width="700">
</p>

# Waveframe Guard

Stop unsafe AI and automated actions **before they execute**.

Waveframe Guard is an execution-boundary SDK. It wraps sensitive actions, resolves compiled authority, evaluates through CRI-CORE, and only runs the action when the outcome is allowed.

Current release: `0.13.0`.

```text
Guard does not generate actions.
Guard does not author governance.
Guard does not replace Cloud.
Guard decides whether this action may run now.
```

## Install

```powershell
pip install waveframe-guard
```

No Ollama installation or Waveframe repository checkout is required. Keep the
customer's existing model, agent framework, and tool functions; Guard wraps the
tool that can cause a real-world change.

## Hosted quickstart

Configure the runtime credential created in Waveframe Console:

```powershell
$env:WAVEFRAME_CLOUD_URL="https://cloud.waveframelabs.com"
$env:WAVEFRAME_CLOUD_ORGANIZATION_ID="acme"
$env:WAVEFRAME_CLOUD_API_KEY="<runtime credential>"
```

Then wrap an existing agent tool:

```python
from waveframe_guard import Guard

guard = Guard.cloud(
    authority="repository-change-policy@1.0.0",
    environment="production",
    actor_identity={
        "id": "release-agent",
        "type": "agent",
        "role": "repository-maintainer",
    },
)

@guard.tool(
    action="write_file",
    target="path",
    include_arguments=("mode",),
    agent={
        "framework": "langgraph",       # or custom, crewai, etc.
        "model_provider": "openai",     # or anthropic, ollama, etc.
        "model": "gpt-5",
    },
)
def write_file(path: str, content: str, mode: str = "replace"):
    return your_existing_write_file(path, content, mode=mode)
```

The three choices are intentionally independent:

- `actor_identity` identifies the agent or human attempting the action.
- `authority` selects the explicit, versioned policy Guard will enforce.
- `agent` records optional framework and model metadata for Console and audit evidence.

`Guard.cloud(...)` fetches the published compiled authority from Cloud, verifies
its identity and hash, and fails closed if it cannot obtain a trustworthy
contract. It uses `runtime_id=` when provided and otherwise uses
`actor_identity["id"]` as the runtime identity. Guard registers that runtime,
sends its first heartbeat, and exposes the observational result as
`guard.runtime_connection`. Guard still evaluates locally before calling the
wrapped function. Afterward, it preserves the decision and attests whether the
wrapped callback executed, failed, or did not run.

Long-running processes may call `guard.heartbeat()` from their existing health
loop. Cloud reporting failures are returned as structured status and never
change Guard's local decision or cause an allowed callback to run twice.

Tool arguments are excluded from preserved evidence by default. Add only safe,
decision-relevant names to `include_arguments`; prompts, tokens, file contents,
and other sensitive values should remain excluded.

## Works with existing agents

`@guard.tool(...)` is framework-neutral. It wraps an ordinary Python callable,
so the model may be hosted or local and the orchestration layer may be a custom
agent, LangGraph, CrewAI, an OpenAI tool loop, or another framework. Guard does
not generate the tool call and does not require the model to emit Guard-specific
JSON.

The wrapper derives a normalized proposal from the real function call, asks
Guard to evaluate it against the selected authority, and invokes the original
function only when admissible. A blocked call never reaches the original
function.

## Local development path

For offline development, a local authority registry is still supported:

```python
from waveframe_guard import Guard

guard = Guard.local(
    workspace=".guard-local",
    authority="finance-policy@1.0.0",
    actor_identity={"id": "agent-1", "type": "agent", "role": "analyst"},
)

@guard.tool(action="wire_transfer", target="account_id")
def wire_transfer(account_id, amount):
    return perform_transfer(account_id, amount)
```

`Guard.local(authority=...)` loads a verified Ledger `authority_bundle.v1` from
the local authority registry. Direct `contract=...`, `authorities={...}`, and
`authority_loader=...` inputs remain available for advanced integrations and
compatibility.

## What Guard owns

Guard owns the developer-side enforcement boundary:

- local SDK integration
- compiled authority resolution
- normalized execution request enforcement
- local allow/block/escalate outcomes
- continuation windows and deferred release checks
- local receipts, replay artifacts, and runtime diagnostics
- evidence spooling for later Cloud submission

Guard does **not** author governance, publish authority, host organization workflows, operate the long-term evidence system, or ship the proprietary Guard Inspector UI.

## Guard, Cloud, and Ledger

| Product | Responsibility |
| --- | --- |
| Guard | Enforce locally before execution. |
| Cloud | Store authority, evidence, receipts, replay packages, lifecycle state, and continuity records. |
| Ledger / Workspace | Author, review, activate, and publish deterministic governance authority. |
| CRI-CORE | Deterministic admissibility kernel used under the Guard boundary. |

The product flow is:

```text
Ledger publishes authority
        -> Cloud distributes authority and records evidence
        -> Guard enforces before execution
        -> Cloud stores receipts and replay history
```

Cloud can publish lifecycle metadata such as `active`, `superseded`, or `revoked`, but Cloud does not decide runtime admissibility. Guard evaluates locally against compiled authority.

## Local authority registry

For applications that resolve published contracts from a local registry, use the runtime layer:

```python
from waveframe_guard import GovernedRuntime

runtime = GovernedRuntime(
    registry_path="contracts/index.json",
    reject_revoked_authority=True,
    warn_on_superseded=True,
)

runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})
runtime.bind_contract("finance-policy@1.0.0")

result = runtime.execute(
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)
```

Runtime authority refs are explicit and versioned. Use `finance-policy@1.0.0`; unversioned IDs such as `finance-policy` are rejected because replay, audit, and cache integrity depend on deterministic authority identity.

## Cloud-connected runtime

For application code that needs Cloud authority metadata and evidence delivery, use the Cloud-connected runtime:

```python
from waveframe_guard import GuardRuntime

runtime = GuardRuntime.from_cloud(
    authority="finance-policy@1.0.0",
    api_key="...",
)

result = runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)

runtime.flush_evidence()
```

`execute(...)` still enforces locally. Cloud availability is only required when you explicitly call `flush_evidence()`.

Guard writes evidence to a durable local spool first:

```text
.waveframe_guard/evidence/
  pending/
  sent/
  failed/
```

If a flush fails, evidence is retained and can be submitted again later.

## Continuation and deferred release

Guard separates admissibility from release. An action can be admissible at T1, queued or delayed, and then blocked at T2 if its continuation lease no longer validates.

Guard emits:

- `guard_continuation_lease.v1`
- `guard_release_validation.v1`
- `release blocked` when execution was admissible earlier but a runtime dependency expired before release

Continuity signals are not Cloud decisions. Guard evaluates continuity locally; Cloud may display and preserve the evidence.

## Guard Inspector

Guard Inspector is the private operational visualization layer for SDK-emitted evaluations, receipts, replay artifacts, continuity signals, and release posture.

It consumes Guard outcomes and artifacts. It is not part of the public Guard SDK package, does not author policy, and does not own enforcement semantics.

## Repository surface

The public Guard surface includes:

- SDK facade
- local runtime
- deterministic evaluation model
- continuation governance
- replay artifacts
- deferred release model
- examples
- docs
- tests
- sample compiled contracts

Non-production or split-bound work is quarantined under `temp/`. In particular, `temp/labs/cloud_runtime/` is a lab preview for future Cloud product work, not production Guard Cloud and not required for local enforcement.

## Release discipline

Every substantive Guard change must update the release surface together:

```text
code
+ README / docs
+ CHANGELOG
+ pyproject metadata
+ version-dependent files
+ tests
+ package build
+ tag
```

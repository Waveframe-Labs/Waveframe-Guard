<p align="center">
  <img src="https://raw.githubusercontent.com/Waveframe-Labs/.github/main/assets/branding/canon_wf_logo_extended.png" width="700">
</p>

# Waveframe Guard

Stop unsafe AI and automated actions **before they execute**.

Waveframe Guard enforces governance at the execution boundary. If an action violates policy, it never runs.

Current release: `0.8.0`.

## Example

This example assumes a published contract artifact exists at `contracts/finance-policy-1.0.0.contract.json`. In your application, point `contract_path` at the contract published by your governance workflow.

```python
from pathlib import Path

from waveframe_guard import install_guard, guard

install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_path=Path("contracts") / "finance-policy-1.0.0.contract.json"
)

@guard
def transfer(amount):
    print(f"Transferred ${amount}")

transfer(100)
```

```text
Execution blocked: required role not satisfied: manager
```

## Governed Runtime

For applications that want to resolve published contracts from a registry, use `GovernedRuntime`:

```python
from waveframe_guard import GovernedRuntime

runtime = GovernedRuntime(
    registry_path="contracts/index.json",
    reject_revoked_authority=True,
    warn_on_superseded=True,
)
runtime.bind_contract("finance-policy@1.0.0")

runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    fn=transfer,
    args=(1250000,),
)
```

Runtime authority refs are explicit and versioned. Bind or pass `finance-policy@1.0.0`; unversioned contract IDs such as `finance-policy` are rejected because replay, audit, and cache integrity depend on deterministic authority identity.

By default, blocked execution raises `GovernanceError`. To observe the decision without raising, pass `raise_on_block=False`:

```python
result = runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_id="finance-policy@1.0.0",
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)

print(result.allowed)
print(result.reason)
print(result.contract_hash)
```

Allowed executions return `GovernedExecutionResult(allowed=True, reason="execution allowed", value=<function return value>, ...)`.
Blocked executions return `GovernedExecutionResult(allowed=False, reason=<policy reason>, error=<block error>, ...)`.

The registry can map contract IDs to published contract artifacts:

```json
{
  "contracts": [
    {
      "contract_id": "finance-policy",
      "contract_version": "1.0.0",
      "contract_hash": "sha256:...",
      "status": "active",
      "path": "finance-policy-1.0.0.contract.json"
    }
  ]
}
```

Runtime execution is intentionally small: registry lookup, load the published contract, install the Guard context, execute the guarded function, then allow or block.

You can also bind runtime context once and omit it from each execution:

```python
runtime = GovernedRuntime(registry_path="contracts/index.json")
runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})
runtime.bind_contract("finance-policy@1.0.0")

result = runtime.execute(
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)
```

Per-call `actor` and versioned `contract_id` values still work and override the bound context for that call.

## Admissibility Continuity

Guard can attach bounded continuity metadata to an admissibility evaluation:

```python
decision = runtime.evaluate(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_id="finance-policy@1.0.0",
    target="transfer",
    args=(1250000,),
)

print(decision.valid_until)
print(decision.revalidation_required_after)
print(decision.continuity_signals)
```

`valid_until` and `revalidation_required_after` describe when a delayed or resumed execution must be deterministically revalidated. `continuity_signals` reports structural drift such as expired admissibility windows, revoked or superseded authorities, or actor continuity breaks.

Continuity signals are not admissibility decisions. Guard evaluates continuity locally; Cloud may display continuity evidence, but Cloud does not decide admissibility.

## Deferred Release Enforcement

Guard separates admissibility from release. An execution can be admissible at T1,
queued or delayed, and then blocked at T2 if its continuation lease no longer
validates.

The first local model emits:

- `guard_continuation_lease.v1` as the continuation lease
- `guard_release_validation.v1` as the release validation
- `release blocked` when execution remained admissible at evaluation time but a
  runtime dependency expired before release

Example: a transfer is admissible, the director approval expires before release,
and Guard blocks the release before the mutation executes.

## Persistent Organizational Runtime

Guard can keep local longitudinal runtime state in `.guard-local/guard-runtime.sqlite3`.
This is a transitional local runtime layer, not Cloud.

It persists organizations, workspaces, runs, actors, compiled authority
references, continuation leases, release validations, runtime dependencies, and
release queue rows so deferred release enforcement can survive process restart.

Guard Inspector reads this local state to show active continuation leases,
expiring dependencies, blocked releases, escalation queue items, replay failures,
invalidated continuations, and runtime drift alerts.

The local runtime can export/import `guard_persistent_runtime_export.v1`
artifacts for deterministic inspection or handoff testing. For development
cleanup, run:

```powershell
python -m guard.sdk.cleanup_local --workspace .guard-local
```

## Cloud-Connected Runtime

For application code, `GuardRuntime.from_cloud(...)` is the ergonomic local-first path:

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

`execute(...)` still enforces locally. It writes governed execution evidence to a local durable spool first:

```text
.waveframe_guard/evidence/
  pending/
  sent/
  failed/
```

Cloud availability is only required when you explicitly call `flush_evidence()`. If a flush fails, evidence is retained under `failed/` and can be flushed again later. Runtime diagnostics such as authority resolution, revoked authority rejection, lineage validation failures, and admissibility evaluation lifecycle are kept in `runtime.runtime_logs` and, for `from_cloud(...)`, appended locally to `runtime-logs.jsonl`.

## Authority Lifecycle Awareness

Registry entries may include authority lifecycle metadata supplied by Cloud:

```json
{
  "authority_ref": "finance-policy@1.0.0",
  "status": "revoked"
}
```

Guard evaluates lifecycle state before admissibility or function execution. Cloud can publish lifecycle metadata, but Cloud does not decide admissibility; Guard still evaluates the compiled authority locally.

- `revoked` fails closed with `GovernanceError` when `reject_revoked_authority=True`.
- `superseded` is warning-only when `warn_on_superseded=True`, records `authority_lifecycle` metadata on the result and event, and still allows intentionally pinned versions to execute.

## Replay Admissibility

Replay systems can evaluate approval evidence without executing the governed function:

```python
from waveframe_guard import evaluate_admissibility

decision = evaluate_admissibility(contract, execution_state)
```

The returned decision includes `allowed`, `reason`, `missing_approvals`, and a governed decision trace.

For proposal-bound execution, pass a normalized proposal directly:

```python
result = runtime.execute_proposal(
    proposal,
    raise_on_block=False,
)
```

`execute_proposal` evaluates the proposal against the bound or supplied contract and returns the same `GovernedExecutionResult` shape.

Each runtime execution also emits a structured SDK-local audit event. Events are kept in memory on the runtime and attached to non-raising results:

```python
result = runtime.execute(
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)

print(result.event)
print(runtime.last_event)
print(runtime.audit_events)
```

Example event:

```python
{
    "event_type": "governed_execution",
    "execution_type": "function",
    "allowed": False,
    "authority_ref": "finance-policy@1.0.0",
    "reason": "required role not satisfied: manager",
    "error": "Execution blocked: required role not satisfied: manager",
    "contract_id": "finance-policy",
    "contract_version": "1.0.0",
    "contract_hash": "...",
    "actor": {"id": "user-1", "type": "human", "role": "intern"},
    "target": "transfer",
    "timestamp": "2026-05-12T12:00:00+00:00",
}
```

To append events locally as JSON lines:

```python
runtime = GovernedRuntime(
    registry_path="contracts/index.json",
    audit_path="runtime-audit.jsonl",
)
```

## What Waveframe Guard Does

- Intercepts function execution
- Loads published contract artifacts
- Evaluates governance rules before execution
- Blocks invalid actions deterministically
- Continues enforcement even if Cloud is unavailable

## Local vs Cloud

| Mode | Behavior |
| --- | --- |
| Local | Fast, local enforcement |
| Cloud | Policy sync, audit, and attestation |

Guard enforces locally. Cloud provides authority, audit, and verification.

## Fail Modes

| Mode | Behavior |
| --- | --- |
| `cache` (default) | Use cached policy if Cloud is unavailable |
| `closed` | Block if Cloud is unavailable and no cached policy exists |
| `open` | Allow execution if policy is unavailable and mark the decision unverified |

## Install

```bash
pip install waveframe-guard cricore-contract-compiler cricore-proposal-normalizer
```

## Live Demo

```bash
python examples/live_enforcement_demo.py
```

The demo shows:

- an intern blocked by policy
- a manager allowed by policy
- cached local enforcement during a simulated Cloud outage

## Published Contracts

Guard runtime consumes published governance authority artifacts:

```python
from pathlib import Path

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_path=Path("contracts") / "finance-policy-1.0.0.contract.json"
)
```

Inline policy dictionaries are authored and compiled before runtime. Guard loads the compiled contract artifact and enforces against it locally.

Guard also records contract metadata in runtime context for audit and telemetry:

```python
{
    "contract_id": "finance-policy",
    "contract_version": "1.0.0",
    "contract_hash": "..."
}
```

## Why This Exists

Most AI systems can suggest, warn, or log.

Waveframe Guard is the layer that can **stop execution**.

## Architecture Note

The Waveframe Guard SDK operates independently and does not require Cloud components to enforce governance locally.

The cloud directory contains experimental Cloud control plane components and is not required for SDK operation.

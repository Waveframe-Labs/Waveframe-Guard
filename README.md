# Waveframe Guard

Stop unsafe AI and automated actions **before they execute**.

Waveframe Guard enforces governance at the execution boundary. If an action violates policy, it never runs.

## Example

This example assumes a published contract artifact exists at `contracts/finance-core-0.3.1.contract.json`. In your application, point `contract_path` at the contract published by your governance workflow.

```python
from pathlib import Path

from waveframe_guard import install_guard, guard

install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_path=Path("contracts") / "finance-core-0.3.1.contract.json"
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
    registry_path="contracts/index.json"
)

runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_id="finance-policy",
    fn=transfer,
    args=(1250000,),
)
```

By default, blocked execution raises `GovernanceError`. To observe the decision without raising, pass `raise_on_block=False`:

```python
result = runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_id="finance-policy",
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
  "contracts": {
    "finance-policy": "finance-core-0.3.1.contract.json"
  }
}
```

Runtime execution is intentionally small in v1: registry lookup, load the published contract, install the Guard context, execute the guarded function, then allow or block.

You can also bind runtime context once and omit it from each execution:

```python
runtime = GovernedRuntime(registry_path="contracts/index.json")
runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})
runtime.bind_contract("finance-policy")

result = runtime.execute(
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)
```

Per-call `actor` and `contract_id` values still work and override the bound context for that call.

For proposal-bound execution, pass a normalized proposal directly:

```python
result = runtime.execute_proposal(
    proposal,
    raise_on_block=False,
)
```

`execute_proposal` evaluates the proposal against the bound or supplied contract and returns the same `GovernedExecutionResult` shape.

Each runtime execution also emits a structured audit event. Events are kept in memory on the runtime and attached to non-raising results:

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
    "reason": "required role not satisfied: manager",
    "error": "Execution blocked: required role not satisfied: manager",
    "contract_id": "finance-policy",
    "contract_version": "0.3.1",
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
    contract_path=Path("contracts") / "finance-core-0.3.1.contract.json"
)
```

Inline policy dictionaries are authored and compiled before runtime. Guard loads the compiled contract artifact and enforces against it locally.

Guard also records contract metadata in runtime context for audit and telemetry:

```python
{
    "contract_id": "finance-core",
    "contract_version": "0.3.1",
    "contract_hash": "..."
}
```

## Why This Exists

Most AI systems can suggest, warn, or log.

Waveframe Guard is the layer that can **stop execution**.

## Architecture Note

The Waveframe Guard SDK operates independently and does not require Cloud components to enforce governance locally.

The cloud directory contains experimental Cloud control plane components and is not required for SDK operation.

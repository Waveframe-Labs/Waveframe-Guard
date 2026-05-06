# Waveframe Guard

Stop unsafe AI and automated actions **before they execute**.

Waveframe Guard enforces governance at the execution boundary. If an action violates policy, it never runs.

## Example

```python
from waveframe_guard import install_guard, guard
from compiler.compile_policy import compile_policy

policy = {
    "contract_id": "finance-core",
    "contract_version": "0.3.0",
    "authority": {
        "required_roles": ["manager"]
    }
}

compiled = compile_policy(policy)

install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract=compiled
)

@guard
def transfer(amount):
    print(f"Transferred ${amount}")

transfer(100)
```

```text
Execution blocked: required role not satisfied: manager
```

## What Waveframe Guard Does

- Intercepts function execution
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
pip install waveframe-guard
```

## Live Demo

```bash
python examples/live_enforcement_demo.py
```

The demo shows:

- an intern blocked by policy
- a manager allowed by policy
- cached local enforcement during a simulated Cloud outage

## Why This Exists

Most AI systems can suggest, warn, or log.

Waveframe Guard is the layer that can **stop execution**.

## Architecture Note

The Waveframe Guard SDK operates independently and does not require Cloud components to enforce governance locally.

The cloud directory contains experimental Cloud control plane components and is not required for SDK operation.

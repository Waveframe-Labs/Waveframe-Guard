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

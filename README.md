# Waveframe Guard

Version: `v0.3.0`

Stop unsafe AI actions before they execute, in one decorator.

## Install

```bash
pip install waveframe-guard
```

## SDK Surface

```python
from waveframe_guard import install_guard, guard
from compiler.compile_policy import compile_policy

policy = {
    "contract_id": "finance-core",
    "contract_version": "0.3.0",
    "authority": {"required_roles": ["manager"]},
}
compiled = compile_policy(policy)

install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract=compiled,
    fail_mode="cache",
)

@guard
def transfer(amount):
    print(f"Transferred ${amount}")

transfer(100)
```

## Modes

Guard runs locally by default and can optionally synchronize with Waveframe Cloud.

- `fail_mode="cache"`: recommended default; enforce with last known policy if Cloud is unavailable and mark decisions unverified
- `fail_mode="closed"`: block if Cloud is unavailable and no cached policy exists
- `fail_mode="open"`: allow if Cloud is unavailable and log an unverified warning

## Live Demo

```bash
python examples/live_enforcement_demo.py
```

The demo shows:

- an intern blocked by policy
- a manager allowed by policy
- cached local enforcement during a simulated Cloud outage

## Architecture Note

The Waveframe Guard SDK operates independently and does not require the backend to enforce governance locally.

The backend directory contains experimental Cloud control plane components and is not required for SDK operation.

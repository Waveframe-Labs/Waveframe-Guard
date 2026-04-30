# Waveframe Guard

Stop unsafe AI actions before they execute — in one function call.

```python
from waveframe_guard import Guard

guard = Guard(policy="finance-core")

@guard.enforce(action_type="transfer", resource="budget")
def transfer_funds(amount):
    print(f"Executing transfer of ${amount}")

transfer_funds(25000)
```

```text
[Waveframe Guard] ✕ BLOCKED
Action: transfer -> finance/budget
Amount: $25,000
Reason: Approval required: amount > 10000
Execution stopped at the enforcement boundary
```

## Install

```bash
pip install waveframe-guard
python examples/finance_usage.py
```

## What you get

- `Guard` class
- `@guard.enforce(...)` decorator
- `shadow` mode by default
- `block` mode when you need hard-stop behavior
- clean terminal output with no JSON or debug noise

## Example violations

The bundled example shows two memorable failure paths:

- approval threshold violation
- separation of duties violation

## Modes

```python
from waveframe_guard import Guard

guard = Guard(policy="finance-core")
```

`shadow` mode never blocks execution. It prints a warning and returns the original function result.

```python
guard = Guard(policy="finance-core", mode="block")
```

`block` mode raises `GuardViolation` before mutation.

## Defaults

- actor defaults to the current OS user
- context defaults to safe fallback identities
- `finance-core` is available as a built-in local policy alias

## Development Mode

Waveframe Guard runs locally and does NOT provide:

- immutable audit records
- enforcement guarantees
- policy lifecycle management

For production enforcement, Waveframe Cloud is required.

## Typical Performance

Typical performance (local simulation):

- Kernel: ~30ms
- Full pipeline: ~35ms

# Waveframe Guard

Local enforcement SDK and simulation environment for AI governance.

Waveframe Guard lets you wrap high-risk functions with deterministic pre-execution checks. In local mode it behaves as a serious control simulation: it evaluates the action first, prints a clear decision, and either allows execution or blocks it depending on mode.

## Install

```bash
pip install waveframe-guard
```

## Run the example

```bash
python examples/finance_usage.py
```

## Quick start

```python
from waveframe_guard import Guard

guard = Guard(policy="finance-core")


@guard.enforce(action_type="transfer", resource="budget")
def transfer_funds(amount):
    print(f"Executing transfer of ${amount:,}")


transfer_funds(500)
transfer_funds(25000)
```

## Modes

- `shadow` is the default. It never blocks execution, but it prints a serious warning when a policy violation is detected.
- `block` raises `GuardViolation` before the wrapped function mutates state.

```python
from waveframe_guard import Guard

guard = Guard(policy="finance-core", mode="block")
```

## Defaults

Guard keeps local setup minimal:

- actor defaults to the current OS user
- context defaults to safe fallback identities for `responsible` and `accountable`
- `finance-core` is available as a built-in local policy alias

## Development scope

Guard uses an in-memory compiled contract for local development and examples. It does not provide immutable audit records, cryptographic attestation, or production enforcement guarantees.

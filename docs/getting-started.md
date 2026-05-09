# Getting Started with Waveframe Guard

Waveframe Guard enforces governance rules at execution time. It blocks actions that violate defined policy before they happen.

---

## Installation

```bash
pip install waveframe-guard cricore-contract-compiler cricore-proposal-normalizer
```

## Basic Usage

```python
from waveframe_guard import install_guard, guard

# 1. Install Guard context from a published contract
install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract_path="contracts/finance-core-0.1.0.contract.json"
)

# 2. Protect a function
@guard
def transfer(amount):
    print(f"Transferred ${amount}")

# 3. Execute
transfer(100)
```

## Expected Behavior

```text
Execution blocked: required role not satisfied: manager
```

## Elevating Privileges

```python
install_guard(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    contract_path="contracts/finance-core-0.1.0.contract.json"
)

transfer(100)
```

```text
Transferred $100
```

## Cloud Mode (Optional)

```python
install_guard(
    api_key="your_api_key_here",
    mode="cloud",
    fail_mode="cache"
)
```

If no cached contract is available, Cloud mode fetches a published contract before enforcement.

In cloud mode:

- Policies are fetched and cached locally
- Enforcement still happens locally
- Decisions are asynchronously logged to Waveframe Cloud

## Fail Modes

| Mode | Behavior |
| --- | --- |
| `cache` (default) | Use cached policy if Cloud unavailable |
| `open` | Allow execution if policy unavailable |
| `closed` | Block execution if policy unavailable |

## Notes

- Guard enforces locally, even if Cloud is unavailable
- Runtime enforcement uses published compiled contract artifacts
- Contract metadata is available in runtime context for audit and telemetry
- Decisions may be marked as unverified when Cloud cannot be reached
- Cloud integration provides audit, attestation, and policy management

# Getting Started with Waveframe Guard

Waveframe Guard enforces governance rules at execution time. It blocks actions that violate defined policy before they happen.

---

## Installation

```bash
pip install waveframe-guard
```

## Basic Usage

```python
from waveframe_guard import install_guard, guard
from compiler.compile_policy import compile_policy

# 1. Define a policy
policy = {
    "contract_id": "finance-core",
    "contract_version": "0.3.0",
    "authority": {
        "required_roles": ["manager"]
    }
}

compiled = compile_policy(policy)

# 2. Install Guard context
install_guard(
    actor={"id": "user-1", "type": "human", "role": "intern"},
    contract=compiled
)

# 3. Protect a function
@guard
def transfer(amount):
    print(f"Transferred ${amount}")

# 4. Execute
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
    contract=compiled
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
- Decisions may be marked as unverified when Cloud cannot be reached
- Cloud integration provides audit, attestation, and policy management

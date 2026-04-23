# Getting Started

Use Waveframe Guard when AI systems can trigger real operations and you need deterministic control before execution.

## 1. Install

```bash
pip install waveframe-guard
```

## 2. Seed local demo data

```bash
python -m backend.seed
```

This creates a demo organization, API key, and stored compiled contract named `finance-core`.

## 3. Create a client

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(
    api_key="wf_test_key_123",
    policy_id="finance-core",
    base_url="http://localhost:8000",
)
```

## 4. Evaluate an action

```python
decision = guard.execute(
    action={
        "type": "transfer",
        "amount": 5000,
        "system": "finance",
        "resource": "payroll",
    },
    context={
        "responsible": "user-alice",
        "accountable": "user-bob",
        "approved_by": "user-charlie",
    },
    actor="ai-agent-v2",
)
```

## 5. Route downstream execution

```python
if decision["allowed"]:
    print("Proceed with downstream execution")
else:
    print(decision["status"], decision["reason"])
```

## 6. Understand the result

Typical response fields:

- `allowed`: whether execution may proceed
- `status`: `allowed`, `pending`, or `blocked`
- `summary`: normalized description of the proposed action
- `reason`: post-enforcement explanation
- `risk_level`: operator-facing severity label

## 7. Inspect audit records

The backend exposes:

- `/api/logs` for live feed summaries
- `/api/log/{decision_id}` for inspector detail
- `/api/audit/{decision_id}` for full downloadable audit records

## When to use Guard

Use Waveframe Guard when:

- AI systems can perform writes, deletes, deployments, or transfers
- compiled-contract version traceability matters
- you need deterministic pre-execution governance, not passive monitoring

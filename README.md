# Waveframe Guard

Enterprise AI governance layer for deterministic execution control with policy-bound enforcement and immutable audit tracing.

Waveframe Guard sits at the execution boundary for AI-initiated actions. It builds a governance proposal, routes it through deterministic policy enforcement, and returns a clear decision before your system mutates state.

## What it does

- Resolves a stored compiled contract by `policy_id`
- Builds a proposal from actor, action, and human execution roles
- Enforces deterministic policy checks before execution
- Returns structured outcomes such as `allowed`, `pending`, or `blocked`
- Produces immutable audit records with policy-version traceability

## What it does not do

- Execute your business action
- Manage approvals or identity proofing for you
- Replace your system-of-record or workflow engine
- Make post-hoc recommendations instead of enforcement decisions

## Install

```bash
pip install waveframe-guard
```

## Quick start

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(
    api_key="wf_test_key_123",
    policy_id="finance-core",
    base_url="http://localhost:8000",
)

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

if decision["allowed"]:
    print("Execute downstream action")
else:
    print(decision["status"], decision["reason"])
```

## Decision model

Guard returns deterministic, machine-friendly responses. Typical fields include:

```json
{
  "allowed": false,
  "status": "pending",
  "summary": "AI proposed transfer on finance/payroll",
  "reason": "Approval missing or threshold exceeded",
  "risk_level": "critical"
}
```

- `allowed`: whether the action may proceed
- `status`: `allowed`, `pending`, or `blocked`
- `reason`: human-readable explanation derived after enforcement
- `risk_level`: UX-level severity classification for operators

## Governance model

Waveframe Guard is designed around deterministic execution control:

- Compiled contracts are resolved from stored policy versions, not injected inline at execution time
- Guard builds proposal structure without translating human governance semantics
- The enforcement kernel determines outcome
- Audit records preserve policy-version linkage and execution trace data

## Local development

Run the seeded backend and the example script:

```bash
python -m backend.seed
python examples/finance_usage.py
```

## Release status

This repository is being prepared for the `v0.2.0` release line.

## License

Proprietary. See [LICENSE](LICENSE).

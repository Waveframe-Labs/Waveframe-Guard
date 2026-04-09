# Waveframe Guard

**Stop bad AI actions before they execute.**

Waveframe Guard is a drop-in execution gate that decides:

- ✅ allow the action  
- ❌ block it before it happens  

No alerts. No audits. No “we’ll catch it later.”

The action either executes — or it doesn’t.

---

## The Problem

AI systems don’t fail when they think.

They fail when they act.

Most “AI governance” tools:
- log decisions
- flag risks
- generate reports

But they **don’t stop execution**.

That means:
- money can still move
- code can still deploy
- systems can still change state

---

## The Solution

Waveframe Guard sits at the execution boundary.

Every action must pass through it.

```python
guard.execute(...)
````

If the action is not admissible:

→ it never runs

---

## Example

### Without Waveframe Guard

```python
execute_budget_transfer(...)
```

💥 Executes immediately
💥 No enforcement
💥 No guarantees

---

### With Waveframe Guard

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(policy=policy)

result = guard.execute(
    action={
        "type": "reallocate_budget",
        "amount": 2_000_000
    },
    actor="ai-agent",
    roles={
        "proposer": "ai-agent",
        "approver": "ai-agent"
    },
    execute_fn=execute_budget_transfer
)
```

### Result

```
❌ BLOCKED
Reason: identity reused across required roles
```

---

### Valid Case

```python
roles = {
    "proposer": "ai-agent",
    "approver": "human-123"
}
```

```
✅ ALLOWED
Execution permitted
```

---

## What This Actually Does

Waveframe Guard enforces:

* role separation
* structural integrity
* execution admissibility

Before anything mutates real state.

It uses a deterministic enforcement engine underneath.

No AI. No heuristics. No interpretation.

---

## Install

```bash
pip install waveframe-guard
```

---

## Minimal Usage

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(policy=policy)

result = guard.execute(
    action=action,
    actor="ai-agent",
    roles=roles,
    execute_fn=my_function
)
```

---

## Policy Example

```python
policy = {
    "contract_id": "finance-policy",
    "contract_version": "0.1.0",
    "constraints": [
        {
            "type": "separation_of_duties",
            "roles": ["proposer", "approver"]
        }
    ]
}
```

---

## What You Get

* deterministic execution control
* enforced role separation
* prevention instead of detection
* zero dependency on AI models

---

## What This Is Not

Waveframe Guard is not:

* a monitoring tool
* a logging system
* a workflow engine
* a policy suggestion layer

It does not advise.

It **decides**.

---

## Where It Runs

Waveframe Guard sits directly in your system:

* AI agents
* backend services
* CI/CD pipelines
* automation workflows

Anywhere an action can execute.

---

## Product Direction

Waveframe Guard is the execution layer.

Upcoming:

* hosted policy management
* audit visibility
* execution dashboards
* usage-based billing

---

## License

Proprietary (Waveframe Labs)

---

<div align="center">
  <sub>© 2026 Waveframe Labs — Independent Open-Science Research Entity</sub>
</div>
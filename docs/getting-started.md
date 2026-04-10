# Getting Started

Use Waveframe Guard to stop unsafe AI actions before they execute.

This guide shows how to install, run, and integrate it into a real system in minutes.

---

## 1. Install

```bash
pip install waveframe-guard
````

---

## 2. Run the example

```bash
python examples/finance_usage.py
```

Expected output:

```
--- Scenario 1: Missing approval ---
{'status': 'blocked', 'reason': 'Blocked: approval required (no approver provided)'}

--- Scenario 3: Valid approval ---
{'status': 'executed', 'result': {...}}
```

This demonstrates:

* actions without approval → blocked
* valid actions → executed

---

## 3. Add to your system

Waveframe Guard runs **at the execution point**, right before an action is performed.

Wrap your AI-driven actions like this:

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(policy="finance-policy.json")


def execute_transfer(action):
    # Your actual system logic
    return {
        "status": "executed",
        "details": action
    }


def process_ai_action(action, actor, context=None):
    decision = guard.execute(
        action=action,
        actor=actor,
        context=context
    )

    if not decision["allowed"]:
        return {
            "status": "blocked",
            "reason": decision["reason"]
        }

    return execute_transfer(action)
```

Now every AI action must pass through an execution gate before it runs.

---

## 4. Example usage

```python
result = process_ai_action(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "human-123"}
)

print(result)
```

---

## 5. What just happened

Waveframe Guard:

1. receives the proposed action
2. evaluates it against governance rules
3. returns:

```python
{
  "allowed": bool,
  "reason": str
}
```

Your system:

* executes if allowed
* blocks if not

---

## 6. Policy

Waveframe Guard uses compiled governance rules:

```python
guard = WaveframeGuard(policy="finance-policy.json")
```

These rules define:

* which actions require approval
* who can approve them
* role separation requirements

---

## 7. When to use this

Use Waveframe Guard when:

* AI systems can trigger real actions
* those actions have financial or operational risk
* you need deterministic control before execution

---

## Summary

Waveframe Guard does one thing:

👉 decides whether an action can execute

You control everything else.

---

<div align="center">
  <sub>© 2026 Waveframe Labs — Independent Open-Science Research Entity</sub>
</div>
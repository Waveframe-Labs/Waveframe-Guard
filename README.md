# Waveframe Guard

Deterministic execution control for AI agents.

Stop unauthorized AI actions—from rogue financial transfers to unapproved budget reallocations—in a single function call.

Prevent costly mistakes before they hit production systems.

---

## The execution boundary

Most AI governance tools act as monitors: they log, flag, and alert after a mistake has already happened.

Waveframe Guard sits directly at the execution boundary. It evaluates every proposed action before it ever reaches your backend or mutates state.

The evaluation is deterministic and the result is binary:

- **Allowed** → execution proceeds seamlessly  
- **Blocked** → execution is stopped before it reaches your system  

No warnings. No post-hoc analysis. The action either happens, or it doesn’t.

---

## A drop-in execution gate

Integrate Waveframe Guard into your workflow in minutes.

Initialize the SDK with your compiled governance policy, pass the proposed AI action, and let Guard handle the evaluation.

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(policy="finance-policy.json")


def execute_transfer(action):
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

    if decision["allowed"]:
        return execute_transfer(action)
    else:
        return {
            "status": "blocked",
            "reason": decision["reason"]
        }


result = process_ai_action(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "human-123"}
)

print(result)
````

Waveframe Guard does not execute actions.

It decides whether execution is allowed.

---

## Predictable, standardized outputs

Guard returns a strict, predictable response so your application can route logic deterministically.

**Authorized attempt:**

```json
{
  "allowed": true,
  "reason": "Allowed: execution permitted"
}
```

---

**Unauthorized attempt (missing approval):**

```json
{
  "allowed": false,
  "reason": "Blocked: approval required (no approver provided)"
}
```

---

## Built for financial-grade governance

Waveframe Guard is designed for high-stakes autonomous systems.

* **Separation of duties**
  The actor proposing an action cannot approve it.

* **Approval requirements**
  Human authorization is required for sensitive actions.

* **Action-level constraints**
  Define exactly what an agent is allowed to do.

* **No state stored**
  Your system remains in full control.

---

## Clear boundaries

Waveframe Guard focuses on one responsibility:

👉 deciding whether an action can execute

It does not:

* run workflows
* manage approvals
* store policies
* maintain system state

---

## Getting started

Waveframe Guard is in active development, focused on financial governance and autonomous agent control.

### Local installation

```bash
pip install waveframe-guard
```

---

### Run the example

```bash
python examples/finance_usage.py
```

---

## Policy

Policies represent compiled governance rules.

```python
guard = WaveframeGuard(policy="finance-policy.json")
```

These rules define:

* who can approve actions
* what actions require approval
* role separation requirements

---

<div align="center">
  <sub><b>Proprietary / Commercial License (Pending)</b></sub>
  <br>
  <sub>© 2026 Waveframe Labs</sub>
</div>


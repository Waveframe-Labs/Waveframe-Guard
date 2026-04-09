# Waveframe Guard

Stop unsafe AI financial actions before they execute.

---

## The problem

AI systems can propose actions.

But nothing actually stops them from executing a bad one.

Examples:
- Reallocating budget without approval
- Transferring funds without oversight
- Acting outside defined authority

Most systems:
- log it
- flag it
- explain it

But they still let it happen.

---

## The solution

Waveframe Guard sits at the execution boundary.

Every action is evaluated before it happens.

The result is binary:

- allowed → execution proceeds
- blocked → execution never occurs

---

## What this looks like

```python
from waveframe_guard import WaveframeGuard

guard = WaveframeGuard(policy="finance-policy.json")

result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "human-123"}
)

print(result)
````

Output:

```python
{'allowed': True, 'reason': 'Execution permitted'}
```

---

## Without approval

```python
result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent"
)
```

Output:

```python
{'allowed': False, 'reason': 'Blocked: approval required for financial action'}
```

---

## What it enforces

* Separation of duties
* Approval requirements
* Action-level constraints
* Deterministic execution control

No warnings.
No post-hoc analysis.

The action either happens — or it doesn’t.

---

## Install

```bash
pip install -e .
```

---

## Run the test

```bash
python test_guard.py
```

---

## How it works (simple)

1. AI proposes an action
2. Guard evaluates it against governance rules
3. Returns:

```python
{
  "allowed": bool,
  "reason": str
}
```

4. Your system decides whether to execute

---

## Policy (governance rules)

Policies define what is allowed.

Example:

```python
guard = WaveframeGuard(policy="finance-policy.json")
```

This represents compiled governance rules such as:

* who can approve actions
* what actions require approval
* role separation requirements

---

## Where this fits

Waveframe Guard is the enforcement layer.

It does not:

* run workflows
* manage approvals
* store policies

It decides one thing:

👉 can this action execute or not?

---

## Use cases

* AI-driven finance systems
* autonomous agents with spending authority
* internal tooling with automated decisions
* any system where actions must be controlled

---

## Status

Active development.
Focused on financial governance use cases.

---

## License

Proprietary / Commercial (pending final terms)

---

<div align="center">
  <sub>© 2026 Waveframe Labs — Independent Open-Science Research Entity</sub>
</div>
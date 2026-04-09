"""
Minimal developer test for Waveframe Guard

Run:
    python test_guard.py
"""

from waveframe_guard.client import WaveframeGuard


# -----------------------------
# Example policy (what the SDK expects)
# -----------------------------

policy = {
    "contract_id": "finance-policy",
    "contract_version": "0.1.0",
    "contract_hash": "abc123",  # placeholder for now
}


# -----------------------------
# Initialize guard
# -----------------------------

guard = WaveframeGuard(policy=policy)


# -----------------------------
# Scenario 1: No approval (should block)
# -----------------------------

result_1 = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
)

print("\nScenario 1: No approval")
print(result_1)


# -----------------------------
# Scenario 2: Same actor approves (should block)
# -----------------------------

result_2 = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "ai-agent"},
)

print("\nScenario 2: Same actor approval")
print(result_2)


# -----------------------------
# Scenario 3: Valid approval (should allow)
# -----------------------------

result_3 = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "human-123"},
)

print("\nScenario 3: Valid approval")
print(result_3)


# -----------------------------
# Expected Output (roughly)
# -----------------------------
"""
Scenario 1:
{'allowed': False, 'reason': 'Blocked: same actor cannot propose and approve'}

Scenario 2:
{'allowed': False, 'reason': 'Blocked: same actor cannot propose and approve'}

Scenario 3:
{'allowed': True, 'reason': 'Execution permitted'}
"""
"""
Minimal developer test for Waveframe Guard

Run:
    python test_guard.py
"""

from waveframe_guard.client import WaveframeGuard


# -----------------------------
# Example policy
# -----------------------------

policy = {
    "contract_id": "finance-policy",
    "contract_version": "0.1.0",
    "contract_hash": "abc123",
}


# -----------------------------
# Initialize guard
# -----------------------------

guard = WaveframeGuard(policy=policy)


# -----------------------------
# Scenario runner helper
# -----------------------------

def run_scenario(name, **kwargs):
    result = guard.execute(**kwargs)
    print(f"\n{name}")
    print(result)


# -----------------------------
# Scenario 1: No approval (should block)
# -----------------------------

run_scenario(
    "Scenario 1: No approval",
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
)


# -----------------------------
# Scenario 2: Same actor approves (should block)
# -----------------------------

run_scenario(
    "Scenario 2: Same actor approval",
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "ai-agent"},
)


# -----------------------------
# Scenario 3: Valid approval (should allow)
# -----------------------------

run_scenario(
    "Scenario 3: Valid approval",
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent",
    context={"approved_by": "human-123"},
)


# -----------------------------
# Scenario 4: Read-only action (should allow)
# -----------------------------

run_scenario(
    "Scenario 4: Read-only action",
    action={"type": "get_balance"},
    actor="ai-agent",
)
"""
Minimal developer test for Waveframe Guard (API-driven)

Run:
    python test_guard.py
"""

from waveframe_guard.client import WaveframeGuard


# -----------------------------
# CONFIG
# -----------------------------

API_KEY = "wf_test_key_123"
BASE_URL = "http://localhost:8000"
POLICY_ID = "finance-core"


# -----------------------------
# Initialize guard
# -----------------------------

guard = WaveframeGuard(
    api_key=API_KEY,
    policy_id=POLICY_ID,
    base_url=BASE_URL
)


# -----------------------------
# Scenario runner helper
# -----------------------------

def run_scenario(name, **kwargs):
    print(f"\n{name}")
    try:
        result = guard.execute(**kwargs)
        print(result)
    except Exception as e:
        print("❌ ERROR:", str(e))


# -----------------------------
# COMMON CONTEXT (REQUIRED)
# -----------------------------

BASE_CONTEXT = {
    "responsible": "user-alice",
    "accountable": "user-bob",
}


# -----------------------------
# Scenario 1: No approval (should BLOCK)
# -----------------------------

run_scenario(
    "Scenario 1: No approval",
    action={"type": "transfer", "amount": 5000},
    context=BASE_CONTEXT,
)


# -----------------------------
# Scenario 2: Same person approves (should BLOCK - separation violation)
# -----------------------------

run_scenario(
    "Scenario 2: Same actor approval",
    action={"type": "transfer", "amount": 5000},
    context={
        **BASE_CONTEXT,
        "approved_by": "user-alice",  # same as responsible
    },
)


# -----------------------------
# Scenario 3: Valid approval (should ALLOW)
# -----------------------------

run_scenario(
    "Scenario 3: Valid approval",
    action={"type": "transfer", "amount": 5000},
    context={
        **BASE_CONTEXT,
        "approved_by": "user-charlie",
    },
)


# -----------------------------
# Scenario 4: Read-only action (should ALLOW)
# -----------------------------

run_scenario(
    "Scenario 4: Read-only action",
    action={"type": "get_balance"},
    context=BASE_CONTEXT,
)


# -----------------------------
# Edge Case 1: Empty action
# -----------------------------

run_scenario(
    "Edge Case 1: Empty action",
    action={},
    context=BASE_CONTEXT,
)


# -----------------------------
# Edge Case 2: Missing type
# -----------------------------

run_scenario(
    "Edge Case 2: Missing type",
    action={"amount": 100},
    context=BASE_CONTEXT,
)


# -----------------------------
# Edge Case 3: Garbage context (should ERROR in SDK)
# -----------------------------

run_scenario(
    "Edge Case 3: Garbage context",
    action={"type": "transfer"},
    context="not a dict",
)

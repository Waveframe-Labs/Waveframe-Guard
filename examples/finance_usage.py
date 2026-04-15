from waveframe_guard import Guard


# ---------------------------
# Example execution function
# ---------------------------

def transfer_funds():
    print("💸 Transfer executed")
    return {"status": "success", "amount": 5000}


# ---------------------------
# Setup Guard
# ---------------------------

guard = Guard(
    base_url="http://localhost:8000",
    policy_ref="finance-core-v1",
)

# ---------------------------
# Scenario 1 — VALID
# ---------------------------

print("\n--- Scenario 1: Valid Roles ---")

result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent-v2",
    context={
        "responsible": "user-alice",
        "accountable": "user-bob",
        "approved_by": "user-charlie",  # ✅ FIXED (independent approver)
    },
    execute_fn=transfer_funds,
)

print(result)


# ---------------------------
# Scenario 2 — INVALID
# ---------------------------

print("\n--- Scenario 2: Role Violation ---")

result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent-v2",
    context={
        "responsible": "user-bob",
        "accountable": "user-alice",
        "approved_by": "user-bob",  # ❌ same as responsible
    },
    execute_fn=transfer_funds,
)

print(result)
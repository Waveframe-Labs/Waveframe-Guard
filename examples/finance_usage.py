from waveframe_guard import Guard
import json


def transfer_funds():
    print("💸 Transfer executed")
    return {"status": "success", "amount": 5000}


def print_decision(record: dict):
    print("\n--- Decision Record ---")
    print(f"Decision ID: {record.get('decision_id')}")
    print(f"Allowed: {record.get('allowed')}")
    print(f"Reason: {record.get('reason')}")
    print(f"Policy: {record.get('policy_ref')}")
    print(f"Timestamp: {record.get('timestamp')}")

    print("\nResolved Identities:")
    for k, v in record.get("resolved_identities", {}).items():
        print(f"  - {k}: {v}")

    print("\nTrace:")
    for stage in record.get("decision_trace", []):
        status = "PASS" if stage.get("passed") else "FAIL"
        print(f"  [{status}] {stage.get('stage')}")
        for msg in stage.get("messages", []):
            print(f"     ↳ {msg}")

    print("\nTrace Hash:", record.get("trace_hash"))
    print("------------------------\n")


guard = Guard(
    base_url="http://localhost:8000",
    policy_ref="finance-core-v1",
)

# ---------------------------
# Scenario 1 — VALID
# ---------------------------

print("\n==============================")
print("SCENARIO 1: VALID TRANSFER")
print("==============================")

result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent-v2",
    context={
        "responsible": "user-alice",
        "accountable": "user-bob",
        "approved_by": "user-charlie",
    },
    execute_fn=transfer_funds,
)

if result.get("executed"):
    print("\n✅ RESULT: EXECUTED")
    print("Funds moved successfully")

    print_decision(result["decision"])

else:
    print("\n❌ RESULT: BLOCKED (unexpected)")
    print(result.get("reason"))
    print_decision(result["decision"])


# ---------------------------
# Scenario 2 — INVALID
# ---------------------------

print("\n==============================")
print("SCENARIO 2: ROLE VIOLATION")
print("==============================")

result = guard.execute(
    action={"type": "transfer", "amount": 5000},
    actor="ai-agent-v2",
    context={
        # ❌ Same person involved in multiple roles (should fail)
        "responsible": "user-bob",
        "accountable": "user-alice",
        "approved_by": "user-bob",
    },
    execute_fn=transfer_funds,
)

if result.get("blocked"):
    print("\n🚫 RESULT: BLOCKED")
    print("Execution was stopped before funds moved")
    print(f"Reason: {result.get('reason')}")

    print_decision(result["decision"])

else:
    print("\n⚠️ RESULT: EXECUTED (unexpected — check enforcement)")
    print(result)
    print_decision(result["decision"])
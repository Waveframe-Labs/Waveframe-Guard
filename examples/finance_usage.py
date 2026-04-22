from waveframe_guard import WaveframeGuard


def print_decision(record: dict) -> None:
    print("\n--- Decision Record ---")
    print(f"Allowed: {record.get('allowed')}")
    print(f"Status: {record.get('status')}")
    print(f"Reason: {record.get('reason')}")
    print(f"Risk: {record.get('risk_level')}")
    print(f"Summary: {record.get('summary')}")
    print("------------------------\n")


guard = WaveframeGuard(
    api_key="wf_test_key_123",
    policy_id="finance-core",
    base_url="http://localhost:8000",
)


print("\n==============================")
print("SCENARIO 1: VALID TRANSFER")
print("==============================")

result = guard.execute(
    action={
        "type": "transfer",
        "amount": 5000,
        "system": "finance",
        "resource": "payroll",
    },
    actor="ai-agent-v2",
    context={
        "responsible": "user-alice",
        "accountable": "user-bob",
        "approved_by": "user-charlie",
    },
)

print_decision(result)


print("\n==============================")
print("SCENARIO 2: ROLE VIOLATION")
print("==============================")

result = guard.execute(
    action={
        "type": "transfer",
        "amount": 5000,
        "system": "finance",
        "resource": "payroll",
    },
    actor="ai-agent-v2",
    context={
        "responsible": "user-bob",
        "accountable": "user-alice",
        "approved_by": "user-bob",
    },
)

print_decision(result)

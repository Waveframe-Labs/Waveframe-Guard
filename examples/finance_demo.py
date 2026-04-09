"""
Waveframe Guard — Finance Demo (Role-Aware)

Demonstrates deterministic enforcement of separation-of-duties.

Same action:
- Blocked when roles are violated
- Allowed when roles are valid
"""

from waveframe_guard import WaveframeGuard


def perform_mutation(action):
    # Simulated execution
    return {
        "status": "executed",
        "action": action
    }


def run_demo():
    print("\nWaveframe Guard — Role-Based Enforcement Demo")
    print("=" * 60)

    # --------------------------------------------------
    # Define policy (what governance requires)
    # --------------------------------------------------
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

    guard = WaveframeGuard(policy=policy)

    action = {
        "type": "reallocate_budget",
        "amount": 2_000_000
    }

    # --------------------------------------------------
    # Scenario 1 — VIOLATION (same actor)
    # --------------------------------------------------
    print("\nScenario 1: Role Violation (Same Actor)")
    print("-" * 60)

    roles = {
        "proposer": "ai-agent",
        "approver": "ai-agent"
    }

    result = guard.execute(
        action=action,
        actor="ai-agent",
        roles=roles,
        execute_fn=perform_mutation
    )

    print("\nAction:")
    print("AI attempts to reallocate $2,000,000")

    print("\nRoles:")
    print(roles)

    if result["allowed"]:
        print("\n⚠️ UNEXPECTED: ALLOWED")
    else:
        print("\n✅ BLOCKED (Expected)")

    print(f"Reason: {result['reason']}")

    # --------------------------------------------------
    # Scenario 2 — VALID (separate actors)
    # --------------------------------------------------
    print("\nScenario 2: Valid Separation of Duties")
    print("-" * 60)

    roles = {
        "proposer": "ai-agent",
        "approver": "human-123"
    }

    result = guard.execute(
        action=action,
        actor="ai-agent",
        roles=roles,
        execute_fn=perform_mutation
    )

    print("\nAction:")
    print("AI attempts to reallocate $2,000,000")

    print("\nRoles:")
    print(roles)

    if result["allowed"]:
        print("\n✅ ALLOWED (Expected)")
    else:
        print("\n❌ UNEXPECTED: BLOCKED")

    print(f"Reason: {result['reason']}")

    print("\n" + "=" * 60)
    print("Demo complete\n")


if __name__ == "__main__":
    run_demo()
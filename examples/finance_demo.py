"""
Waveframe Guard — Finance Demo

This demo shows how Waveframe Guard prevents unsafe AI actions
at the moment of execution.

No internal knowledge of CRI-CORE is required.
"""

from waveframe_guard import WaveframeGuard


def run_demo():
    print("\nWaveframe Guard — Finance Execution Demo")
    print("=" * 50)

    guard = WaveframeGuard()

    # --------------------------------------------------
    # Scenario 1: Unsafe Action (Should be BLOCKED)
    # --------------------------------------------------
    print("\nScenario 1: Unauthorized Financial Action")
    print("-" * 50)

    action = {
        "type": "reallocate_budget",
        "amount": 2_000_000
    }

    result = guard.execute(
        action=action,
        actor="ai-agent"
    )

    print("\nAction:")
    print("AI attempts to reallocate $2,000,000")

    if result["allowed"]:
        print("\n✅ ALLOWED")
    else:
        print("\n❌ BLOCKED")

    print(f"Reason: {result['reason']}")

    # --------------------------------------------------
    # Scenario 2: Safe Action (Should be ALLOWED)
    # --------------------------------------------------
    print("\nScenario 2: Approved Financial Action")
    print("-" * 50)

    action = {
        "type": "reallocate_budget",
        "amount": 50_000
    }

    result = guard.execute(
        action=action,
        actor="ai-agent"
    )

    print("\nAction:")
    print("AI attempts to reallocate $50,000")

    if result["allowed"]:
        print("\n✅ ALLOWED")
    else:
        print("\n❌ BLOCKED")

    print(f"Reason: {result['reason']}")

    print("\n" + "=" * 50)
    print("Demo complete\n")


if __name__ == "__main__":
    run_demo()
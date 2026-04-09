"""
Waveframe Guard — Production Usage Example

This shows how a backend service would use Waveframe Guard
to evaluate AI-generated financial actions BEFORE execution.

Run:
    python examples/finance_usage.py
"""

from waveframe_guard import WaveframeGuard


# --------------------------------------------------
# Load compiled governance policy
# --------------------------------------------------

# In production, this would come from a file or config system
policy = "finance-policy.json"

guard = WaveframeGuard(policy=policy)


# --------------------------------------------------
# Simulated execution layer (your actual system)
# --------------------------------------------------

def execute_transfer(action: dict):
    """
    This represents your real system performing the action.
    Only called if guard allows execution.
    """
    return {
        "status": "executed",
        "details": action
    }


# --------------------------------------------------
# Core evaluation wrapper
# --------------------------------------------------

def process_action(action: dict, actor: str, context: dict | None = None):
    """
    Standard pattern:

    1. Evaluate with Waveframe Guard
    2. If allowed → execute
    3. If blocked → stop
    """

    decision = guard.execute(
        action=action,
        actor=actor,
        context=context
    )

    if not decision["allowed"]:
        return {
            "status": "blocked",
            "reason": decision["reason"]
        }

    result = execute_transfer(action)

    return {
        "status": "executed",
        "result": result
    }


# --------------------------------------------------
# Example scenarios (real-world style)
# --------------------------------------------------

def main():

    print("\n--- Scenario 1: Missing approval ---")

    result_1 = process_action(
        action={"type": "transfer", "amount": 5000},
        actor="ai-agent"
    )

    print(result_1)


    print("\n--- Scenario 2: Invalid approval (same actor) ---")

    result_2 = process_action(
        action={"type": "transfer", "amount": 5000},
        actor="ai-agent",
        context={"approved_by": "ai-agent"}
    )

    print(result_2)


    print("\n--- Scenario 3: Valid approval ---")

    result_3 = process_action(
        action={"type": "transfer", "amount": 5000},
        actor="ai-agent",
        context={"approved_by": "human-123"}
    )

    print(result_3)


    print("\n--- Scenario 4: Read-only action ---")

    result_4 = process_action(
        action={"type": "get_balance"},
        actor="ai-agent"
    )

    print(result_4)


if __name__ == "__main__":
    main()
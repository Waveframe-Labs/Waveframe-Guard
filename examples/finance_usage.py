from waveframe_guard import Guard, GuardViolation


allow_guard = Guard(policy="finance-policy.json")


@allow_guard.enforce(action_type="write", resource="finance/budget")
def approved_write():
    print("Budget write executed.\n")


block_guard = Guard(policy="finance-policy.json", mode="block")
block_guard.context["accountable"] = block_guard.context["responsible"]


@block_guard.enforce(action_type="write", resource="finance/budget")
def rejected_write():
    print("This line should never execute.\n")


if __name__ == "__main__":
    print("\n--- Passing action ---")
    approved_write()

    print("--- Failing action ---")
    try:
        rejected_write()
    except GuardViolation as exc:
        print(exc)

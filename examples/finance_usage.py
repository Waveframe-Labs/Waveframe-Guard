from waveframe_guard import Guard, GuardViolation


guard = Guard(policy="finance-core", mode="block")


@guard.enforce(action_type="transfer", resource="budget")
def transfer_funds(amount):
    print(f"Executing transfer of ${amount:,}")


same_actor_guard = Guard(policy="finance-core", mode="block")
same_actor_guard.context["accountable"] = same_actor_guard.context["responsible"]


@same_actor_guard.enforce(action_type="transfer", resource="budget")
def transfer_funds_with_same_actor(amount):
    print(f"Executing transfer of ${amount:,}")


if __name__ == "__main__":
    print("\n--- Approval Threshold Violation ---")
    try:
        transfer_funds(25000)
    except GuardViolation as exc:
        print(exc)

    print("\n--- Separation Of Duties Violation ---")
    try:
        transfer_funds_with_same_actor(500)
    except GuardViolation as exc:
        print(exc)

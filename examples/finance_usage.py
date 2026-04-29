from waveframe_guard import Guard, GuardViolation


guard = Guard(policy="finance-core", mode="block")


@guard.enforce(action_type="transfer", resource="budget")
def transfer_funds(amount):
    print(f"Executing transfer of ${amount:,}")


if __name__ == "__main__":
    print("\n--- Incident Simulation ---")
    transfer_funds(500)

    try:
        transfer_funds(25000)
    except GuardViolation as exc:
        print(exc)

from waveframe_guard import install_guard, guard
from compiler.compile_policy import compile_policy


policy = {
    "contract_id": "finance-core",
    "contract_version": "0.3.0",
    "authority": {
        "required_roles": ["manager"]
    }
}

compiled = compile_policy(policy)


@guard
def transfer_funds(amount):
    print(f"Transferred ${amount:,}")


if __name__ == "__main__":
    print("\n--- Blocked Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        contract=compiled
    )

    try:
        transfer_funds(500)
    except PermissionError as exc:
        print("BLOCKED:", exc)

    print("\n--- Allowed Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract=compiled
    )
    transfer_funds(500)

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard, GovernanceError


@guard
def transfer_funds(amount):
    print(f"Transferred ${amount:,}")


if __name__ == "__main__":
    print("\n--- Blocked Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        contract_path="contracts/finance-core-0.1.0.contract.json"
    )

    try:
        transfer_funds(500)
    except GovernanceError as exc:
        print("BLOCKED:", exc)

    print("\n--- Allowed Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_path="contracts/finance-core-0.1.0.contract.json"
    )
    transfer_funds(500)

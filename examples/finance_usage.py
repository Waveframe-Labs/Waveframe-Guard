from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard, GovernanceError

CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "finance-core-0.3.0.contract.json"
)


@guard
def transfer_funds(amount):
    print(f"Transferred ${amount:,}")


if __name__ == "__main__":
    print("\n--- Blocked Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        contract_path=CONTRACT_PATH,
    )

    try:
        transfer_funds(500)
    except GovernanceError as exc:
        print("BLOCKED:", exc)

    print("\n--- Allowed Transaction ---")
    install_guard(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_path=CONTRACT_PATH,
    )
    transfer_funds(500)

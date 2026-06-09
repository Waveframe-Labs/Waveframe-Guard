from pathlib import Path

from waveframe_guard import guard, install_guard


CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "finance-policy-1.0.0.contract.json"
)

install_guard(
    actor={"id": "u1", "type": "human", "role": "manager"},
    contract_path=CONTRACT_PATH,
)


@guard
def demo_action():
    return "executed"


print(demo_action())

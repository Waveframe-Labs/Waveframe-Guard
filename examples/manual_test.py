from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard

CONTRACT_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "finance-core-0.3.1.contract.json"
)

install_guard(
    actor={"id": "u1", "type": "human", "role": "manager"},
    contract_path=CONTRACT_PATH,
)


@guard
def demo_action():
    return "executed"


print(demo_action())

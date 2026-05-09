from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard

install_guard(
    actor={"id": "u1", "type": "human", "role": "manager"},
    contract_path="contracts/finance-core-0.1.0.contract.json",
)


@guard
def demo_action():
    return "executed"


print(demo_action())

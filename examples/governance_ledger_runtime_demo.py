from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waveframe_guard import install_guard, guard, GovernanceError


# Governance Ledger publishes contract
#         ↓
# Guard loads contract from contracts/
#         ↓
# AI proposal generated
#         ↓
# CRI-CORE evaluates proposal
#         ↓
# Execution blocked

CONTRACT_PATH = "contracts/finance-core-0.3.0.contract.json"


install_guard(
    actor={"id": "agent-1", "type": "agent", "role": "intern"},
    contract_path=CONTRACT_PATH,
)


@guard
def approve_transfer(amount):
    print(f"Approved transfer for ${amount}")


print("\n--- Full-stack governance runtime demo ---")
print(f"Loaded published contract: {CONTRACT_PATH}")

try:
    approve_transfer(100)
except GovernanceError as exc:
    print("BLOCKED:", exc)

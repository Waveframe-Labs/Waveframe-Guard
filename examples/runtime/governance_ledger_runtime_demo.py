from pathlib import Path

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

CONTRACT_PATH = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "finance-policy-1.0.0.contract.json"
)


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

import json
import tempfile
from pathlib import Path

from waveframe_guard import Guard, GuardViolation


POLICY = {
    "contract_id": "finance-core",
    "contract_version": "1.2.0",
    "authority_requirements": {
        "required_roles": ["proposer", "responsible", "accountable"]
    },
    "artifact_requirements": {
        "artifacts_present": True
    },
    "stage_requirements": {
        "integrity": {"artifacts_present": True},
        "publication": {"ready": True}
    },
    "invariants": [
        {"type": "separation_of_duties", "roles": ["responsible", "accountable"]}
    ],
    "approval_requirements": {
        "thresholds": [
            {
                "field": "amount",
                "operator": ">",
                "value": 10000,
                "requires_role": "approver"
            }
        ]
    }
}


with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tmp:
    json.dump(POLICY, tmp)
    POLICY_PATH = Path(tmp.name)


guard = Guard(policy=str(POLICY_PATH), mode="block")


@guard.enforce(action_type="transfer", resource="company-funds")
def transfer_funds(amount):
    print(f"Executing transfer of ${amount:,}")


if __name__ == "__main__":
    print("\n--- Incident Simulation ---")
    transfer_funds(500)

    try:
        transfer_funds(25000)
    except GuardViolation as exc:
        print(exc)

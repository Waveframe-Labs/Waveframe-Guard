from guard.sdk import GuardRuntimeBoundary


def build_transfer_request(amount):
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": f"transfer-{amount}",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


guard = GuardRuntimeBoundary(
    compiled_authority={
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:example",
        "authority_requirements": {"required_roles": ["manager"]},
        "approval_requirements": {"required": [{"role": "manager"}]},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    },
    actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
    approvals=[{"role": "manager", "approved_by": "manager-approval"}],
)


@guard.decorator(build_transfer_request)
def transfer(amount):
    return {"transferred": amount}


print(transfer(500))

from guard.sdk import GuardExecutionBlocked, GuardRuntimeBoundary, LocalEvaluationStore


compiled_authority = {
    "schema_version": "compiled_authority_contract.v1",
    "contract_id": "finance-policy",
    "contract_version": "1.0.0",
    "contract_hash": "sha256:example",
    "authority_requirements": {"required_roles": ["manager"]},
    "approval_requirements": {"required": [{"role": "manager"}]},
    "artifact_requirements": {},
    "stage_requirements": {},
    "invariants": {},
}


def normalized_transfer_request(amount):
    return {
        "schema_version": "normalized_execution_request.v1",
        "request_id": f"transfer-{amount}",
        "action": "transfer",
        "target": "wire",
        "arguments": {"amount": amount},
        "artifacts": [],
    }


guard = GuardRuntimeBoundary(
    compiled_authority=compiled_authority,
    actor_identity={"id": "manager-1", "type": "human", "role": "manager"},
    approvals=[{"role": "manager", "approved_by": "manager-approval"}],
    store=LocalEvaluationStore(".guard-local"),
)


def send_wire(amount):
    return {"wire_sent": amount}


try:
    result = guard.execute(
        send_wire,
        execution_request=normalized_transfer_request(500),
        args=(500,),
    )
    print(result["outcome"]["status"], result["value"])
except GuardExecutionBlocked as exc:
    print(exc.outcome["status"], exc.outcome["rationale"])

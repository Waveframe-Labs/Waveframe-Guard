from guard.sdk import GuardRuntimeBoundary, agent_runner_adapter


guard = GuardRuntimeBoundary(
    compiled_authority={
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "agent-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:example",
        "authority_requirements": {"required_roles": ["agent"]},
        "approval_requirements": {"required": []},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    },
    actor_identity={"id": "agent-1", "type": "agent", "role": "agent"},
)


def run_agent_step(step):
    return {"step_id": step["id"], "executed": True}


guarded_agent_step = agent_runner_adapter(
    guard,
    request_loader=lambda step: step["execution_request"],
    runner=run_agent_step,
)


result = guarded_agent_step(
    {
        "id": "tool-call-1",
        "execution_request": {
            "schema_version": "normalized_execution_request.v1",
            "request_id": "tool-call-1",
            "action": "tool_call",
            "target": "crm.write_note",
            "arguments": {"account_id": "acct-1"},
            "artifacts": [],
        },
    }
)
print(result)

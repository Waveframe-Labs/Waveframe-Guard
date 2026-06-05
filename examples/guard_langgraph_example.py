from guard.sdk import GuardRuntimeBoundary


guard = GuardRuntimeBoundary(
    compiled_authority={
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "agent-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:example",
        "authority_requirements": {"required_roles": ["operator"]},
        "approval_requirements": {"required": []},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    },
    actor_identity={"id": "agent-runner-1", "type": "service", "role": "operator"},
)


def guarded_langgraph_node(state):
    execution_request = state["execution_request"]
    guard.enforce(
        execution_request,
        execution_context={"surface": "langgraph_node"},
    )
    return {
        **state,
        "guard_outcome": "admissible",
    }


# graph.add_node("guard_runtime_boundary", guarded_langgraph_node)

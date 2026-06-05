from guard.sdk import GuardExecutionError, GuardRuntimeBoundary


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


async def guard_fastapi_middleware(request, call_next):
    payload = await request.json()
    try:
        guard.enforce(
            payload["execution_request"],
            execution_context={"surface": "fastapi"},
        )
    except GuardExecutionError as exc:
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=403,
            content={"guard_enforcement_outcome": exc.outcome},
        )
    return await call_next(request)


# app.middleware("http")(guard_fastapi_middleware)

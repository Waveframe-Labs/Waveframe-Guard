from guard.sdk import GuardRuntimeBoundary, queue_job_adapter


guard = GuardRuntimeBoundary(
    compiled_authority={
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "job-policy",
        "contract_version": "1.0.0",
        "contract_hash": "sha256:example",
        "authority_requirements": {"required_roles": ["worker"]},
        "approval_requirements": {"required": []},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    },
    actor_identity={"id": "worker-1", "type": "service", "role": "worker"},
)


def process_job(job):
    return {"processed": job["id"]}


guarded_process_job = queue_job_adapter(
    guard,
    request_loader=lambda job: job["execution_request"],
    handler=process_job,
)


# @celery_app.task
# def process_transfer_job(job):
#     return guarded_process_job(job)

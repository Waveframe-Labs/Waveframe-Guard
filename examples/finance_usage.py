from waveframe_guard import Guard

policy = {
    "contract_id": "finance-core",
    "contract_version": "1.0.0",
    "authority_requirements": {
        "required_roles": ["proposer", "responsible", "accountable"]
    }
}

guard = Guard(policy=policy, mode="shadow")


@guard.enforce(
    action="delete",
    system="infra",
    resource="prod-db"
)
def dangerous_operation():
    print("🔥 This should NOT run safely")


dangerous_operation()

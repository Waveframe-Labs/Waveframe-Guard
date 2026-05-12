from waveframe_guard import GovernanceError, GovernedRuntime


def transfer(amount):
    print(f"Transferred ${amount}")


runtime = GovernedRuntime(
    registry_path="contracts/index.json",
)

try:
    runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        contract_id="finance-policy",
        fn=transfer,
        args=(1250000,),
    )
except GovernanceError as exc:
    print(exc)

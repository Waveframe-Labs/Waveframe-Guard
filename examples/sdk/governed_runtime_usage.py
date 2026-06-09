from waveframe_guard import GovernanceError, GovernedRuntime


def transfer(amount):
    print(f"Transferred ${amount}")


runtime = GovernedRuntime(
    registry_path="contracts/index.json",
)
runtime.bind_contract("finance-policy@1.0.0")

try:
    runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        fn=transfer,
        args=(1250000,),
    )
except GovernanceError as exc:
    print(exc)

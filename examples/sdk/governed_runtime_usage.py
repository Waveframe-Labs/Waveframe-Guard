"""Retained legacy migration demonstration; execution always fails closed.

Use Guard.local()/Guard.cloud() guarded tools; see
 docs/getting-started/STRICT_EXECUTION_MIGRATION.md and examples/quickstart_guard.py.
"""

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

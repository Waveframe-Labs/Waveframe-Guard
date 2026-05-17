import json

import pytest
from compiler.compile_policy import compile_policy

from waveframe_guard import GovernanceError, GovernedRuntime


def write_contract(tmp_path):
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "authority": {"required_roles": ["manager"]},
    }
    contract = compile_policy(policy)
    contract_path = tmp_path / "finance-policy.contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return contract_path


def write_registry(tmp_path, contract_path):
    registry_path = tmp_path / "index.json"
    registry_path.write_text(
        json.dumps(
            {
                "contracts": [
                    {
                        "contract_id": "finance-policy",
                        "contract_version": "1.0.0",
                        "path": contract_path.name,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return registry_path


def test_runtime_allows_authorized_actor(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    assert runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        fn=transfer,
        args=(125,),
    ) == "transferred 125"


def test_runtime_blocks_unauthorized_actor(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    with pytest.raises(GovernanceError, match="required role not satisfied"):
        runtime.execute(
            actor={"id": "user-1", "type": "human", "role": "intern"},
            contract_id="finance-policy@1.0.0",
            fn=transfer,
            args=(1250000,),
        )


def test_runtime_raises_for_unknown_contract(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    with pytest.raises(KeyError, match="Unknown contract"):
        runtime.execute(
            actor={"id": "user-1", "type": "human", "role": "manager"},
            contract_id="missing-policy@1.0.0",
            fn=lambda: "ok",
        )

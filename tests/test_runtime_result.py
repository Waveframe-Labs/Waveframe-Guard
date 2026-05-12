import json

from compiler.compile_policy import compile_policy

from waveframe_guard import GovernedExecutionResult, GovernedRuntime


def write_contract(tmp_path):
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.3.1",
        "authority": {"required_roles": ["manager"]},
    }
    contract = compile_policy(policy)
    contract_path = tmp_path / "finance-policy.contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    return contract, contract_path


def write_registry(tmp_path, contract_path):
    registry_path = tmp_path / "index.json"
    registry_path.write_text(
        json.dumps(
            {
                "contracts": {
                    "finance-policy": contract_path.name,
                },
            }
        ),
        encoding="utf-8",
    )
    return registry_path


def test_runtime_result_for_allowed_execution(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    result = runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy",
        fn=transfer,
        args=(125,),
        raise_on_block=False,
    )

    assert result == GovernedExecutionResult(
        allowed=True,
        reason="execution allowed",
        contract_id="finance-policy",
        contract_version="0.3.1",
        contract_hash=contract["contract_hash"],
        value="transferred 125",
    )


def test_runtime_result_for_blocked_execution(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    result = runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "intern"},
        contract_id="finance-policy",
        fn=transfer,
        args=(1250000,),
        raise_on_block=False,
    )

    assert result == GovernedExecutionResult(
        allowed=False,
        reason="required role not satisfied: manager",
        contract_id="finance-policy",
        contract_version="0.3.1",
        contract_hash=contract["contract_hash"],
        error="Execution blocked: required role not satisfied: manager",
    )

import json

import pytest
from compiler.compile_policy import compile_policy
from proposal_normalizer.build_proposal import build_proposal

from waveframe_guard import GovernanceError, GovernedExecutionResult, GovernedRuntime


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


def make_proposal(actor, contract):
    return build_proposal(
        proposal_id="proposal-1",
        actor=actor,
        mutation={
            "domain": "python",
            "resource": "transfer",
            "action": "call",
        },
        contract={
            "id": contract["contract_id"],
            "version": contract["contract_version"],
            "hash": contract["contract_hash"],
        },
        artifact_paths=[],
    )


def test_runtime_uses_bound_actor_and_contract_for_function_execution(tmp_path):
    _, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})
    runtime.bind_contract("finance-policy")

    def transfer(amount):
        return f"transferred {amount}"

    assert runtime.execute(fn=transfer, args=(125,)) == "transferred 125"


def test_runtime_call_actor_overrides_bound_actor(tmp_path):
    _, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor({"id": "user-1", "type": "human", "role": "intern"})
    runtime.bind_contract("finance-policy")

    def transfer(amount):
        return f"transferred {amount}"

    assert runtime.execute(
        actor={"id": "user-2", "type": "human", "role": "manager"},
        fn=transfer,
        args=(125,),
    ) == "transferred 125"


def test_runtime_requires_actor_context(tmp_path):
    _, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.bind_contract("finance-policy")

    with pytest.raises(ValueError, match="Missing actor"):
        runtime.execute(fn=lambda: "ok")


def test_runtime_requires_contract_context(tmp_path):
    _, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})

    with pytest.raises(ValueError, match="Missing contract_id"):
        runtime.execute(fn=lambda: "ok")


def test_execute_proposal_allows_bound_context(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    actor = {"id": "user-1", "type": "human", "role": "manager"}
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor(actor).bind_contract("finance-policy")

    result = runtime.execute_proposal(
        make_proposal(actor, contract),
        raise_on_block=False,
    )

    assert result == GovernedExecutionResult(
        allowed=True,
        reason="execution allowed",
        contract_id="finance-policy",
        contract_version="0.3.1",
        contract_hash=contract["contract_hash"],
        value=make_proposal(actor, contract),
    )


def test_execute_proposal_blocks_bound_context(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    actor = {"id": "user-1", "type": "human", "role": "intern"}
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor(actor).bind_contract("finance-policy")

    result = runtime.execute_proposal(
        make_proposal(actor, contract),
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


def test_execute_proposal_raises_by_default(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    actor = {"id": "user-1", "type": "human", "role": "intern"}
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.install_actor(actor).bind_contract("finance-policy")

    with pytest.raises(GovernanceError, match="required role not satisfied"):
        runtime.execute_proposal(make_proposal(actor, contract))

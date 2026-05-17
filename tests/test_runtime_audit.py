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
    return contract, contract_path


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


def test_runtime_returns_and_stores_blocked_execution_event(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    actor = {"id": "user-1", "type": "human", "role": "intern"}
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    result = runtime.execute(
        actor=actor,
        contract_id="finance-policy@1.0.0",
        fn=transfer,
        args=(1250000,),
        raise_on_block=False,
    )

    assert result.event == runtime.last_event
    assert runtime.audit_events == [result.event]
    assert result.event["event_type"] == "governed_execution"
    assert result.event["execution_type"] == "function"
    assert result.event["allowed"] is False
    assert result.event["reason"] == "required role not satisfied: manager"
    assert result.event["error"] == "Execution blocked: required role not satisfied: manager"
    assert result.event["contract_id"] == "finance-policy"
    assert result.event["contract_version"] == "1.0.0"
    assert result.event["contract_hash"] == contract["contract_hash"]
    assert result.event["actor"] == actor
    assert result.event["target"] == "transfer"
    assert "timestamp" in result.event


def test_runtime_emits_event_before_raising_block(tmp_path):
    _, contract_path = write_contract(tmp_path)
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

    assert runtime.last_event["allowed"] is False
    assert runtime.last_event["reason"] == "required role not satisfied: manager"
    assert len(runtime.audit_events) == 1


def test_runtime_writes_audit_events_to_jsonl(tmp_path):
    _, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    audit_path = tmp_path / "audit" / "events.jsonl"
    runtime = GovernedRuntime(registry_path=registry_path, audit_path=audit_path)

    def transfer(amount):
        return f"transferred {amount}"

    result = runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        fn=transfer,
        args=(125,),
        raise_on_block=False,
    )

    records = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
    ]
    assert records == [result.event]


def test_execute_proposal_emits_event(tmp_path):
    contract, contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)
    actor = {"id": "user-1", "type": "human", "role": "manager"}
    proposal = {
        "proposal_id": "proposal-1",
        "actor": actor,
        "mutation": {
            "domain": "python",
            "resource": "transfer",
            "action": "call",
        },
        "contract": {
            "id": contract["contract_id"],
            "version": contract["contract_version"],
            "hash": contract["contract_hash"],
        },
        "artifacts": [],
    }

    result = runtime.execute_proposal(
        proposal,
        actor=actor,
        contract_id="finance-policy@1.0.0",
        raise_on_block=False,
    )

    assert result.event == runtime.last_event
    assert result.event["execution_type"] == "proposal"
    assert result.event["allowed"] is True
    assert result.event["target"] == "proposal-1"

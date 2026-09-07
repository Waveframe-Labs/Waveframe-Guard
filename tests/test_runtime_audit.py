import json

import pytest
from compiler.compile_policy import compile_policy

from waveframe_guard import GovernanceError, GovernedRuntime
from waveframe_guard import LegacyExecutionError


@pytest.mark.parametrize("role", ["manager", "intern"])
def test_rejected_legacy_calls_emit_no_execution_evidence(tmp_path, role):
    _, path = write_contract(tmp_path)
    audit = tmp_path / "audit.jsonl"
    runtime = GovernedRuntime(registry_path=write_registry(tmp_path, path), audit_path=audit)
    calls = []
    with pytest.raises(LegacyExecutionError):
        runtime.execute(actor={"id": "u", "type": "human", "role": role},
                        contract_id="finance-policy@1.0.0", fn=lambda: calls.append(1),
                        raise_on_block=False)
    assert calls == [] and runtime.audit_events == []
    assert runtime.last_event is None and not audit.exists()


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

import json

from compiler.compile_policy import compile_policy

from waveframe_guard import GovernedExecutionResult, GovernedRuntime
from waveframe_guard import LegacyExecutionError
import pytest


@pytest.mark.parametrize("raise_on_block", [False, True])
def test_legacy_execution_never_returns_success_result(tmp_path, raise_on_block):
    _, path = write_contract(tmp_path)
    runtime = GovernedRuntime(registry_path=write_registry(tmp_path, path))
    with pytest.raises(LegacyExecutionError):
        runtime.execute(actor={"id": "u", "type": "human", "role": "manager"},
                        contract_id="finance-policy@1.0.0", fn=lambda: pytest.fail("callback ran"),
                        raise_on_block=raise_on_block)


def test_historical_execution_result_remains_serializable():
    result = GovernedExecutionResult(allowed=True, reason="historical record", value="saved",
                                      contract_id="t", contract_version="1.0.0", contract_hash="saved-hash",
                                      execution_state={"schema_version": "governed_execution_state.v1",
                                                       "authority_ref": "t@1.0.0", "actor": {},
                                                       "approvals": [], "arguments": {}, "artifacts": []})
    assert result.to_dict()["allowed"] is True
    assert result.value == "saved"


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

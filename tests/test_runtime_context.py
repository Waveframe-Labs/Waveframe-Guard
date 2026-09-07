import json

import pytest
from compiler.compile_policy import compile_policy
from proposal_normalizer.build_proposal import build_proposal

from waveframe_guard import GovernanceError, GovernedExecutionResult, GovernedRuntime
from waveframe_guard import LegacyExecutionError


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize("role", ["manager", "intern"])
def test_execute_proposal_original_inputs_require_migration(tmp_path, bound, role):
    contract, path = write_contract(tmp_path)
    runtime = GovernedRuntime(registry_path=write_registry(tmp_path, path))
    actor = {"id": "u", "type": "human", "role": role}
    if bound:
        runtime.bind_contract("finance-policy@1.0.0").install_actor(actor)
    kwargs = {} if bound else {"actor": actor, "contract_id": "finance-policy@1.0.0"}
    with pytest.raises(LegacyExecutionError):
        runtime.execute_proposal(make_proposal(actor, contract), raise_on_block=False, **kwargs)
    assert runtime.last_event is None


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

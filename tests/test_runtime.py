import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from compiler.compile_policy import compile_policy

from waveframe_guard import GovernanceError, GovernedRuntime
from waveframe_guard import LegacyExecutionError


@pytest.mark.parametrize("status", ["active", "superseded", "revoked"])
def test_legacy_lifecycle_cannot_enable_execution(tmp_path, status):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, status=status)
    runtime = GovernedRuntime(registry_path=registry_path)
    calls = []
    with pytest.raises(LegacyExecutionError):
        runtime.execute(actor={"id": "u", "type": "human", "role": "manager"},
                        contract_id="finance-policy@1.0.0", fn=lambda: calls.append(1))
    assert calls == [] and runtime.last_event is None


def test_registry_loading_still_rejects_unknown_contract(tmp_path):
    registry = write_registry(tmp_path, write_contract(tmp_path))
    runtime = GovernedRuntime(registry_path=registry)
    with pytest.raises(KeyError, match="Unknown contract"):
        runtime._load_contract("missing-policy", "1.0.0")


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


def write_registry(tmp_path, contract_path, **entry_metadata):
    registry_path = tmp_path / "index.json"
    entry = {
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "path": contract_path.name,
    }
    entry.update(entry_metadata)
    registry_path.write_text(
        json.dumps(
            {
                "contracts": [entry],
            }
        ),
        encoding="utf-8",
    )
    return registry_path

import json
import pytest

from waveframe_guard import install_guard, guard, LegacyExecutionError
from compiler.compile_policy import compile_policy


def setup_contract():
    policy = {
        "contract_id": "t",
        "contract_version": "1.0.0",
        "authority": {"required_roles": ["manager"]},
    }
    return compile_policy(policy)


def test_formerly_allowed_execution_requires_migration():
    contract = setup_contract()

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract=contract,
    )

    @guard
    def f():
        return "ok"

    with pytest.raises(LegacyExecutionError, match="Guard.local"):
        f()


def test_blocked_execution_requires_migration():
    contract = setup_contract()

    install_guard(
        actor={"id": "u", "type": "human", "role": "intern"},
        contract=contract,
    )

    @guard
    def f():
        return "ok"

    with pytest.raises(LegacyExecutionError, match="strict execution evidence"):
        f()


def test_contract_path_execution(tmp_path):
    contract = setup_contract()
    contract_path = tmp_path / "t-1.0.0.contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract_path=contract_path,
    )

    @guard
    def f():
        return "ok"

    with pytest.raises(LegacyExecutionError, match="Guard.local"):
        f()


def test_contract_metadata_exposed():
    contract = setup_contract()

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract=contract,
    )

    from waveframe_guard.context import get_context

    assert get_context()["contract_metadata"] == {
        "contract_id": contract["contract_id"],
        "contract_version": contract["contract_version"],
        "contract_hash": contract["contract_hash"],
    }

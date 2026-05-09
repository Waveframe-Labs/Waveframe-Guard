import json
import pytest

from waveframe_guard import install_guard, guard, GovernanceError
from compiler.compile_policy import compile_policy


def setup_contract():
    policy = {
        "contract_id": "t",
        "contract_version": "0.3.1",
        "authority": {"required_roles": ["manager"]},
    }
    return compile_policy(policy)


def test_allowed_execution():
    contract = setup_contract()

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract=contract,
    )

    @guard
    def f():
        return "ok"

    assert f() == "ok"


def test_blocked_execution():
    contract = setup_contract()

    install_guard(
        actor={"id": "u", "type": "human", "role": "intern"},
        contract=contract,
    )

    @guard
    def f():
        return "ok"

    with pytest.raises(GovernanceError, match="required role not satisfied"):
        f()


def test_contract_path_execution(tmp_path):
    contract = setup_contract()
    contract_path = tmp_path / "t-0.3.1.contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract_path=contract_path,
    )

    @guard
    def f():
        return "ok"

    assert f() == "ok"


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

import pytest

from waveframe_guard import install_guard, guard, GovernanceError
from compiler.compile_policy import compile_policy


def setup_contract():
    policy = {
        "contract_id": "t",
        "contract_version": "0.3.0",
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

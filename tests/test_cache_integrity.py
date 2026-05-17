import pytest

from waveframe_guard import install_guard, guard, GovernanceError
from waveframe_guard.context import get_context
from compiler.compile_policy import compile_policy


def test_cache_tampering_detected():
    policy = {
        "contract_id": "t",
        "contract_version": "1.0.0",
        "authority": {"required_roles": ["manager"]},
    }
    contract = compile_policy(policy)

    install_guard(
        actor={"id": "u", "type": "human", "role": "manager"},
        contract=contract,
    )

    get_context()["policy_cache"]["compiled_contract"]["contract_version"] = "9.9.9"

    @guard
    def f():
        return "ok"

    with pytest.raises(GovernanceError, match="Cached policy integrity check failed"):
        f()

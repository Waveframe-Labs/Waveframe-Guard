from unittest.mock import Mock

import pytest

from waveframe_guard import install_guard, guard, LegacyExecutionError, GovernanceError
from waveframe_guard.execute import _resolve_no_policy


def test_fail_open_cannot_execute_without_policy():
    install_guard(actor=None, contract=None, mode="cloud", fail_mode="open")
    callback = Mock()
    with pytest.raises(LegacyExecutionError, match="strict execution evidence"):
        guard(callback)()
    callback.assert_not_called()


@pytest.mark.parametrize("fail_mode", ["open", "closed", "cache"])
def test_policy_resolution_failure_never_returns_fail_open_permission(fail_mode):
    with pytest.raises(GovernanceError, match="No policy available"):
        _resolve_no_policy({"fail_mode": fail_mode})

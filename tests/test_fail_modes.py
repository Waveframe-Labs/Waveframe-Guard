import pytest

from waveframe_guard import install_guard, guard


def test_fail_open_allows_execution():
    install_guard(
        actor=None,
        contract=None,
        mode="cloud",
        fail_mode="open",
    )

    @guard
    def f():
        return True

    with pytest.warns(RuntimeWarning, match="allowing execution"):
        assert f() is True

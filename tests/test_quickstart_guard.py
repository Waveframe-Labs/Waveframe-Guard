# ---
# title: "Waveframe Guard Quickstart Regression Test"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.16.1"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from __future__ import annotations

from examples import quickstart_guard


def test_quickstart_guard_blocks_before_execution(capsys):
    quickstart_guard.main()

    output = capsys.readouterr().out

    assert "executed=False" in output
    assert "decision=blocked" in output
    assert "transfer executed" not in output

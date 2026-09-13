from __future__ import annotations

import copy
import importlib.metadata

import pytest

from governance_ledger.replay import replay_admissibility


waveframe_guard = pytest.importorskip("waveframe_guard")


def test_guard_019_reports_unsupported_raw_replay_without_mutation() -> None:
    from governance_ledger.integrations.guard import GuardReplayUnsupportedError

    assert importlib.metadata.version("waveframe-guard") == "0.19.0"
    authority = _authority_contract()
    for approvals in ([], [{"role": "manager", "approved_by": "manager-1"}]):
        state = _execution_state(approvals=approvals)
        before = copy.deepcopy([authority, state])
        with pytest.raises(GuardReplayUnsupportedError, match="evaluate_admissibility is retired") as caught:
            replay_admissibility(authority_contract=authority, execution_state=state)
        assert caught.value.code == "LEDGER_GUARD_REPLAY_UNSUPPORTED"
        assert caught.value.__cause__ is None
        assert [authority, state] == before


def test_guard_019_cli_reports_unsupported_without_traceback(tmp_path) -> None:
    import json
    import subprocess
    import sys

    contract = tmp_path / "contract.json"
    state = tmp_path / "state.json"
    contract.write_text(json.dumps(_authority_contract()), encoding="utf-8")
    state.write_text(json.dumps(_execution_state(approvals=[])), encoding="utf-8")
    result = subprocess.run([sys.executable, "-m", "governance_ledger.cli",
                             "replay-execution", "--contract", str(contract),
                             "--execution-state", str(state), "--json"],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "LEDGER_GUARD_REPLAY_UNSUPPORTED" in result.stderr
    assert "store replay(run_id)" in result.stderr
    assert "Traceback" not in result.stderr
    assert not result.stdout


def _authority_contract() -> dict:
    return {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "contract_hash": "sha256:contract",
        "lineage": {
            "schema_version": "governance_authority_lineage.v1",
            "source_hash": "sha256:source",
            "compilation_report_hash": "sha256:report",
        },
        "approval_requirements": {
            "required": [
                {
                    "role": "manager",
                    "condition": {
                        "field": "amount",
                        "operator": ">",
                        "value": 1_000_000,
                    },
                }
            ]
        },
    }


def _execution_state(*, approvals: list[dict]) -> dict:
    return {
        "schema_version": "governed_execution_state.v1",
        "authority_ref": "finance-policy@0.1.0",
        "source_hash": "sha256:source",
        "compilation_report_hash": "sha256:report",
        "actor": {"id": "employee-1", "type": "human", "role": "employee"},
        "approvals": approvals,
        "action": "transfer",
        "target": "transfer",
        "arguments": {"amount": 1_250_000},
        "artifacts": [],
    }

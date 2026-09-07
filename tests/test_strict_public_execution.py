"""Issue #39: public legacy permission boundaries cannot use CRI advisory mode."""

import ast
from copy import deepcopy
import importlib
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from compiler.compile_policy import compile_policy
import cricore.api

from waveframe_guard import (
    GovernanceError, GuardRuntime, GovernedRuntime, LegacyExecutionError,
    execute, guard, install_guard, evaluate_admissibility,
)
from waveframe_guard.context import get_context
from waveframe_guard.result import GovernedExecutionResult
from tools.security.reproduce_issue39 import reproduce



def test_original_reproductions_fail_closed():
    report = reproduce()
    assert report["strict_control_allowed"] is False
    assert {"integrity", "publication"} <= set(report["strict_control_failed_stages"])
    assert report["callback_count"] == 0
    assert "execute_proposal_allowed" not in report
    assert report["runtime_allowed_events"] == 0
    for key in ("execute_error", "execute_proposal_error"):
        assert "GUARD_LEGACY_EXECUTION_UNSUPPORTED" in report[key]


@pytest.mark.parametrize("mode", ["local", "cloud"])
@pytest.mark.parametrize("fail_mode", ["open", "closed", "cache"])
@pytest.mark.parametrize("source", ["missing", "explicit", "cached", "expired", "offline"])
@pytest.mark.parametrize("decorated", [False, True])
def test_legacy_resolution_cannot_authorize(mode, fail_mode, source, decorated,
                                          monkeypatch, strict_cri, capsys):
    contract = compile_policy({"contract_id": "t", "contract_version": "1.0.0",
                               "authority": {"required_roles": ["manager"]}})
    install_guard(actor={"id": "u", "type": "human", "role": "manager"},
                  mode=mode, fail_mode=fail_mode, api_key="test-key",
                  contract=contract if source in {"cached", "expired", "offline"} else None,
                  policy_refresh=-1 if source == "expired" else 60)
    ctx = get_context()
    ctx["offline"] = source == "offline"
    before = deepcopy(ctx)
    module = importlib.import_module("waveframe_guard.execute")
    fetch = Mock(side_effect=AssertionError("legacy execution must not resolve policy"))
    send = Mock(side_effect=AssertionError("legacy execution must not send decisions"))
    monkeypatch.setattr(module, "fetch_policy", fetch)
    monkeypatch.setattr(module, "send_to_cloud_async", send)
    callback = Mock()
    with pytest.raises(LegacyExecutionError, match="cannot establish strict execution evidence") as caught:
        if decorated:
            guard(callback)()
        else:
            execute(callback, contract=contract if source == "explicit" else None)
    assert isinstance(caught.value, GovernanceError)
    assert caught.value.code == "GUARD_LEGACY_EXECUTION_UNSUPPORTED"
    assert "Guard.local()" in str(caught.value) and "Guard.cloud()" in str(caught.value)
    callback.assert_not_called()
    fetch.assert_not_called()
    send.assert_not_called()
    assert strict_cri == []  # No placeholder integrity/publication inputs, no evaluation.
    assert ctx == before
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("runtime_class", [GovernedRuntime, GuardRuntime])
@pytest.mark.parametrize("method", ["execute", "execute_proposal", "evaluate", "revalidate"])
@pytest.mark.parametrize("raise_on_block", [False, True])
@pytest.mark.parametrize("approval_required", [False, True])
def test_all_legacy_runtime_permission_paths_reject_before_effects(
        tmp_path, monkeypatch, strict_cri, runtime_class, method, raise_on_block, approval_required):
    contract = compile_policy({"contract_id": "t", "contract_version": "1.0.0",
                               "authority": {"required_roles": ["manager"]}})
    if approval_required:
        contract["approval_requirements"] = {"required": [{"role": "manager"}]}
    (tmp_path / "contract.json").write_text(json.dumps(contract), encoding="utf-8")
    registry = tmp_path / "index.json"
    registry.write_text(json.dumps({"contracts": [{"contract_id": "t",
                        "contract_version": "1.0.0", "path": "contract.json"}]}), encoding="utf-8")
    runtime = runtime_class(registry_path=registry, audit_path=tmp_path / "audit.jsonl",
                            evidence_dir=tmp_path / "evidence", runtime_log_path=tmp_path / "runtime.jsonl")
    runtime.bind_contract("t@1.0.0").install_actor({"id": "u", "type": "human", "role": "manager"})
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    resolve = Mock(side_effect=AssertionError("must reject before authority resolution"))
    monkeypatch.setattr(runtime, "_resolve_authority_entry", resolve)
    callback = Mock()
    with pytest.raises(LegacyExecutionError):
        if method == "execute":
            runtime.execute(fn=callback, approvals=[{"role": "manager", "approved_by": "reviewer"}],
                            raise_on_block=raise_on_block)
        elif method == "execute_proposal":
            runtime.execute_proposal({"proposal_id": "issue39"}, raise_on_block=raise_on_block)
        elif method == "evaluate":
            runtime.evaluate(fn=callback)
        else:
            runtime.revalidate(GovernedExecutionResult(allowed=True, reason="old advisory decision"))
    callback.assert_not_called()
    resolve.assert_not_called()
    assert strict_cri == []
    assert runtime.audit_events == [] and runtime.runtime_logs == []
    assert runtime.last_event is None
    assert runtime._evidence_counts() == {"pending": 0, "sent": 0, "failed": 0}
    assert before == {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("evidence", [None, {}, {"integrity": {}, "publication": {}},
                                      {"integrity": {"verified": True}, "publication": {"published": True}}])
def test_untrusted_or_missing_prerequisites_cannot_reenable_execution(evidence, strict_cri):
    callback = Mock()
    contract = {"contract_id": "t", "contract_version": "1.0.0", "contract_hash": "untrusted"}
    if evidence is not None:
        contract.update(deepcopy(evidence))
    before = deepcopy(contract)
    with pytest.raises(LegacyExecutionError):
        execute(callback, contract=contract)
    with pytest.raises(LegacyExecutionError):
        evaluate_admissibility(contract, {"approvals": []})
    callback.assert_not_called()
    assert strict_cri == [] and contract == before


def test_active_guard_surface_has_no_cri_execution_calls():
    """The migration removes both calls; fail if an alias/module call returns.

    Any future CRI integration requires explicit strict mode and matching context
    plus trusted prerequisites, and must deliberately update this inventory test.
    """
    root = Path(__file__).resolve().parents[1]
    violations = []
    for package in ("guard", "waveframe_guard"):
        for path in (root / package).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if any(alias.name in {"evaluate_structured", "run_execution_pipeline"} for alias in node.names):
                        violations.append((path.name, node.lineno))
                if isinstance(node, ast.Attribute) and node.attr in {"evaluate_structured", "run_execution_pipeline"}:
                    violations.append((path.name, node.lineno))
    assert violations == []

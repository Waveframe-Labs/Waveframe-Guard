import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from compiler.compile_policy import compile_policy

from waveframe_guard import GovernanceError, GovernedRuntime


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


def test_runtime_allows_authorized_actor(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    assert runtime.execute(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        fn=transfer,
        args=(125,),
    ) == "transferred 125"


def test_runtime_blocks_unauthorized_actor(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    with pytest.raises(GovernanceError, match="required role not satisfied"):
        runtime.execute(
            actor={"id": "user-1", "type": "human", "role": "intern"},
            contract_id="finance-policy@1.0.0",
            fn=transfer,
            args=(1250000,),
        )


def test_runtime_rejects_revoked_authority_before_execution(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, status="revoked")
    runtime = GovernedRuntime(registry_path=registry_path)
    called = False

    def transfer(amount):
        nonlocal called
        called = True
        return f"transferred {amount}"

    with patch("waveframe_guard.runtime._evaluate_approval_admissibility") as admissibility:
        with pytest.raises(
            GovernanceError,
            match="Authority lifecycle invalidated: finance-policy@1.0.0 is revoked",
        ):
            runtime.execute(
                actor={"id": "user-1", "type": "human", "role": "manager"},
                contract_id="finance-policy@1.0.0",
                fn=transfer,
                args=(125,),
                raise_on_block=False,
            )

    assert called is False
    admissibility.assert_not_called()
    assert runtime.last_authority_lifecycle == {
        "authority_ref": "finance-policy@1.0.0",
        "status": "revoked",
    }
    assert runtime.runtime_logs[-1]["event_type"] == "revoked_authority_rejected"
    assert runtime.runtime_logs[-1]["authority_ref"] == "finance-policy@1.0.0"
    assert runtime.last_event is None
    assert runtime.last_contract_source is None


def test_runtime_warns_on_superseded_authority_and_records_metadata(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(
        tmp_path,
        contract_path,
        status="superseded",
        superseded_by="finance-policy@1.1.0",
    )
    runtime = GovernedRuntime(registry_path=registry_path)

    def transfer(amount):
        return f"transferred {amount}"

    with pytest.warns(RuntimeWarning, match="finance-policy@1.0.0 is superseded"):
        result = runtime.execute(
            actor={"id": "user-1", "type": "human", "role": "manager"},
            contract_id="finance-policy@1.0.0",
            fn=transfer,
            args=(125,),
            raise_on_block=False,
        )

    assert result.allowed is True
    assert result.authority_lifecycle == {
        "authority_ref": "finance-policy@1.0.0",
        "status": "superseded",
        "superseded_by": "finance-policy@1.1.0",
    }
    assert result.event["authority_lifecycle"] == result.authority_lifecycle


def test_runtime_evaluate_records_admissibility_window(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, admissibility_window_seconds=30)
    runtime = GovernedRuntime(registry_path=registry_path)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    decision = runtime.evaluate(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        target="transfer",
        args=(125,),
        now=now,
    )

    assert decision.valid_until == (now + timedelta(seconds=30)).isoformat()
    assert decision.revalidation_required_after == decision.valid_until
    assert decision.continuity_signals == []


def test_runtime_emits_validity_window_expiration_signal(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, admissibility_window_seconds=1)
    runtime = GovernedRuntime(registry_path=registry_path)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    decision = runtime.evaluate(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        target="transfer",
        args=(125,),
        now=now,
    )

    continuity = runtime.revalidate(decision, now=now + timedelta(seconds=2))

    assert continuity.allowed is True
    assert continuity.continuity_signals == [
        "ADMISSIBILITY_WINDOW_EXPIRED",
        "REVALIDATION_REQUIRED",
    ]


def test_runtime_detects_revoked_authority_after_delay(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, admissibility_window_seconds=60)
    runtime = GovernedRuntime(registry_path=registry_path)
    decision = runtime.evaluate(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        target="transfer",
        args=(125,),
    )
    runtime.registry["contracts"][0]["status"] = "revoked"

    continuity = runtime.revalidate(decision)

    assert continuity.continuity_signals == [
        "AUTHORITY_REVOKED_POST_DECISION",
        "REVALIDATION_REQUIRED",
    ]


def test_runtime_detects_superseded_authority_during_resumed_execution(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, admissibility_window_seconds=60)
    runtime = GovernedRuntime(registry_path=registry_path)
    decision = runtime.evaluate(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        target="transfer",
        args=(125,),
    )
    runtime.registry["contracts"][0]["status"] = "superseded"
    runtime.registry["contracts"][0]["superseded_by"] = "finance-policy@1.1.0"

    continuity = runtime.revalidate(decision)

    assert continuity.continuity_signals == [
        "AUTHORITY_SUPERSEDED_DURING_EXECUTION",
        "REVALIDATION_REQUIRED",
    ]


def test_runtime_detects_actor_continuity_break(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path, admissibility_window_seconds=60)
    runtime = GovernedRuntime(registry_path=registry_path)
    decision = runtime.evaluate(
        actor={"id": "user-1", "type": "human", "role": "manager"},
        contract_id="finance-policy@1.0.0",
        target="transfer",
        args=(125,),
    )

    continuity = runtime.revalidate(
        decision,
        actor={"id": "user-2", "type": "human", "role": "manager"},
    )

    assert continuity.continuity_signals == [
        "ACTOR_CONTINUITY_BROKEN",
        "REVALIDATION_REQUIRED",
    ]


def test_runtime_raises_for_unknown_contract(tmp_path):
    contract_path = write_contract(tmp_path)
    registry_path = write_registry(tmp_path, contract_path)
    runtime = GovernedRuntime(registry_path=registry_path)

    with pytest.raises(KeyError, match="Unknown contract"):
        runtime.execute(
            actor={"id": "user-1", "type": "human", "role": "manager"},
            contract_id="missing-policy@1.0.0",
            fn=lambda: "ok",
        )

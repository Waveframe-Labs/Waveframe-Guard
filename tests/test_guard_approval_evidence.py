from __future__ import annotations

import json
from pathlib import Path


from waveframe_guard import GovernanceError, GovernedRuntime
from waveframe_guard.schemas import (
    GOVERNED_EXECUTION_EVENT_V1,
    GOVERNED_EXECUTION_RESULT_V1,
    GOVERNED_EXECUTION_STATE_V1,
)


def transfer(amount: int) -> str:
    return f"Transferred ${amount}"


def test_guard_blocks_until_required_approval_evidence_is_present(tmp_path):
    contract = _compiled_contract()
    registry_path = _write_registry(tmp_path, contract)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester-1", "type": "human", "role": "employee"})

    blocked = runtime.execute(
        fn=transfer,
        args=(12_500,),
        approvals=[{"role": "manager", "approved_by": "manager-1"}],
        raise_on_block=False,
    )

    assert blocked.allowed is False
    assert blocked.reason == "required approval missing: director"
    assert blocked.decision_trace["schema_version"] == "governed_decision_trace.v1"
    assert blocked.decision_trace["satisfied_approvals"] == [
        {"role": "manager", "approved_by": "manager-1"}
    ]
    assert blocked.decision_trace["missing_approvals"] == [
        {
            "role": "director",
            "condition": {
                "field": "amount",
                "operator": ">",
                "value": 10000,
            },
        }
    ]
    assert blocked.decision_trace["conditions_triggered"] == [
        {
            "field": "amount",
            "operator": ">",
            "value": 10000,
        }
    ]
    assert blocked.missing_approvals == [
        {
            "role": "director",
            "condition": {
                "field": "amount",
                "operator": ">",
                "value": 10000,
            },
        }
    ]

    allowed = runtime.execute(
        fn=transfer,
        args=(12_500,),
        approvals=[
            {"role": "manager", "approved_by": "manager-1"},
            {"role": "director", "approved_by": "director-1"},
        ],
        raise_on_block=False,
    )

    assert allowed.allowed is True
    assert allowed.value == "Transferred $12500"
    assert allowed.event["approvals"][1]["role"] == "director"
    assert allowed.execution_state["schema_version"] == GOVERNED_EXECUTION_STATE_V1
    assert allowed.execution_state["actor"]["id"] == "requester-1"
    assert allowed.execution_state["authority_ref"] == "finance-policy@1.0.0"
    assert allowed.event["execution_state"] == allowed.execution_state
    assert allowed.event["schema_version"] == GOVERNED_EXECUTION_EVENT_V1
    assert allowed.to_dict() == {
        "schema_version": GOVERNED_EXECUTION_RESULT_V1,
        "decision": "ALLOWED",
        "allowed": True,
        "reason": "execution allowed",
        "missing_approvals": [],
        "authority_ref": "finance-policy@1.0.0",
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": contract["contract_hash"],
        "source_hash": None,
        "compilation_report_hash": None,
        "execution_state": allowed.execution_state,
        "decision_trace": allowed.decision_trace,
        "event_id": allowed.event["event_id"],
        "event_hash": None,
    }


def test_guard_enforces_approval_separation_of_duties(tmp_path):
    contract = _compiled_contract()
    registry_path = _write_registry(tmp_path, contract)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester-1", "type": "human", "role": "employee"})

    blocked = runtime.execute(
        fn=transfer,
        args=(500,),
        approvals=[{"role": "manager", "approved_by": "requester-1"}],
        raise_on_block=False,
    )

    assert blocked.allowed is False
    assert blocked.reason == "separation of duties violated: requester approved own transfer"
    assert blocked.execution_state["approvals"] == [
        {"role": "manager", "approved_by": "requester-1"}
    ]


def test_guard_rejects_same_approver_for_distinct_required_roles(tmp_path):
    contract = _compiled_contract()
    registry_path = _write_registry(tmp_path, contract)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester-1", "type": "human", "role": "employee"})

    blocked = runtime.execute(
        fn=transfer,
        args=(12_500,),
        approvals=[
            {"role": "manager", "approved_by": "approver-1"},
            {"role": "director", "approved_by": "approver-1"},
        ],
        raise_on_block=False,
    )

    assert blocked.allowed is False
    assert (
        blocked.reason
        == "approval identity reused across required roles: approver-1 satisfied director, manager"
    )
    assert blocked.missing_approvals == []


def test_guard_rejects_malformed_approval_evidence(tmp_path):
    contract = _compiled_contract()
    registry_path = _write_registry(tmp_path, contract)
    runtime = GovernedRuntime(registry_path=registry_path)
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester-1", "type": "human", "role": "employee"})

    blocked = runtime.execute(
        fn=transfer,
        args=(500,),
        approvals=[{"role": "manager"}],
        raise_on_block=False,
    )

    assert blocked.allowed is False
    assert blocked.reason == "invalid approval evidence: approved_by is required"


def test_guard_can_require_verified_authority_lineage(tmp_path):
    contract = _compiled_contract()
    registry_path = _write_registry(tmp_path, contract)
    runtime = GovernedRuntime(registry_path=registry_path, require_verified_lineage=True)
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester-1", "type": "human", "role": "employee"})

    try:
        runtime.execute(
            fn=transfer,
            args=(500,),
            approvals=[{"role": "manager", "approved_by": "manager-1"}],
            raise_on_block=False,
        )
    except GovernanceError as exc:
        assert str(exc) == "Authority provenance verification failed: missing lineage"
    else:
        raise AssertionError("expected provenance-gated execution to fail closed")


def _compiled_contract():
    contract = {
        "contract_id": "finance-policy",
        "contract_version": "1.0.0",
        "contract_hash": None,
        "authority_requirements": {
            "required_roles": ["manager", "director"],
        },
        "approval_requirements": {
            "required": [
                {"role": "manager"},
                {
                    "role": "director",
                    "condition": {
                        "field": "amount",
                        "operator": ">",
                        "value": 10000,
                    },
                },
            ],
        },
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {
            "separation_of_duties": True,
        },
    }
    contract["contract_hash"] = _compute_contract_hash(contract)
    return contract


def _compute_contract_hash(contract: dict) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    import hashlib

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _write_registry(root: Path, contract: dict) -> Path:
    contracts_dir = root / "contracts"
    contracts_dir.mkdir()
    contract_path = contracts_dir / "finance-policy-1.0.0.contract.json"
    contract_path.write_text(json.dumps(contract, indent=2, sort_keys=True), encoding="utf-8")
    registry = {
        "contracts": [
            {
                "contract_id": "finance-policy",
                "contract_version": "1.0.0",
                "contract_hash": f"sha256:{contract['contract_hash']}",
                "path": str(contract_path),
            }
        ]
    }
    registry_path = contracts_dir / "index.json"
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    return registry_path

from __future__ import annotations

import json
from pathlib import Path


from waveframe_guard import GovernanceError, GovernedRuntime
from waveframe_guard import LegacyExecutionError
import pytest


@pytest.mark.parametrize("approvals", [[], [{"role": "manager", "approved_by": "reviewer"}],
    [{"role": "manager", "approved_by": "m"}, {"role": "director", "approved_by": "d"}]])
@pytest.mark.parametrize("amount", [500, 12500])
def test_approval_only_legacy_branch_cannot_invoke_callback(tmp_path, approvals, amount):
    runtime = GovernedRuntime(registry_path=_write_registry(tmp_path, _compiled_contract()))
    runtime.bind_contract("finance-policy@1.0.0")
    runtime.install_actor({"id": "requester", "type": "human", "role": "employee"})
    calls = []
    with pytest.raises(LegacyExecutionError):
        runtime.execute(fn=lambda value: calls.append(value), args=(amount,),
                        approvals=approvals, raise_on_block=False)
    assert calls == [] and runtime.audit_events == [] and runtime.runtime_logs == []


def test_legacy_lineage_reader_still_validates_missing_lineage(tmp_path):
    contract = _compiled_contract()
    runtime = GovernedRuntime(registry_path=_write_registry(tmp_path, contract), require_verified_lineage=True)
    with pytest.raises(GovernanceError, match="missing lineage"):
        runtime._enforce_authority_lineage(contract)
from waveframe_guard.schemas import (
    GOVERNED_EXECUTION_EVENT_V1,
    GOVERNED_EXECUTION_RESULT_V1,
    GOVERNED_EXECUTION_STATE_V1,
)


def transfer(amount: int) -> str:
    return f"Transferred ${amount}"


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

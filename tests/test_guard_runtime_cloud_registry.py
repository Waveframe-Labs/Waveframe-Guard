from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server


REPO_ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_PATHS = [
    REPO_ROOT / "integrations" / "contract-compiler" / "src",
    REPO_ROOT / "integrations" / "guard",
    REPO_ROOT / "integrations" / "proposal-normalizer",
    REPO_ROOT / "integrations" / "cricore" / "src",
]

for path in INTEGRATION_PATHS:
    sys.path.insert(0, str(path))

from cloud.api.app import create_app
from compiler.compile_policy import compile_policy
from waveframe_guard import GovernedRuntime


def transfer(amount: int) -> str:
    return f"Transferred ${amount}"


def seed_cloud_data(data_root):
    policy = {
        "contract_id": "finance-policy",
        "contract_version": "0.1.0",
        "authority": {
            "required_roles": ["manager"],
        },
    }
    contract = compile_policy(policy)
    contracts_dir = data_root / "contracts"
    contracts_dir.mkdir(parents=True)
    contract_path = contracts_dir / "finance-policy-0.1.0.contract.json"
    contract_path.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (contracts_dir / "index.json").write_text(
        json.dumps(
            {
                "contracts": [
                    {
                        "contract_id": contract["contract_id"],
                        "contract_version": contract["contract_version"],
                        "contract_hash": f"sha256:{contract['contract_hash']}",
                        "path": "contracts/finance-policy-0.1.0.contract.json",
                    }
                ]
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return contract


def serve_cloud(data_root):
    app = create_app(data_root=data_root)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def test_governed_runtime_fetches_contract_from_cloud_and_enforces_locally(tmp_path):
    contract = seed_cloud_data(tmp_path / "cloud-data")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")
    cache_dir = tmp_path / "guard-cache"

    try:
        runtime = GovernedRuntime(
            registry_url=registry_url,
            cache_dir=cache_dir,
        )
        runtime.bind_contract("finance-policy", "0.1.0")

        runtime.install_actor(
            {
                "id": "user-1",
                "type": "human",
                "role": "intern",
            }
        )
        blocked = runtime.execute(
            fn=transfer,
            args=(1_250_000,),
            raise_on_block=False,
        )

        runtime.install_actor(
            {
                "id": "manager-1",
                "type": "human",
                "role": "manager",
            }
        )
        allowed = runtime.execute(
            fn=transfer,
            args=(1_250_000,),
            raise_on_block=False,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert blocked.allowed is False
    assert blocked.reason == "required role not satisfied: manager"
    assert blocked.event["schema_version"] == "governed_execution.v1"
    assert blocked.event["authority_ref"] == "finance-policy@0.1.0"
    assert blocked.event["contract_ref"] == "finance-policy@0.1.0"
    assert blocked.event["decision"] == "BLOCKED"
    assert blocked.event["contract_source"] == "registry_url"
    assert blocked.audit_receipt == blocked.event["audit_receipt"]
    assert blocked.audit_receipt["status"] == "accepted"
    assert blocked.audit_receipt["event_id"] == blocked.event["event_id"]
    assert blocked.audit_receipt["authority_ref"] == "finance-policy@0.1.0"
    assert blocked.audit_receipt["event_hash"].startswith("sha256:")
    assert blocked.audit_receipt["received_at"]
    assert blocked.audit_receipt["path"] == "audits/governed-execution.jsonl"
    assert allowed.allowed is True
    assert allowed.value == "Transferred $1250000"
    assert allowed.event["decision"] == "ALLOWED"
    assert allowed.audit_receipt["status"] == "accepted"

    cached_contracts = list(cache_dir.glob("*.contract.json"))
    assert len(cached_contracts) == 1
    assert json.loads(cached_contracts[0].read_text(encoding="utf-8")) == contract
    assert (cache_dir / "registry-index.json").exists()
    cached_registry = json.loads((cache_dir / "registry-index.json").read_text(encoding="utf-8"))
    assert cached_registry["registry_hash"].startswith("sha256:")

    audit_lines = (
        tmp_path / "cloud-data" / "audits" / "governed-execution.jsonl"
    ).read_text(encoding="utf-8").splitlines()
    assert len(audit_lines) == 2
    assert json.loads(audit_lines[0])["allowed"] is False
    assert json.loads(audit_lines[1])["allowed"] is True
    audit_index = json.loads(
        (tmp_path / "cloud-data" / "audits" / "audit-index.json").read_text(encoding="utf-8")
    )
    assert audit_index["schema_version"] == "audit_index.v1"
    assert audit_index["event_count"] == 2
    assert audit_index["events"][0]["event_hash"].startswith("sha256:")

    offline_runtime = GovernedRuntime(
        registry_url=registry_url,
        cache_dir=cache_dir,
        offline=True,
    )
    offline_runtime.bind_contract("finance-policy", "0.1.0")
    offline_runtime.install_actor(
        {
            "id": "manager-1",
            "type": "human",
            "role": "manager",
        }
    )
    offline_allowed = offline_runtime.execute(
        fn=transfer,
        args=(1_250_000,),
        raise_on_block=False,
    )
    assert offline_allowed.allowed is True
    assert offline_allowed.event["contract_source"] == "cache"


def test_governed_runtime_rejects_ambiguous_contract_binding(tmp_path):
    contract = seed_cloud_data(tmp_path / "cloud-data")
    contracts_dir = tmp_path / "cloud-data" / "contracts"
    second = compile_policy(
        {
            "contract_id": "finance-policy",
            "contract_version": "0.2.0",
            "authority": {
                "required_roles": ["director"],
            },
        }
    )
    (contracts_dir / "finance-policy-0.2.0.contract.json").write_text(
        json.dumps(second, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    registry_path = contracts_dir / "index.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["contracts"].append(
        {
            "contract_id": second["contract_id"],
            "contract_version": second["contract_version"],
            "contract_hash": f"sha256:{second['contract_hash']}",
            "path": "contracts/finance-policy-0.2.0.contract.json",
        }
    )
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")

    try:
        runtime = GovernedRuntime(registry_url=registry_url, cache_dir=tmp_path / "guard-cache")
        runtime.bind_contract("finance-policy")
        runtime.install_actor({"id": "manager-1", "type": "human", "role": "manager"})
        try:
            runtime.execute(fn=transfer, args=(1_250_000,), raise_on_block=False)
        except ValueError as exc:
            assert "Missing contract_version" in str(exc)
        else:
            raise AssertionError("ambiguous contract binding should fail")
    finally:
        server.shutdown()
        server.server_close()


def test_governed_runtime_rejects_cached_hash_mismatch(tmp_path):
    contract = seed_cloud_data(tmp_path / "cloud-data")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")
    cache_dir = tmp_path / "guard-cache"

    try:
        runtime = GovernedRuntime(registry_url=registry_url, cache_dir=cache_dir)
        runtime.bind_contract("finance-policy@0.1.0")
        runtime.install_actor({"id": "manager-1", "type": "human", "role": "manager"})
        runtime.execute(fn=transfer, args=(1_250_000,), raise_on_block=False)
    finally:
        server.shutdown()
        server.server_close()

    cached_contract = next(cache_dir.glob("*.contract.json"))
    mutated = json.loads(cached_contract.read_text(encoding="utf-8"))
    mutated["authority_requirements"]["required_roles"] = ["director"]
    cached_contract.write_text(json.dumps(mutated), encoding="utf-8")

    offline_runtime = GovernedRuntime(registry_url=registry_url, cache_dir=cache_dir, offline=True)
    offline_runtime.bind_contract("finance-policy@0.1.0")
    offline_runtime.install_actor({"id": "manager-1", "type": "human", "role": "manager"})
    try:
        offline_runtime.execute(fn=transfer, args=(1_250_000,), raise_on_block=False)
    except Exception as exc:
        assert "hash mismatch" in str(exc)
    else:
        raise AssertionError("mutated cached contract should fail integrity validation")


def test_governed_runtime_rejects_cached_registry_hash_mismatch(tmp_path):
    seed_cloud_data(tmp_path / "cloud-data")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")
    cache_dir = tmp_path / "guard-cache"

    try:
        runtime = GovernedRuntime(registry_url=registry_url, cache_dir=cache_dir)
        runtime.bind_contract("finance-policy@0.1.0")
        runtime.install_actor({"id": "manager-1", "type": "human", "role": "manager"})
        runtime.execute(fn=transfer, args=(1_250_000,), raise_on_block=False)
    finally:
        server.shutdown()
        server.server_close()

    cached_registry_path = cache_dir / "registry-index.json"
    cached_registry = json.loads(cached_registry_path.read_text(encoding="utf-8"))
    cached_registry["contracts"][0]["path"] = "contracts/tampered.contract.json"
    cached_registry_path.write_text(json.dumps(cached_registry), encoding="utf-8")

    try:
        GovernedRuntime(registry_url=registry_url, cache_dir=cache_dir, offline=True)
    except Exception as exc:
        assert "Registry hash mismatch" in str(exc)
    else:
        raise AssertionError("mutated cached registry should fail integrity validation")

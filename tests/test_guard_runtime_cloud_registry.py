from __future__ import annotations

import json
import threading
from pathlib import Path
from wsgiref.simple_server import make_server


from compiler.compile_policy import compile_policy
from waveframe_guard import GuardRuntime, GovernedRuntime


def transfer(amount: int) -> str:
    return f"Transferred ${amount}"


def seed_cloud_data(data_root):
    policy = {
        "contract_id": "finance-policy",
            "contract_version": "1.0.0",
        "authority": {
            "required_roles": ["manager"],
        },
    }
    contract = compile_policy(policy)
    contracts_dir = data_root / "contracts"
    contracts_dir.mkdir(parents=True)
    contract_path = contracts_dir / "finance-policy-1.0.0.contract.json"
    contract_path.write_text(
        json.dumps(contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    registry = {
        "contracts": [
            {
                "contract_id": contract["contract_id"],
                "contract_version": contract["contract_version"],
                "contract_hash": f"sha256:{contract['contract_hash']}",
                "path": "contracts/finance-policy-1.0.0.contract.json",
            }
        ]
    }
    registry["registry_hash"] = _registry_hash(registry)
    (contracts_dir / "index.json").write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return contract


def serve_cloud(data_root, state=None):
    app = _registry_app(data_root, state=state)
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _registry_app(data_root, state=None):
    data_root = Path(data_root)
    state = state or {"audit_available": True}

    def app(environ, start_response):
        method = environ["REQUEST_METHOD"]
        path = environ["PATH_INFO"].strip("/")
        if method == "GET" and path == "registry/index.json":
            return _json_response(start_response, _read_json(data_root / "contracts" / "index.json"))
        if method == "GET" and path.startswith("contracts/"):
            _, contract_id, version = path.split("/", 2)
            contract_path = data_root / "contracts" / f"{contract_id}-{version}.contract.json"
            return _json_response(start_response, _read_json(contract_path))
        if method == "POST" and path == "audit-events":
            if not state.get("audit_available", True):
                start_response("503 Service Unavailable", [("Content-Type", "application/json")])
                return [b'{"error":"audit unavailable"}']
            length = int(environ.get("CONTENT_LENGTH") or "0")
            body = environ["wsgi.input"].read(length)
            event = json.loads(body.decode("utf-8"))
            receipt = _write_audit_event(data_root, event)
            return _json_response(start_response, receipt)
        start_response("404 Not Found", [("Content-Type", "application/json")])
        return [b'{"error":"not found"}']

    return app


def _json_response(start_response, payload):
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [body]


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_audit_event(data_root, event):
    audits_dir = data_root / "audits"
    audits_dir.mkdir(parents=True, exist_ok=True)
    event_hash = _json_hash(event)
    receipt = {
        "status": "accepted",
        "event_id": event["event_id"],
        "authority_ref": event["authority_ref"],
        "event_hash": event_hash,
        "received_at": "2026-05-17T00:00:00+00:00",
        "path": "audits/governed-execution.jsonl",
    }
    audit_path = audits_dir / "governed-execution.jsonl"
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")

    events = []
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            stored = json.loads(line)
            events.append(
                {
                    "event_id": stored["event_id"],
                    "event_hash": _json_hash(stored),
                }
            )
    (audits_dir / "audit-index.json").write_text(
        json.dumps(
            {
                "schema_version": "audit_index.v1",
                "event_count": len(events),
                "events": events,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return receipt


def _json_hash(payload):
    import hashlib

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _registry_hash(registry):
    canonical_registry = {
        key: value
        for key, value in registry.items()
        if key != "registry_hash"
    }
    return _json_hash(canonical_registry)


def test_governed_runtime_fetches_contract_from_cloud_and_enforces_locally(tmp_path):
    contract = seed_cloud_data(tmp_path / "cloud-data")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")
    cache_dir = tmp_path / "guard-cache"

    try:
        runtime = GovernedRuntime(
            registry_url=registry_url,
            cache_dir=cache_dir,
        )
        runtime.bind_contract("finance-policy@1.0.0")

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
    assert blocked.event["authority_ref"] == "finance-policy@1.0.0"
    assert blocked.event["contract_ref"] == "finance-policy@1.0.0"
    assert blocked.event["decision"] == "BLOCKED"
    assert blocked.event["contract_source"] == "registry_url"
    assert blocked.audit_receipt == blocked.event["audit_receipt"]
    assert blocked.audit_receipt["status"] == "accepted"
    assert blocked.audit_receipt["event_id"] == blocked.event["event_id"]
    assert blocked.audit_receipt["authority_ref"] == "finance-policy@1.0.0"
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
    offline_runtime.bind_contract("finance-policy@1.0.0")
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


def test_guard_runtime_from_cloud_spools_evidence_until_explicit_flush(tmp_path):
    seed_cloud_data(tmp_path / "cloud-data")
    state = {"audit_available": True}
    server, registry_url = serve_cloud(tmp_path / "cloud-data", state=state)
    evidence_dir = tmp_path / "guard-evidence"

    try:
        runtime = GuardRuntime.from_cloud(
            authority="finance-policy@1.0.0",
            api_key="test-key",
            base_url=registry_url,
            cache_dir=tmp_path / "guard-cache",
            evidence_dir=evidence_dir,
            actor={"id": "manager-1", "type": "human", "role": "manager"},
        )

        result = runtime.execute(
            fn=transfer,
            args=(1_250_000,),
            raise_on_block=False,
        )
        assert result.allowed is True
        assert result.audit_receipt is None
        assert runtime._evidence_counts() == {"pending": 1, "sent": 0, "failed": 0}
        assert not (tmp_path / "cloud-data" / "audits").exists()

        state["audit_available"] = False
        assert runtime.flush_evidence() == {"pending": 0, "sent": 0, "failed": 1}
        failed_payload = json.loads(next((evidence_dir / "failed").glob("*.json")).read_text(encoding="utf-8"))
        assert failed_payload["event_id"] == result.event["event_id"]
        assert failed_payload["flush_error"]

        state["audit_available"] = True
        assert runtime.flush_evidence() == {"pending": 0, "sent": 1, "failed": 0}
        sent_payload = json.loads(next((evidence_dir / "sent").glob("*.json")).read_text(encoding="utf-8"))
        assert sent_payload["audit_receipt"]["status"] == "accepted"

        runtime_log_types = [event["event_type"] for event in runtime.runtime_logs]
        assert "authority_resolution_started" in runtime_log_types
        assert "authority_resolution_completed" in runtime_log_types
        assert "admissibility_evaluation_started" in runtime_log_types
        assert "admissibility_evaluation_completed" in runtime_log_types
    finally:
        server.shutdown()
        server.server_close()


def test_governed_runtime_rejects_unversioned_contract_binding(tmp_path):
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
    registry["registry_hash"] = _registry_hash(registry)
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")

    try:
        runtime = GovernedRuntime(registry_url=registry_url, cache_dir=tmp_path / "guard-cache")
        unversioned_authority_ref = "finance-policy"
        runtime.bind_contract(unversioned_authority_ref)
        runtime.install_actor({"id": "manager-1", "type": "human", "role": "manager"})
        try:
            runtime.execute(fn=transfer, args=(1_250_000,), raise_on_block=False)
        except ValueError as exc:
            assert "Missing contract_version" in str(exc)
        else:
            raise AssertionError("unversioned contract binding should fail")
    finally:
        server.shutdown()
        server.server_close()


def test_governed_runtime_rejects_cached_hash_mismatch(tmp_path):
    contract = seed_cloud_data(tmp_path / "cloud-data")
    server, registry_url = serve_cloud(tmp_path / "cloud-data")
    cache_dir = tmp_path / "guard-cache"

    try:
        runtime = GovernedRuntime(registry_url=registry_url, cache_dir=cache_dir)
        runtime.bind_contract("finance-policy@1.0.0")
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
    offline_runtime.bind_contract("finance-policy@1.0.0")
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
        runtime.bind_contract("finance-policy@1.0.0")
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

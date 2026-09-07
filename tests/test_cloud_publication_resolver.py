from __future__ import annotations

import copy
import os
import gzip
import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from waveframe_guard.cloud import (
    CloudAuthorityClient,
    CloudAuthorityFetchError,
    CloudPublicationProtocolError,
    CloudPublicationUnavailable,
    parse_cloud_authority_publication,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cloud_authority_publication.v1.json"
AUTHORITY_REF = "repository-authority@1.0.0"
ORGANIZATION_ID = "example-organization"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _canonical_hash(payload) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _rehash(payload: dict, *, registry: bool = True) -> dict:
    if registry:
        payload["registry_entry_hash"] = _canonical_hash(payload["registry_entry"])
    payload["envelope_hash"] = _canonical_hash(
        {key: value for key, value in payload.items() if key != "envelope_hash"}
    )
    return payload


def test_cloud_publication_protocol_accepts_matching_v3_envelope() -> None:
    payload = _fixture()
    payload["authority_bundle"]["schema_version"] = "authority_bundle.v3"
    payload["publication_receipt"]["schema_version"] = "publication_receipt.v3"
    _rehash(payload)
    parsed = parse_cloud_authority_publication(
        payload,
        requested_authority_ref=AUTHORITY_REF,
        expected_organization_id=ORGANIZATION_ID,
    )
    assert parsed.authority_bundle["schema_version"] == "authority_bundle.v3"
    assert parsed.publication_receipt["schema_version"] == "publication_receipt.v3"


def test_cloud_publication_protocol_rejects_cross_version_v3_envelope() -> None:
    payload = _fixture()
    payload["authority_bundle"]["schema_version"] = "authority_bundle.v3"
    _rehash(payload)
    with pytest.raises(CloudPublicationProtocolError, match="versions do not match"):
        parse_cloud_authority_publication(
            payload,
            requested_authority_ref=AUTHORITY_REF,
            expected_organization_id=ORGANIZATION_ID,
        )


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        state = self.server.state
        state.setdefault("requests", []).append(
            {"method": "GET", "path": self.path, "headers": dict(self.headers)}
        )
        if self.path.startswith("/v1/authorities/"):
            if state.get("delay"):
                time.sleep(state["delay"])
            self._respond(
                state.get("publication_status", 200),
                state.get("publication_body", json.dumps(_fixture()).encode("utf-8")),
                state.get("publication_headers", {"Content-Type": "application/json"}),
            )
            return
        if self.path.startswith("/v1/contracts/"):
            self._respond(
                state.get("legacy_status", 200),
                state.get("legacy_body", json.dumps(_v1_contract()).encode("utf-8")),
                {"Content-Type": "application/json"},
            )
            return
        self._respond(404, b'{"error":"not found"}', {"Content-Type": "application/json"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length:
            self.rfile.read(length)
        self.server.state.setdefault("requests", []).append(
            {"method": "POST", "path": self.path, "headers": dict(self.headers)}
        )
        self._respond(200, b'{"ok":true}', {"Content-Type": "application/json"})

    def _respond(self, status: int, body: bytes, headers: dict[str, str]):
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _serve(state=None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.state = state or {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _v1_contract():
    contract = {
        "schema_version": "compiled_authority_contract.v1",
        "contract_id": "repository-authority",
        "contract_version": "1.0.0",
        "authority_requirements": {"required_roles": ["repository-maintainer"]},
        "approval_requirements": {},
        "artifact_requirements": {},
        "stage_requirements": {},
        "invariants": {},
    }
    contract["contract_hash"] = _canonical_hash(contract)
    return contract


def _cloud_guard(tmp_path, base_url, **kwargs):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "README.md").write_bytes(b"original")
    return Guard.cloud(
        repository_root=tmp_path,
        authority=AUTHORITY_REF,
        workspace=tmp_path,
        cloud_url=base_url,
        cloud_organization_id=ORGANIZATION_ID,
        cloud_api_key="runtime-secret",
        runtime_id="repository-runtime",
        actor_identity={
            "id": "repository-agent",
            "type": "agent",
            "role": "repository-maintainer",
        },
        **kwargs,
    )


def test_atomic_v2_publication_allows_readme_blocks_deployment_and_stays_warm(
    tmp_path, monkeypatch
):
    import governance_ledger

    calls = {"bundle": 0, "receipt": 0, "facts": 0, "schema": 0}
    originals = {
        "bundle": governance_ledger.validate_authority_bundle,
        "receipt": governance_ledger.validate_publication_receipt,
        "facts": governance_ledger.validate_runtime_fact_compatibility,
        "schema": governance_ledger.validate_runtime_fact_schema,
    }

    def counted(label):
        def invoke(*args, **kwargs):
            calls[label] += 1
            return originals[label](*args, **kwargs)

        return invoke

    monkeypatch.setattr(governance_ledger, "validate_authority_bundle", counted("bundle"))
    monkeypatch.setattr(governance_ledger, "validate_publication_receipt", counted("receipt"))
    monkeypatch.setattr(governance_ledger, "validate_runtime_fact_compatibility", counted("facts"))
    monkeypatch.setattr(governance_ledger, "validate_runtime_fact_schema", counted("schema"))
    server, base_url = _serve()
    try:
        guard = _cloud_guard(tmp_path, base_url)
        guard.cloud_preservation_client = None
        guard.cloud_runtime_client = None
        cold_calls = dict(calls)
        callback_calls = []

        @guard.repository_tool(action="modify", target="path", return_result=True)
        def write_file(path, metadata):
            callback_calls.append(path.relative_path)
            path.write_bytes(b"updated")
            return path.relative_path

        metadata = {"caller": ["unchanged"]}
        before = copy.deepcopy(metadata)
        allowed = write_file("README.md", metadata)
        with pytest.raises(GuardExecutionBlocked) as blocked:
            write_file("deployment/production.yml", metadata)
    finally:
        server.shutdown()
        server.server_close()

    assert callback_calls == ["README.md"]
    assert allowed["executed"] is True
    assert blocked.value.evaluation["execution_attestation"]["callback_invoked"] is False
    assert allowed["evaluation"]["runtime_facts_hash"].startswith("sha256:")
    assert allowed["evaluation"]["runtime_facts"] == {
        "actor.principal_id": "repository-agent",
        "actor.role": "repository-maintainer",
        "actor.subject_kind": "agent",
        "proposal.action": "modify",
        "proposal.resource.kind": "repository_path",
        "proposal.resource.path": "README.md",
    }
    assert metadata == before
    assert calls == cold_calls == {"bundle": 1, "receipt": 1, "facts": 1, "schema": 1}
    assert len(guard.authority_cache) == 1
    publication_gets = [
        item for item in server.state["requests"] if item["path"].endswith("/publication")
    ]
    assert len(publication_gets) == 1
    assert not any(item["path"].startswith("/v1/contracts/") for item in server.state["requests"])
    assert publication_gets[0]["headers"]["X-Organization-ID"] == ORGANIZATION_ID
    assert publication_gets[0]["headers"]["X-API-Key"] == "runtime-secret"


def test_legacy_404_fallback_preserves_v1_and_contract_only_v2_still_fails(tmp_path):
    fallback = {"publication_status": 404, "publication_body": b'{"error":"not found"}'}
    server, base_url = _serve(fallback)
    try:
        guard = _cloud_guard(tmp_path / "v1", base_url)
        assert guard.boundary_for().compiled_authority["schema_version"] == "compiled_authority_contract.v1"
        paths = [item["path"] for item in server.state["requests"] if item["method"] == "GET"]
        assert paths == [
            "/v1/authorities/repository-authority%401.0.0/publication",
            "/v1/contracts/repository-authority/1.0.0",
        ]

        server.state["legacy_body"] = json.dumps(
            _fixture()["authority_bundle"]["compiled_authority_contract"]
        ).encode("utf-8")
        contract_only = _cloud_guard(tmp_path / "v2", base_url)
        with pytest.raises(
            AuthorityVerificationError,
            match="compiled_authority_contract.v2 requires a verified authority bundle",
        ):
            contract_only.boundary_for()
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("status", [401, 403, 409, 413, 422, 429, 500, 503])
def test_publication_http_failures_never_fallback(status):
    server, base_url = _serve({"publication_status": status, "publication_body": b"private-policy"})
    try:
        with pytest.raises(CloudAuthorityFetchError) as exc_info:
            CloudAuthorityClient(
                base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
            ).fetch_publication(AUTHORITY_REF)
    finally:
        server.shutdown()
        server.server_close()
    message = str(exc_info.value)
    assert str(status) in message
    assert "runtime-secret" not in message
    assert "private-policy" not in message
    assert len(server.state["requests"]) == 1


@pytest.mark.parametrize(
    ("body", "headers", "message"),
    [
        (b"{}", {"Content-Type": "text/plain"}, "application/json"),
        (b"", {"Content-Type": "application/json"}, "empty"),
        (b'{"schema_version":', {"Content-Type": "application/json"}, "strict UTF-8 JSON"),
        (b"not-json", {"Content-Type": "application/json"}, "strict UTF-8 JSON"),
        (
            b'{"schema_version":"cloud_authority_publication.v1","schema_version":"foreign"}',
            {"Content-Type": "application/json"},
            "duplicate JSON keys",
        ),
    ],
)
def test_invalid_publication_bodies_fail_closed(body, headers, message):
    server, base_url = _serve({"publication_body": body, "publication_headers": headers})
    try:
        with pytest.raises(CloudAuthorityFetchError, match=message):
            CloudAuthorityClient(
                base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
            ).fetch_publication(AUTHORITY_REF)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b'{"error":"authority_publication_not_found"}', {"Content-Type": "text/plain"}),
        (b'{"error":', {"Content-Type": "application/json"}),
        (b'{"error":"unexpected_missing_state"}', {"Content-Type": "application/json"}),
    ],
)
def test_malformed_or_unclear_404_never_triggers_legacy_fallback(body, headers):
    server, base_url = _serve(
        {
            "publication_status": 404,
            "publication_body": body,
            "publication_headers": headers,
        }
    )
    try:
        with pytest.raises(CloudAuthorityFetchError) as exc_info:
            CloudAuthorityClient(
                base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
            ).fetch_publication(AUTHORITY_REF)
    finally:
        server.shutdown()
        server.server_close()
    assert not isinstance(exc_info.value, CloudPublicationUnavailable)
    assert len(server.state["requests"]) == 1


def test_oversized_encoded_and_compressed_bodies_fail_closed(monkeypatch):
    monkeypatch.setattr("waveframe_guard.cloud.client.MAX_CLOUD_PUBLICATION_BODY_BYTES", 512)
    cases = [
        (b"x" * 513, {"Content-Type": "application/json"}),
        (
            gzip.compress(b"x" * 513),
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        ),
    ]
    for body, headers in cases:
        server, base_url = _serve({"publication_body": body, "publication_headers": headers})
        try:
            with pytest.raises(CloudAuthorityFetchError, match="body limit"):
                CloudAuthorityClient(
                    base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
                ).fetch_publication(AUTHORITY_REF)
        finally:
            server.shutdown()
            server.server_close()


def test_timeout_and_redirect_rejection_never_fallback(monkeypatch):
    client = CloudAuthorityClient(
        "https://cloud.example", organization_id=ORGANIZATION_ID, api_key="runtime-secret"
    )

    def timeout(*args, **kwargs):
        raise requests.Timeout("private-policy runtime-secret")

    original_get = requests.get
    monkeypatch.setattr(requests, "get", timeout)
    with pytest.raises(CloudAuthorityFetchError, match="timed out") as timeout_error:
        client.fetch_publication(AUTHORITY_REF)
    assert "runtime-secret" not in str(timeout_error.value)
    monkeypatch.setattr(requests, "get", original_get)

    server, base_url = _serve(
        {
            "publication_status": 302,
            "publication_headers": {
                "Content-Type": "application/json",
                "Location": "https://foreign.example/private",
            },
        }
    )
    try:
        with pytest.raises(CloudAuthorityFetchError, match="redirect"):
            CloudAuthorityClient(
                base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
            ).fetch_publication(AUTHORITY_REF)
    finally:
        server.shutdown()
        server.server_close()
    assert len(server.state["requests"]) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bundle_ref", "../bundle.json"),
        ("receipt_ref", "/tenant/receipt.json"),
        ("receipt_ref", "C:/tenant/receipt.json"),
        ("receipt_ref", "tenant\\receipt.json"),
        ("receipt_ref", "tenant//receipt.json"),
        ("receipt_ref", "tenant/./receipt.json"),
        ("receipt_ref", "tenant/../receipt.json"),
    ],
)
def test_logical_path_attacks_are_rejected_on_all_platforms(field, value):
    payload = _fixture()
    payload["registry_entry"][field] = value
    _rehash(payload)
    with pytest.raises(CloudPublicationProtocolError, match="unsafe logical"):
        parse_cloud_authority_publication(
            payload,
            requested_authority_ref=AUTHORITY_REF,
            expected_organization_id=ORGANIZATION_ID,
        )


def test_envelope_rejects_partial_duplicate_foreign_and_cross_tenant_bindings():
    mutations = []
    partial = _fixture()
    partial.pop("publication_receipt")
    mutations.append(partial)
    extra = _fixture()
    extra["contract"] = {"separately_trusted": True}
    mutations.append(extra)
    foreign_tenant = _fixture()
    foreign_tenant["organization_id"] = "foreign-organization"
    _rehash(foreign_tenant)
    mutations.append(foreign_tenant)
    foreign_authority = _fixture()
    foreign_authority["authority_ref"] = "foreign-authority@1.0.0"
    _rehash(foreign_authority)
    mutations.append(foreign_authority)
    bad_registry_hash = _fixture()
    bad_registry_hash["registry_entry_hash"] = "sha256:" + "0" * 64
    _rehash(bad_registry_hash, registry=False)
    mutations.append(bad_registry_hash)
    bad_envelope_hash = _fixture()
    bad_envelope_hash["envelope_hash"] = "sha256:" + "0" * 64
    mutations.append(bad_envelope_hash)

    for payload in mutations:
        with pytest.raises(CloudPublicationProtocolError):
            parse_cloud_authority_publication(
                payload,
                requested_authority_ref=AUTHORITY_REF,
                expected_organization_id=ORGANIZATION_ID,
            )


def test_protocol_errors_do_not_echo_server_fields_or_policy_bytes():
    payload = _fixture()
    secret_field = "runtime-secret-private-policy-bytes"
    payload[secret_field] = "complete private artifact"
    with pytest.raises(CloudPublicationProtocolError) as exc_info:
        parse_cloud_authority_publication(
            payload,
            requested_authority_ref=AUTHORITY_REF,
            expected_organization_id=ORGANIZATION_ID,
        )
    message = str(exc_info.value)
    assert secret_field not in message
    assert "complete private artifact" not in message


def test_foreign_receipt_reaches_ledger_and_fails_before_guard_activation(tmp_path):
    payload = _fixture()
    receipt = payload["publication_receipt"]
    receipt["publication_id"] = "foreign-publication"
    receipt["receipt_hash"] = _canonical_hash(
        {key: value for key, value in receipt.items() if key != "receipt_hash"}
    )
    payload["registry_entry"]["publication_id"] = "foreign-publication"
    payload["registry_entry"]["receipt_hash"] = receipt["receipt_hash"]
    _rehash(payload)
    server, base_url = _serve({"publication_body": json.dumps(payload).encode("utf-8")})
    try:
        with pytest.raises(AuthorityVerificationError, match="Ledger rejected"):
            _cloud_guard(tmp_path, base_url)
    finally:
        server.shutdown()
        server.server_close()


def test_runtime_credential_alias_reuses_existing_headers(tmp_path):
    server, base_url = _serve()
    try:
        guard = Guard.cloud(
            authority=AUTHORITY_REF,
            workspace=tmp_path,
            cloud_url=base_url,
            cloud_organization_id=ORGANIZATION_ID,
            runtime_credential="runtime-secret",
            runtime_id="repository-runtime",
            actor_identity={"id": "repository-agent", "type": "agent", "role": "repository-maintainer"},
        )
    finally:
        server.shutdown()
        server.server_close()
    assert guard.default_authority_ref == AUTHORITY_REF
    publication_request = server.state["requests"][0]
    assert publication_request["headers"]["X-Organization-ID"] == ORGANIZATION_ID
    assert publication_request["headers"]["X-API-Key"] == "runtime-secret"


def test_authority_reference_is_percent_encoded():
    server, base_url = _serve(
        {"publication_status": 404, "publication_body": b'{"error":"endpoint_not_found"}'}
    )
    try:
        with pytest.raises(CloudPublicationUnavailable):
            CloudAuthorityClient(
                base_url, organization_id=ORGANIZATION_ID, api_key="runtime-secret"
            ).fetch_publication("repository authority@1.0.0")
    finally:
        server.shutdown()
        server.server_close()
    assert server.state["requests"][0]["path"].endswith(
        "/repository%20authority%401.0.0/publication"
    )

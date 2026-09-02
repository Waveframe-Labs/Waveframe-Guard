from __future__ import annotations

import hashlib
import json
import math
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from numbers import Number
from typing import Any, Mapping, Optional
from urllib.parse import quote
from uuid import uuid4

import requests

from guard.adapters.compiled_authority import (
    CompiledAuthorityIntakeError,
    intake_compiled_authority,
)
from waveframe_guard.authority.loader import parse_authority_ref
from .publication import (
    CloudAuthorityPublication,
    CloudPublicationProtocolError,
    parse_cloud_authority_publication,
)


DEFAULT_CLOUD_BASE_URL = "http://localhost:8000"
DEFAULT_PRESERVATION_TIMEOUT_SECONDS = 10.0
DEFAULT_AUTHORITY_TIMEOUT_SECONDS = 5.0
DEFAULT_RUNTIME_TIMEOUT_SECONDS = 5.0
MAX_CLOUD_PUBLICATION_BODY_BYTES = 8 * 1024 * 1024


class CloudAuthorityFetchError(RuntimeError):
    """Raised when Guard cannot obtain a trustworthy authority from Cloud."""


class CloudPublicationUnavailable(CloudAuthorityFetchError):
    """Signals the narrow, explicit legacy fallback condition."""


class CloudAuthorityClient:
    """Fetch published authority contracts for local Guard enforcement."""

    def __init__(
        self,
        base_url: str = DEFAULT_CLOUD_BASE_URL,
        *,
        organization_id: str,
        api_key: str,
        timeout_seconds: float = DEFAULT_AUTHORITY_TIMEOUT_SECONDS,
    ):
        self.base_url = base_url.rstrip("/")
        self.organization_id = _required_credential("organization_id", organization_id)
        self._api_key = _required_credential("api_key", api_key)
        self.timeout_seconds = timeout_seconds

    def fetch(self, authority_ref: str) -> dict[str, Any]:
        contract_id, contract_version = parse_authority_ref(authority_ref)
        url = (
            f"{self.base_url}/v1/contracts/"
            f"{quote(contract_id, safe='')}/{quote(contract_version, safe='')}"
        )
        try:
            response = requests.get(
                url,
                headers={
                    "X-Organization-ID": self.organization_id,
                    "X-API-Key": self._api_key,
                },
                timeout=self.timeout_seconds,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise CloudAuthorityFetchError("Cloud authority request timed out") from exc
        except requests.RequestException as exc:
            message = _redact_secret(str(exc) or "Cloud authority request failed", self._api_key)
            raise CloudAuthorityFetchError(message) from exc

        if 300 <= response.status_code < 400:
            raise CloudAuthorityFetchError("Cloud authority request rejected an HTTP redirect")
        if not 200 <= response.status_code < 300:
            raise CloudAuthorityFetchError(_authority_http_error(response.status_code))

        try:
            contract = response.json()
        except ValueError as exc:
            raise CloudAuthorityFetchError("Cloud authority response was not valid JSON") from exc
        if not isinstance(contract, dict):
            raise CloudAuthorityFetchError("Cloud authority response must be a JSON object")
        try:
            contract = intake_compiled_authority(
                contract,
                _verified_v2_authority=(
                    contract.get("schema_version") == "compiled_authority_contract.v2"
                ),
            )
        except CompiledAuthorityIntakeError as exc:
            raise CloudAuthorityFetchError(
                f"Cloud authority response is not enforceable: {exc}"
            ) from exc
        if contract.get("contract_id") != contract_id:
            raise CloudAuthorityFetchError(
                "Cloud authority contract_id does not match the requested authority"
            )
        if contract.get("contract_version") != contract_version:
            raise CloudAuthorityFetchError(
                "Cloud authority contract_version does not match the requested authority"
            )
        expected_hash = _normalize_hash(contract["contract_hash"])
        actual_hash = _normalize_hash(_contract_hash(contract))
        if expected_hash != actual_hash:
            raise CloudAuthorityFetchError(
                "Cloud authority response failed its contract_hash integrity check"
            )
        return contract

    def fetch_publication(self, authority_ref: str) -> CloudAuthorityPublication:
        parse_authority_ref(authority_ref)
        url = f"{self.base_url}/v1/authorities/{quote(authority_ref, safe='')}/publication"
        try:
            response = requests.get(
                url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip, identity",
                    "X-Organization-ID": self.organization_id,
                    "X-API-Key": self._api_key,
                },
                timeout=self.timeout_seconds,
                allow_redirects=False,
                stream=True,
            )
        except requests.Timeout as exc:
            raise CloudAuthorityFetchError("Cloud publication request timed out") from exc
        except requests.RequestException as exc:
            message = _redact_secret(str(exc) or "Cloud publication request failed", self._api_key)
            raise CloudAuthorityFetchError(message) from exc

        try:
            if 300 <= response.status_code < 400:
                raise CloudAuthorityFetchError("Cloud publication request rejected an HTTP redirect")
            if response.status_code == 404:
                body = _read_publication_body(response)
                error_code = _error_code_from_json(body)
                if error_code in {
                    "not found",
                    "not_found",
                    "endpoint_not_found",
                    "authority_publication_not_found",
                }:
                    raise CloudPublicationUnavailable(
                        "Cloud publication endpoint is unavailable for this authority"
                    )
                raise CloudAuthorityFetchError(_publication_http_error(404))
            if not 200 <= response.status_code < 300:
                raise CloudAuthorityFetchError(_publication_http_error(response.status_code))
            body = _read_publication_body(response)
        finally:
            response.close()

        try:
            payload = _strict_json_object(body)
            return parse_cloud_authority_publication(
                payload,
                requested_authority_ref=authority_ref,
                expected_organization_id=self.organization_id,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, CloudPublicationProtocolError) as exc:
            if isinstance(exc, CloudPublicationProtocolError):
                message = str(exc)
            else:
                message = "Cloud publication response was not valid strict UTF-8 JSON"
            raise CloudAuthorityFetchError(message) from exc


@dataclass(frozen=True)
class CloudPreservationResult:
    ok: bool
    package_id: Optional[str] = None
    receipt_id: Optional[str] = None
    sha256: Optional[str] = None
    timestamp: Optional[str] = None
    receipt: Optional[Mapping[str, Any]] = None
    response: Optional[Mapping[str, Any]] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    ambiguous: bool = False


class CloudPreservationClient:
    def __init__(
        self,
        base_url: str = DEFAULT_CLOUD_BASE_URL,
        *,
        timeout_seconds: float = DEFAULT_PRESERVATION_TIMEOUT_SECONDS,
        organization_id: str | None = None,
        api_key: str | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = _preservation_timeout_seconds(timeout_seconds)
        self.organization_id = _optional_credential("organization_id", organization_id)
        self._api_key = _optional_credential("api_key", api_key)
        if (self.organization_id is None) != (self._api_key is None):
            raise ValueError("organization_id and api_key must be configured together")

    def preserve(self, payload: Mapping[str, Any]) -> CloudPreservationResult:
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")

        try:
            request_options: dict[str, Any] = {
                "json": dict(payload),
                "timeout": self.timeout_seconds,
            }
            if self.organization_id is not None and self._api_key is not None:
                request_options["headers"] = {
                    "X-Organization-ID": self.organization_id,
                    "X-API-Key": self._api_key,
                }
            response = requests.post(
                f"{self.base_url}/v1/preserve",
                **request_options,
            )
        except requests.Timeout as exc:
            return CloudPreservationResult(
                ok=False,
                error=(
                    "Cloud evidence preservation was not confirmed; the local Guard "
                    "decision remains authoritative. Do not blindly retry because Cloud "
                    "may already have committed it."
                ),
                error_type="timeout",
                ambiguous=True,
            )
        except requests.RequestException as exc:
            return CloudPreservationResult(
                ok=False,
                error=_redact_secret(
                    str(exc) or "Cloud preservation request failed",
                    self._api_key,
                ),
                error_type="request_error",
            )

        if not 200 <= response.status_code < 300:
            return CloudPreservationResult(
                ok=False,
                response=_sanitized_response(response, self._api_key),
                status_code=response.status_code,
                error=_redact_secret(response.text, self._api_key),
                error_type="http_error",
            )

        try:
            parsed = response.json()
        except ValueError as exc:
            return CloudPreservationResult(
                ok=False,
                status_code=response.status_code,
                error=str(exc) or "Cloud preservation response was not valid JSON",
                error_type="invalid_json",
            )

        if not isinstance(parsed, Mapping):
            return CloudPreservationResult(
                ok=False,
                status_code=response.status_code,
                error="Cloud preservation response must be a JSON object",
                error_type="invalid_response",
            )

        receipt = parsed.get("receipt")
        if receipt is not None and not isinstance(receipt, Mapping):
            return CloudPreservationResult(
                ok=False,
                response=parsed,
                status_code=response.status_code,
                error="Cloud preservation receipt must be a JSON object",
                error_type="invalid_response",
            )

        package_id = _extract_package_id(parsed, receipt)
        required_fields = {
            "package_id": package_id,
            "receipt_id": _extract_string("receipt_id", parsed, receipt),
            "sha256": _extract_string("sha256", parsed, receipt),
            "timestamp": _extract_string("timestamp", parsed, receipt),
        }
        missing_fields = [
            key
            for key, value in required_fields.items()
            if not isinstance(value, str) or not value
        ]
        if missing_fields:
            return CloudPreservationResult(
                ok=False,
                response=parsed,
                status_code=response.status_code,
                error=f"Cloud preservation response missing required fields: {', '.join(missing_fields)}",
                error_type="invalid_response",
            )

        return CloudPreservationResult(
            ok=True,
            package_id=required_fields["package_id"],
            receipt_id=required_fields["receipt_id"],
            sha256=required_fields["sha256"],
            timestamp=required_fields["timestamp"],
            receipt=receipt,
            response=parsed,
            status_code=response.status_code,
        )


@dataclass(frozen=True)
class CloudRuntimeOperationResult:
    ok: bool
    response: Optional[Mapping[str, Any]] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    error_type: Optional[str] = None


@dataclass(frozen=True)
class CloudRuntimeConnectionResult:
    ok: bool
    registration: CloudRuntimeOperationResult
    heartbeat: Optional[CloudRuntimeOperationResult] = None


class CloudRuntimeClient:
    """Report Guard runtime lifecycle and execution results to Cloud.

    These calls are observational. A Cloud reporting failure must never change
    Guard's local admissibility decision or whether a protected callback runs.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_CLOUD_BASE_URL,
        *,
        organization_id: str,
        api_key: str,
        runtime_id: str,
        environment: str,
        authority_ref: str,
        runtime_version: str,
        timeout_seconds: float = DEFAULT_RUNTIME_TIMEOUT_SECONDS,
    ):
        self.base_url = base_url.rstrip("/")
        self.organization_id = _required_credential("organization_id", organization_id)
        self._api_key = _required_credential("api_key", api_key)
        self.runtime_id = _required_credential("runtime_id", runtime_id)
        self.environment = _required_credential("environment", environment)
        self.authority_ref = _required_credential("authority_ref", authority_ref)
        self.runtime_version = _required_credential("runtime_version", runtime_version)
        self.timeout_seconds = timeout_seconds

    def connect(self) -> CloudRuntimeConnectionResult:
        registration = self.register()
        if not registration.ok:
            return CloudRuntimeConnectionResult(ok=False, registration=registration)
        heartbeat = self.heartbeat()
        return CloudRuntimeConnectionResult(
            ok=heartbeat.ok,
            registration=registration,
            heartbeat=heartbeat,
        )

    def register(self) -> CloudRuntimeOperationResult:
        return self._post(
            "/v1/runtimes/register",
            {
                "runtime_id": self.runtime_id,
                "runtime_version": self.runtime_version,
                "status": "registered",
                "environment": self.environment,
                "environment_id": self.environment,
                "capabilities": [
                    "agent_tool_boundary",
                    "local_admissibility",
                    "cloud_evidence_preservation",
                    "runtime_result_attestation",
                ],
                "authority_refs": [self.authority_ref],
            },
        )

    def heartbeat(self) -> CloudRuntimeOperationResult:
        return self._post(
            f"/v1/runtimes/{quote(self.runtime_id, safe='')}/heartbeats",
            {
                "schema_version": "cloud_runtime_heartbeat.v1",
                "heartbeat_id": f"heartbeat-{self.runtime_id}-{uuid4().hex}",
                "runtime_id": self.runtime_id,
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "status": "online",
                "surface": "guard_sdk",
                "environment": self.environment,
                "environment_id": self.environment,
                "authority_refs": [self.authority_ref],
            },
        )

    def attest(
        self,
        *,
        event_id: str,
        compiled_contract_hash: str,
        runtime_decision: str,
        execution_status: str,
        execution_result_summary: str,
        mutation_executed: bool | None = None,
    ) -> CloudRuntimeOperationResult:
        payload: dict[str, Any] = {
            "schema_version": "runtime_execution_attestation.v1",
            "event_id": event_id,
            "runtime_id": self.runtime_id,
            "authority_ref": self.authority_ref,
            "compiled_contract_hash": compiled_contract_hash,
            "runtime_decision": runtime_decision,
            "execution_status": execution_status,
            "execution_result_summary": execution_result_summary[:500],
        }
        if mutation_executed is not None:
            payload["mutation_executed"] = mutation_executed
        return self._post("/v1/runtime/attestations", payload)

    def _post(
        self,
        path: str,
        payload: Mapping[str, Any],
    ) -> CloudRuntimeOperationResult:
        try:
            response = requests.post(
                f"{self.base_url}{path}",
                json=dict(payload),
                headers={
                    "X-Organization-ID": self.organization_id,
                    "X-API-Key": self._api_key,
                },
                timeout=self.timeout_seconds,
            )
        except requests.Timeout as exc:
            return CloudRuntimeOperationResult(
                ok=False,
                error=_redact_secret(
                    str(exc) or "Cloud runtime request timed out",
                    self._api_key,
                ),
                error_type="timeout",
            )
        except requests.RequestException as exc:
            return CloudRuntimeOperationResult(
                ok=False,
                error=_redact_secret(
                    str(exc) or "Cloud runtime request failed",
                    self._api_key,
                ),
                error_type="request_error",
            )

        if not 200 <= response.status_code < 300:
            return CloudRuntimeOperationResult(
                ok=False,
                response=_sanitized_response(response, self._api_key),
                status_code=response.status_code,
                error=_redact_secret(response.text, self._api_key),
                error_type="http_error",
            )
        try:
            parsed = response.json()
        except ValueError as exc:
            return CloudRuntimeOperationResult(
                ok=False,
                status_code=response.status_code,
                error=str(exc) or "Cloud runtime response was not valid JSON",
                error_type="invalid_json",
            )
        if not isinstance(parsed, Mapping):
            return CloudRuntimeOperationResult(
                ok=False,
                status_code=response.status_code,
                error="Cloud runtime response must be a JSON object",
                error_type="invalid_response",
            )
        return CloudRuntimeOperationResult(
            ok=True,
            response=parsed,
            status_code=response.status_code,
        )


def _extract_package_id(
    parsed: Mapping[str, Any],
    receipt: Optional[Mapping[str, Any]],
) -> Optional[str]:
    package_id = parsed.get("package_id")
    if isinstance(package_id, str):
        return package_id

    package = parsed.get("package")
    if isinstance(package, Mapping) and isinstance(package.get("id"), str):
        return package["id"]

    if receipt is not None and isinstance(receipt.get("package_id"), str):
        return receipt["package_id"]

    return None


def _extract_string(
    key: str,
    parsed: Mapping[str, Any],
    receipt: Optional[Mapping[str, Any]],
) -> Optional[str]:
    value = parsed.get(key)
    if isinstance(value, str):
        return value
    if receipt is not None and isinstance(receipt.get(key), str):
        return receipt[key]
    return None


def _optional_credential(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string when configured")
    return value


def _preservation_timeout_seconds(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, Number):
        raise ValueError("preservation_timeout_seconds must be a positive finite number")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            "preservation_timeout_seconds must be a positive finite number"
        ) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("preservation_timeout_seconds must be a positive finite number")
    return timeout


def _required_credential(name: str, value: str) -> str:
    normalized = _optional_credential(name, value)
    if normalized is None:
        raise ValueError(f"{name} is required")
    return normalized


def _contract_hash(contract: Mapping[str, Any]) -> str:
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_hash(value: str) -> str:
    return value if value.startswith("sha256:") else f"sha256:{value}"


def _read_publication_body(response: Any) -> bytes:
    content_type = str(response.headers.get("Content-Type", ""))
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise CloudAuthorityFetchError("Cloud publication response must use application/json")
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            parsed_length = int(content_length)
            if parsed_length < 0:
                raise ValueError
            if parsed_length > MAX_CLOUD_PUBLICATION_BODY_BYTES:
                raise CloudAuthorityFetchError("Cloud publication response exceeded the body limit")
        except ValueError as exc:
            raise CloudAuthorityFetchError("Cloud publication response had an invalid Content-Length") from exc

    encoding = str(response.headers.get("Content-Encoding", "identity")).strip().lower()
    if encoding not in {"", "identity", "gzip"}:
        raise CloudAuthorityFetchError("Cloud publication response used an unsupported content encoding")
    response.raw.decode_content = False
    encoded = bytearray()
    while True:
        chunk = response.raw.read(64 * 1024)
        if not chunk:
            break
        encoded.extend(chunk)
        if len(encoded) > MAX_CLOUD_PUBLICATION_BODY_BYTES:
            raise CloudAuthorityFetchError("Cloud publication response exceeded the encoded body limit")
    if not encoded:
        raise CloudAuthorityFetchError("Cloud publication response body was empty")
    if encoding != "gzip":
        return bytes(encoded)

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        decoded = decompressor.decompress(bytes(encoded), MAX_CLOUD_PUBLICATION_BODY_BYTES + 1)
        if len(decoded) <= MAX_CLOUD_PUBLICATION_BODY_BYTES:
            decoded += decompressor.flush(MAX_CLOUD_PUBLICATION_BODY_BYTES + 1 - len(decoded))
    except zlib.error as exc:
        raise CloudAuthorityFetchError("Cloud publication response had invalid gzip encoding") from exc
    if len(decoded) > MAX_CLOUD_PUBLICATION_BODY_BYTES or decompressor.unconsumed_tail:
        raise CloudAuthorityFetchError("Cloud publication response exceeded the decompressed body limit")
    if not decompressor.eof or decompressor.unused_data:
        raise CloudAuthorityFetchError("Cloud publication response had ambiguous gzip framing")
    return decoded


def _strict_json_object(body: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CloudPublicationProtocolError("Cloud publication response contains duplicate JSON keys")
            result[key] = value
        return result

    payload = json.loads(body.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(payload, dict):
        raise CloudPublicationProtocolError("Cloud publication response must be a JSON object")
    return payload


def _error_code_from_json(body: bytes) -> str | None:
    try:
        payload = _strict_json_object(body)
    except (UnicodeDecodeError, json.JSONDecodeError, CloudPublicationProtocolError) as exc:
        raise CloudAuthorityFetchError("Cloud publication 404 response was not valid strict JSON") from exc
    error = payload.get("error")
    return error if isinstance(error, str) else None


def _authority_http_error(status_code: int) -> str:
    return f"Cloud authority request failed with HTTP {status_code}"


def _publication_http_error(status_code: int) -> str:
    labels = {
        401: "authentication failed",
        403: "authorization failed",
        404: "publication was not found",
        409: "publication conflicted",
        413: "publication was too large",
        422: "publication was invalid",
        429: "publication request was rate limited",
    }
    if status_code >= 500:
        label = "Cloud service failed"
    else:
        label = labels.get(status_code, "request failed")
    return f"Cloud publication {label} (HTTP {status_code})"


def _redact_secret(message: str, secret: str | None) -> str:
    if secret:
        return message.replace(secret, "[REDACTED]")
    return message


def _sanitized_response(response: Any, secret: str | None) -> Mapping[str, Any]:
    try:
        payload = response.json()
    except ValueError:
        return {"body": _redact_secret(response.text, secret)}
    sanitized = _redact_response_value(payload, secret)
    if isinstance(sanitized, Mapping):
        return sanitized
    return {"body": sanitized}


def _redact_response_value(value: Any, secret: str | None) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in {"api_key", "secret", "token", "authorization"}
                else _redact_response_value(item, secret)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_response_value(item, secret) for item in value]
    if isinstance(value, str):
        return _redact_secret(value, secret)
    return value

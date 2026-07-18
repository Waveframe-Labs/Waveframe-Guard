from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

import requests


DEFAULT_CLOUD_BASE_URL = "http://localhost:8000"
DEFAULT_PRESERVATION_TIMEOUT_SECONDS = 2.0


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
        self.timeout_seconds = timeout_seconds
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
                error=_redact_secret(
                    str(exc) or "Cloud preservation request timed out",
                    self._api_key,
                ),
                error_type="timeout",
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


def _redact_secret(message: str, secret: str | None) -> str:
    if secret:
        return message.replace(secret, "[REDACTED]")
    return message

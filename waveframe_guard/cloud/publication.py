from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import RLock
from typing import TYPE_CHECKING, Any, Mapping

from waveframe_guard.authority.adapters.common import (
    validate_logical_artifact_ref,
    validate_registry_entry,
)
from waveframe_guard.authority.exceptions import MalformedAuthorityRegistry
from waveframe_guard.authority.loader import parse_authority_ref
from waveframe_guard.authority.types import RegistryEntry

if TYPE_CHECKING:
    from .client import CloudAuthorityClient


CLOUD_AUTHORITY_PUBLICATION_V1 = "cloud_authority_publication.v1"

_ENVELOPE_FIELDS = {
    "schema_version",
    "organization_id",
    "authority_ref",
    "registry_entry",
    "registry_entry_hash",
    "authority_bundle",
    "publication_receipt",
    "envelope_hash",
}
_REGISTRY_FIELDS = {
    "authority_ref",
    "contract_id",
    "contract_version",
    "contract_hash",
    "publication_id",
    "bundle_ref",
    "bundle_hash",
    "receipt_ref",
    "receipt_hash",
    "lifecycle_state",
    "published_at",
    "published_by",
}


class CloudPublicationProtocolError(ValueError):
    """Raised when a Cloud publication envelope violates the public protocol."""


@dataclass(frozen=True)
class CloudAuthorityPublication:
    organization_id: str
    authority_ref: str
    registry_entry: Mapping[str, Any]
    registry_entry_hash: str
    authority_bundle: Mapping[str, Any]
    publication_receipt: Mapping[str, Any]
    envelope_hash: str


def parse_cloud_authority_publication(
    payload: Any,
    *,
    requested_authority_ref: str,
    expected_organization_id: str,
) -> CloudAuthorityPublication:
    """Strictly parse the atomic Cloud-to-Guard publication protocol."""

    if not isinstance(payload, dict):
        raise CloudPublicationProtocolError("Cloud publication response must be a JSON object")
    _require_exact_fields(payload, _ENVELOPE_FIELDS, "Cloud publication response")
    if payload["schema_version"] != CLOUD_AUTHORITY_PUBLICATION_V1:
        raise CloudPublicationProtocolError("Cloud publication response has an unsupported schema_version")

    authority_ref = _required_string(payload, "authority_ref", "Cloud publication response")
    parse_authority_ref(authority_ref)
    if authority_ref != requested_authority_ref:
        raise CloudPublicationProtocolError("Cloud publication authority_ref does not match the request")
    organization_id = _required_string(payload, "organization_id", "Cloud publication response")
    if organization_id != expected_organization_id:
        raise CloudPublicationProtocolError("Cloud publication organization binding does not match the request")

    registry = payload["registry_entry"]
    if not isinstance(registry, dict):
        raise CloudPublicationProtocolError("Cloud publication registry_entry must be a JSON object")
    _require_exact_fields(registry, _REGISTRY_FIELDS, "Cloud publication registry_entry")
    for field in _REGISTRY_FIELDS:
        _required_string(registry, field, "Cloud publication registry_entry")
    if registry["authority_ref"] != authority_ref:
        raise CloudPublicationProtocolError("Cloud publication registry authority_ref mismatch")
    contract_id, contract_version = parse_authority_ref(authority_ref)
    if registry["contract_id"] != contract_id:
        raise CloudPublicationProtocolError("Cloud publication registry contract_id mismatch")
    if registry["contract_version"] != contract_version:
        raise CloudPublicationProtocolError("Cloud publication registry contract_version mismatch")
    if registry["lifecycle_state"] not in {"active", "superseded", "revoked"}:
        raise CloudPublicationProtocolError("Cloud publication registry lifecycle_state is unsupported")
    _required_sha256(registry, "contract_hash", "Cloud publication registry_entry")
    _required_sha256(registry, "bundle_hash", "Cloud publication registry_entry")
    _required_sha256(registry, "receipt_hash", "Cloud publication registry_entry")
    try:
        validate_logical_artifact_ref(
            registry["bundle_ref"], authority_ref=authority_ref, field="bundle_ref"
        )
        validate_logical_artifact_ref(
            registry["receipt_ref"], authority_ref=authority_ref, field="receipt_ref"
        )
    except MalformedAuthorityRegistry as exc:
        raise CloudPublicationProtocolError("Cloud publication contains an unsafe logical artifact reference") from exc

    registry_entry_hash = _required_sha256(
        payload, "registry_entry_hash", "Cloud publication response"
    )
    if registry_entry_hash != _canonical_hash(registry):
        raise CloudPublicationProtocolError("Cloud publication registry_entry_hash mismatch")

    bundle = payload["authority_bundle"]
    receipt = payload["publication_receipt"]
    if not isinstance(bundle, dict) or bundle.get("schema_version") != "authority_bundle.v2":
        raise CloudPublicationProtocolError("Cloud publication must contain authority_bundle.v2")
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "publication_receipt.v2":
        raise CloudPublicationProtocolError("Cloud publication must contain publication_receipt.v2")

    envelope_hash = _required_sha256(payload, "envelope_hash", "Cloud publication response")
    expected_envelope_hash = _canonical_hash(
        {key: value for key, value in payload.items() if key != "envelope_hash"}
    )
    if envelope_hash != expected_envelope_hash:
        raise CloudPublicationProtocolError("Cloud publication envelope_hash mismatch")

    return CloudAuthorityPublication(
        organization_id=organization_id,
        authority_ref=authority_ref,
        registry_entry=deepcopy(registry),
        registry_entry_hash=registry_entry_hash,
        authority_bundle=deepcopy(bundle),
        publication_receipt=deepcopy(receipt),
        envelope_hash=envelope_hash,
    )


class CloudAuthorityResolver:
    """Resolve an atomic Cloud publication through Guard's existing loader boundary."""

    def __init__(self, client: "CloudAuthorityClient"):
        self.client = client
        self._directories: list[TemporaryDirectory[str]] = []
        self._lock = RLock()

    def resolve(self, authority_ref: str) -> RegistryEntry:
        publication = self.client.fetch_publication(authority_ref)
        directory = TemporaryDirectory(prefix="waveframe-guard-cloud-publication-")
        root = Path(directory.name)
        bundle_path = root / "authority-bundle.json"
        receipt_path = root / "publication-receipt.json"
        bundle_path.write_text(_canonical_json(publication.authority_bundle) + "\n", encoding="utf-8")
        receipt_path.write_text(_canonical_json(publication.publication_receipt) + "\n", encoding="utf-8")
        with self._lock:
            self._directories.append(directory)

        binding = publication.registry_entry
        return validate_registry_entry(
            RegistryEntry(
                authority_ref=authority_ref,
                contract_id=binding["contract_id"],
                contract_version=binding["contract_version"],
                contract_hash=binding["contract_hash"],
                bundle_path=bundle_path,
                publication_id=binding["publication_id"],
                bundle_hash=binding["bundle_hash"],
                lifecycle_state=binding["lifecycle_state"],
                published_at=binding["published_at"],
                published_by=binding["published_by"],
                raw=deepcopy(binding),
                receipt_path=receipt_path,
                receipt_hash=binding["receipt_hash"],
                bundle_ref=binding["bundle_ref"],
                receipt_ref=binding["receipt_ref"],
            )
        )

    def close(self) -> None:
        with self._lock:
            directories, self._directories = self._directories, []
        for directory in directories:
            directory.cleanup()

    def __enter__(self) -> "CloudAuthorityResolver":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _require_exact_fields(payload: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(payload)
    if actual != expected:
        raise CloudPublicationProtocolError(f"{label} field set is invalid")


def _required_string(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value or value != value.strip():
        raise CloudPublicationProtocolError(f"{label} {field} must be a non-empty string")
    return value


def _required_sha256(payload: Mapping[str, Any], field: str, label: str) -> str:
    value = _required_string(payload, field, label)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise CloudPublicationProtocolError(f"{label} {field} must be a canonical SHA-256 identifier")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise CloudPublicationProtocolError(
            f"{label} {field} must be a canonical SHA-256 identifier"
        ) from exc
    if value[7:] != value[7:].lower():
        raise CloudPublicationProtocolError(f"{label} {field} must use lowercase hexadecimal")
    return value


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .exceptions import AuthorityVerificationError, InvalidAuthorityRef
from .types import Bundle, LoadedAuthority, RegistryEntry
from .verifier import AuthorityVerifier


def load_authority(authority_ref: str) -> LoadedAuthority:
    from .resolver import LocalRegistryResolver

    resolver = LocalRegistryResolver()
    loader = BundleLoader()
    verifier = AuthorityVerifier()
    return verifier.verify(loader.load(resolver.resolve(authority_ref)))


class BundleLoader:
    def load(self, registry_entry: RegistryEntry) -> Bundle:
        contract = _read_json(registry_entry.bundle_path)
        return Bundle(
            registry_entry=registry_entry,
            contract=contract,
            bundle_path=registry_entry.bundle_path,
            bundle_hash=f"sha256:{_file_hash(registry_entry.bundle_path)}",
        )


def parse_authority_ref(authority_ref: str) -> tuple[str, str]:
    if not isinstance(authority_ref, str):
        raise InvalidAuthorityRef("authority_ref must be a string")
    if "/" in authority_ref or "\\" in authority_ref or authority_ref.endswith(".json"):
        raise InvalidAuthorityRef("authority_ref must be an explicit name@version, not a path")
    if authority_ref.count("@") != 1:
        raise InvalidAuthorityRef("authority_ref must be an explicit name@version")
    name, version = authority_ref.split("@", 1)
    if not name or not version:
        raise InvalidAuthorityRef("authority_ref must include both name and version")
    if version == "latest":
        raise InvalidAuthorityRef("authority_ref must not use implicit versions such as latest")
    return name, version


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise AuthorityVerificationError("authority bundle must be a JSON object")
    return payload


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

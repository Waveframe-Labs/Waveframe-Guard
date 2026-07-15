from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .exceptions import AuthorityVerificationError, InvalidAuthorityRef
from .resolver import AuthorityResolver
from .types import Bundle, LoadedAuthority, RegistryEntry
from .verifier import AuthorityVerifier


def load_authority(authority_ref: str, *, resolver: AuthorityResolver | None = None) -> LoadedAuthority:
    from .adapters import LocalRegistryResolver

    active_resolver = resolver or LocalRegistryResolver()
    loader = BundleLoader()
    verifier = AuthorityVerifier()
    return verifier.verify(loader.load(active_resolver.resolve(authority_ref)))


class BundleLoader:
    def load(self, registry_entry: RegistryEntry) -> Bundle:
        payload = _read_json(registry_entry.bundle_path)
        return Bundle(
            registry_entry=registry_entry,
            payload=payload,
            bundle_path=registry_entry.bundle_path,
            bundle_hash=f"sha256:{_canonical_hash(payload)}",
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
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version):
        raise InvalidAuthorityRef("authority_ref version must use explicit numeric x.y.z form")
    return name, version


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise AuthorityVerificationError("authority bundle must be a JSON object")
    return payload


def _canonical_hash(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

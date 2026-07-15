from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class RegistryEntry:
    authority_ref: str
    contract_id: str
    contract_version: str
    contract_hash: str
    bundle_path: Path
    publication_id: Optional[str] = None
    bundle_hash: Optional[str] = None
    lifecycle_state: str = "active"
    published_at: Optional[str] = None
    published_by: Optional[str] = None
    raw: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Bundle:
    registry_entry: RegistryEntry
    contract: Mapping[str, Any]
    bundle_hash: str
    bundle_path: Path


@dataclass(frozen=True)
class LoadedAuthority:
    authority_ref: str
    publication_id: Optional[str]
    contract: Mapping[str, Any]
    contract_hash: str
    bundle_hash: str
    bundle_path: Path
    lifecycle_state: str
    published_at: Optional[str]
    published_by: Optional[str]

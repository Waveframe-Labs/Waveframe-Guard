from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def stable_hash(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def stable_id(prefix: str, payload: Any) -> str:
    digest = stable_hash(payload).split(":", 1)[1]
    return f"{prefix}_{digest[:24]}"

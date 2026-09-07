from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import threading
import warnings

import requests

from .context import get_context


DEFAULT_BASE_URL = "http://localhost:8000"


class GovernanceError(RuntimeError):
    pass


class LegacyExecutionError(GovernanceError):
    """Stable migration error for APIs without trusted strict execution evidence."""

    code = "GUARD_LEGACY_EXECUTION_UNSUPPORTED"

    def __init__(self, api):
        super().__init__(
            f"{self.code}: {api} cannot establish strict execution evidence "
            "(integrity/publication prerequisites). Migrate to Guard.local() or "
            "Guard.cloud() and guarded tools. Guard execution is never advisory."
        )


def execute(fn, *, args=None, kwargs=None, actor=None, contract=None):
    """Deprecated: always raise LegacyExecutionError before resolving or executing.

    Use Guard.local()/Guard.cloud() with tool() or repository_tool(). Local/cloud
    selects authority resolution, never CRI enforcement strength. Legacy contracts,
    caches and fail_mode="open" cannot establish strict execution evidence.
    """
    raise LegacyExecutionError("waveframe_guard.execute()")


def fetch_policy(api_key):
    base_url = os.getenv("WAVEFRAME_GUARD_URL", DEFAULT_BASE_URL)
    response = requests.get(
        f"{base_url}/v1/policy",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=2,
    )
    response.raise_for_status()
    payload = response.json()
    return (
        payload.get("compiled_contract")
        or payload.get("contract")
        or payload
    )


def send_to_cloud_async(payload, ctx=None):
    ctx = ctx or get_context()
    api_key = ctx.get("api_key")
    if not api_key:
        return

    def send():
        try:
            base_url = os.getenv("WAVEFRAME_GUARD_URL", DEFAULT_BASE_URL)
            requests.post(
                f"{base_url}/v1/decisions",
                headers={"Authorization": f"Bearer {api_key}"},
                json=payload,
                timeout=2,
            )
        except requests.RequestException:
            pass

    threading.Thread(target=send, daemon=True).start()


def _resolve_contract(ctx, explicit_contract=None):
    if explicit_contract is not None:
        _validate_contract(explicit_contract)
        ctx["policy_source"] = "explicit"
        return explicit_contract, False

    cache = ctx.get("policy_cache")
    if ctx.get("mode", "local") != "cloud":
        if cache:
            _validate_policy_cache(cache)
            ctx["policy_source"] = "local_cache"
            return cache["compiled_contract"], False

        ctx["policy_source"] = "local"
        return ctx.get("contract"), False

    if ctx.get("offline"):
        return _resolve_offline_cloud(ctx)

    if _cache_is_fresh(cache):
        _validate_policy_cache(cache)
        ctx["policy_source"] = "local_cache"
        return cache["compiled_contract"], False

    if not ctx.get("api_key"):
        if ctx.get("fail_mode") == "open":
            return _resolve_no_policy(ctx)
        if cache:
            _record_cloud_failure(ctx)
            return _resolve_unreachable_cloud(ctx)
        raise GovernanceError("Missing API key")

    try:
        fetched_contract = fetch_policy(ctx.get("api_key"))
    except requests.RequestException:
        _record_cloud_failure(ctx)
        return _resolve_unreachable_cloud(ctx)

    _record_cloud_success(ctx)
    _store_policy_cache(ctx, fetched_contract)
    ctx["policy_source"] = "cloud"
    return fetched_contract, False


def _resolve_offline_cloud(ctx):
    cache = ctx.get("policy_cache")
    if cache:
        _validate_policy_cache(cache)
        ctx["policy_source"] = "local_cache"
        warnings.warn(
            "Cloud unavailable; operating in cached enforcement mode",
            RuntimeWarning,
            stacklevel=2,
        )
        return cache["compiled_contract"], True

    return _resolve_no_policy(ctx)


def _resolve_unreachable_cloud(ctx):
    cache = ctx.get("policy_cache")
    if cache:
        _validate_policy_cache(cache)
        ctx["policy_source"] = "local_cache"
        warnings.warn(
            "Cloud unreachable; enforcing with last known policy",
            RuntimeWarning,
            stacklevel=2,
        )
        return cache["compiled_contract"], True

    return _resolve_no_policy(ctx)


def _resolve_no_policy(ctx):
    raise GovernanceError("No policy available; legacy fail-open execution is disabled. "
                          "Migrate to Guard.local() or Guard.cloud() and guarded tools.")


def _cache_is_fresh(cache):
    return (
        cache is not None
        and cache.get("expires_at") is not None
        and cache["expires_at"] > datetime.now(timezone.utc)
    )


def _store_policy_cache(ctx, contract):
    _validate_contract(contract)
    now = datetime.now(timezone.utc)
    ctx["contract"] = contract
    ctx["contract_metadata"] = _contract_metadata(contract)
    ctx["policy_cache"] = {
        "compiled_contract": contract,
        "contract_hash": contract["contract_hash"],
        "fetched_at": now,
        "expires_at": now + timedelta(seconds=ctx.get("policy_refresh", 60)),
    }


def _validate_policy_cache(cache):
    cached_hash = cache.get("contract_hash")
    contract = cache.get("compiled_contract", {})
    _validate_contract_shape(contract)

    actual_hash = compute_contract_hash(contract)
    if actual_hash != cached_hash:
        raise GovernanceError("Cached policy integrity check failed")


def _validate_contract(contract):
    _validate_contract_shape(contract)

    if compute_contract_hash(contract) != contract["contract_hash"]:
        raise GovernanceError("Invalid policy: hash mismatch")


def _validate_contract_shape(contract):
    required = ["contract_id", "contract_version", "contract_hash"]
    for key in required:
        if key not in contract:
            raise GovernanceError(f"Invalid policy: missing {key}")


def compute_contract_hash(contract):
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(
        canonical_contract,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _contract_metadata(contract):
    return {
        "contract_id": contract["contract_id"],
        "contract_version": contract["contract_version"],
        "contract_hash": contract["contract_hash"],
    }


def _record_cloud_failure(ctx):
    ctx["failure_count"] = ctx.get("failure_count", 0) + 1
    if ctx["failure_count"] >= ctx.get("max_failures", 3):
        ctx["offline"] = True


def _record_cloud_success(ctx):
    ctx["failure_count"] = 0
    ctx["offline"] = False

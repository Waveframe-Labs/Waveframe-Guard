from datetime import datetime, timedelta, timezone
import os
import threading
import warnings

import requests
from proposal_normalizer.build_proposal import build_proposal
from cricore.api import evaluate_structured

from .context import get_context, resolve_actor


DEFAULT_BASE_URL = "http://localhost:8000"


class GovernanceError(RuntimeError):
    pass


def execute(fn, *, args=None, kwargs=None, actor=None, contract=None):
    ctx = get_context()

    actor = actor or ctx.get("actor") or resolve_actor()
    mode = ctx.get("mode", "local")
    contract, unverified = _resolve_contract(ctx, contract)

    if contract is None:
        if mode == "cloud" and ctx.get("fail_mode") == "open":
            send_to_cloud_async(
                {
                    "decision": {
                        "commit_allowed": True,
                        "failed_stages": [],
                        "summary": "Cloud unreachable; fail-open execution allowed",
                        "status": "unverified",
                    },
                    "proposal": None,
                    "trace_hash": None,
                },
                ctx,
            )
            return fn(*(args or []), **(kwargs or {}))

        raise ValueError("Missing contract")

    proposal = build_proposal(
        proposal_id="auto",
        actor=actor,
        mutation=_infer_mutation(fn, args, kwargs),
        contract={
            "id": contract["contract_id"],
            "version": contract["contract_version"],
            "hash": contract["contract_hash"],
        },
        artifact_paths=[],
    )

    result = evaluate_structured(
        proposal=proposal,
        compiled_contract=contract,
        run_context=_build_run_context(actor, contract, mode, unverified),
    )
    _tag_decision(result, unverified, ctx.get("policy_source", "cloud"))

    if unverified:
        print("WARNING: Decision unverified (cloud unavailable)")

    send_to_cloud_async(
        {
            "decision": _serialize_decision(result),
            "proposal": proposal,
            "trace_hash": contract["contract_hash"],
        },
        ctx,
    )

    if not result.commit_allowed:
        raise PermissionError("Execution blocked")

    return fn(*(args or []), **(kwargs or {}))


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
    if ctx.get("fail_mode") == "closed":
        raise GovernanceError("No policy available")

    if ctx.get("fail_mode") == "open":
        warnings.warn(
            "Cloud unreachable; allowing execution without policy enforcement",
            RuntimeWarning,
            stacklevel=2,
        )
        return None, True

    raise GovernanceError("No policy available")


def _cache_is_fresh(cache):
    return (
        cache is not None
        and cache.get("expires_at") is not None
        and cache["expires_at"] > datetime.now(timezone.utc)
    )


def _store_policy_cache(ctx, contract):
    now = datetime.now(timezone.utc)
    ctx["contract"] = contract
    ctx["policy_cache"] = {
        "compiled_contract": contract,
        "contract_hash": contract["contract_hash"],
        "fetched_at": now,
        "expires_at": now + timedelta(seconds=ctx.get("policy_refresh", 60)),
    }


def _validate_policy_cache(cache):
    cached_hash = cache.get("contract_hash")
    contract_hash = cache.get("compiled_contract", {}).get("contract_hash")
    if cached_hash != contract_hash:
        raise GovernanceError("Cached policy integrity check failed")


def _record_cloud_failure(ctx):
    ctx["failure_count"] = ctx.get("failure_count", 0) + 1
    if ctx["failure_count"] >= ctx.get("max_failures", 3):
        ctx["offline"] = True


def _record_cloud_success(ctx):
    ctx["failure_count"] = 0
    ctx["offline"] = False


def _infer_mutation(fn, args, kwargs):
    return {
        "domain": "python",
        "resource": fn.__name__,
        "action": "call",
    }


def _build_run_context(actor, contract, mode, unverified=False):
    required_roles = (
        contract.get("authority_requirements", {}).get("required_roles")
        or [actor.get("role")]
    )

    return {
        "mode": mode,
        "decision_status": "unverified" if unverified else "verified",
        "identities": {
            "actors": [actor],
            "required_roles": required_roles,
            "conflict_flags": {},
        },
    }


def _tag_decision(result, unverified, source):
    object.__setattr__(
        result,
        "meta",
        {
            "verification": "unverified" if unverified else "verified",
            "source": source,
        },
    )


def _serialize_decision(result):
    return {
        "commit_allowed": result.commit_allowed,
        "failed_stages": result.failed_stages,
        "summary": result.summary,
        "meta": result.meta,
        "stage_results": [
            {
                "stage_id": stage.stage_id,
                "passed": stage.passed,
                "messages": stage.messages,
            }
            for stage in result.stage_results
        ],
    }

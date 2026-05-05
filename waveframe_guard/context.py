from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
import os

_guard_context = ContextVar("guard_context", default={})


def install_guard(
    *,
    actor=None,
    contract,
    api_key=None,
    mode="local",
    fail_mode="cache",
    policy_refresh=60,
):
    if mode not in {"local", "cloud"}:
        raise ValueError("mode must be 'local' or 'cloud'")

    if fail_mode not in {"open", "closed", "cache"}:
        raise ValueError("fail_mode must be 'open', 'closed', or 'cache'")

    policy_cache = None
    if contract is not None:
        now = datetime.now(timezone.utc)
        policy_cache = {
            "compiled_contract": contract,
            "contract_hash": contract["contract_hash"],
            "fetched_at": now,
            "expires_at": now + timedelta(seconds=policy_refresh),
        }

    _guard_context.set(
        {
            "actor": actor,
            "contract": contract,
            "api_key": api_key,
            "mode": mode,
            "fail_mode": fail_mode,
            "policy_refresh": policy_refresh,
            "policy_cache": policy_cache,
            "failure_count": 0,
            "max_failures": 3,
            "offline": False,
        }
    )


def get_context():
    return _guard_context.get()


def resolve_actor():
    return {
        "id": os.getenv("USER") or "unknown",
        "type": "human",
        "role": os.getenv("WF_ROLE") or "unknown",
    }

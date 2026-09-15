"""Explicit local development gate; never modifies Ledger's environment."""

import os

from .exceptions import AuthorityVerificationError


def require_action_policy_development():
    for name in ("WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"):
        if os.environ.get(name) != "1":
            raise AuthorityVerificationError(f"action policy development requires explicit {name}=1")

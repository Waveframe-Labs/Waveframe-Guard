from __future__ import annotations

import os
import getpass
from typing import Dict, Any

from waveframe_guard.core import run_validation


class GuardViolation(Exception):
    pass


class Guard:

    def __init__(
        self,
        policy: Dict[str, Any],
        mode: str = "shadow",  # "shadow" or "enforce"
    ):
        self.policy = policy
        self.mode = mode

    def enforce(self, action: str, system: str, resource: str):

        def decorator(fn):

            def wrapper(*args, **kwargs):

                context = {
                    "proposer": getpass.getuser(),
                    "env": os.getenv("ENV", "local"),
                }

                decision = run_validation(
                    compiled_contract=self.policy,
                    action={
                        "type": action,
                        "system": system,
                        "resource": resource,
                    },
                    actor=context["proposer"],
                    context=context,
                )

                if not decision["allowed"]:
                    self._handle_violation(decision)

                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def _handle_violation(self, decision):

        message = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️  WAVEFRAME GUARD — EXECUTION BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Reason:
{decision.get("reason")}

Trace Hash:
{decision.get("trace_hash")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

        if self.mode == "enforce":
            raise GuardViolation(message)
        else:
            print(message)
# ---
# title: "Waveframe Guard External Agent Quickstart"
# filetype: "python"
# type: "example"
# domain: "guard-sdk"
# version: "0.14.0-dev"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from waveframe_guard import Guard


@dataclass(frozen=True)
class QuickstartSettings:
    cloud_url: str
    organization_id: str
    api_key: str
    runtime_id: str
    environment: str
    actor_id: str
    actor_role: str
    authority_ref: str

    @classmethod
    def from_environment(cls) -> "QuickstartSettings":
        return cls(
            cloud_url=_required_setting("WAVEFRAME_CLOUD_URL"),
            organization_id=_required_setting("WAVEFRAME_CLOUD_ORGANIZATION_ID"),
            api_key=_required_setting("WAVEFRAME_CLOUD_API_KEY"),
            runtime_id=_required_setting("WAVEFRAME_RUNTIME_ID"),
            environment=os.environ.get("WAVEFRAME_RUNTIME_ENVIRONMENT", "development"),
            actor_id=_required_setting("WAVEFRAME_ACTOR_ID"),
            actor_role=_required_setting("WAVEFRAME_ACTOR_ROLE"),
            authority_ref=_required_setting("WAVEFRAME_AUTHORITY_REF"),
        )


def build_guard(settings: QuickstartSettings) -> Guard:
    return Guard.cloud(
        cloud_url=settings.cloud_url,
        cloud_organization_id=settings.organization_id,
        cloud_api_key=settings.api_key,
        runtime_id=settings.runtime_id,
        environment=settings.environment,
        authority=settings.authority_ref,
        actor_identity={
            "id": settings.actor_id,
            "type": "agent",
            "role": settings.actor_role,
        },
    )


def run_quickstart(
    guard: Guard,
    settings: QuickstartSettings,
) -> dict[str, Any]:
    mutations: list[dict[str, Any]] = []

    @guard.tool(
        authority=settings.authority_ref,
        action="allocate_budget",
        target="account_id",
        include_arguments=("amount",),
        agent={"framework": "custom-python"},
        raise_on_block=False,
        return_result=True,
    )
    def allocate_budget(account_id: str, amount: int) -> dict[str, Any]:
        mutation = {"account_id": account_id, "amount": amount}
        mutations.append(mutation)
        return mutation

    allowed = allocate_budget("quickstart-account", 500)
    blocked = allocate_budget("quickstart-account", 12_500)

    if allowed["executed"] is not True:
        raise RuntimeError("Quickstart authority did not allow the 500-unit action")
    if blocked["executed"] is not False:
        raise RuntimeError("Quickstart authority did not block the 12,500-unit action")
    if mutations != [{"account_id": "quickstart-account", "amount": 500}]:
        raise RuntimeError("Exactly-once mutation assertion failed")

    summary = {
        "runtime_id": settings.runtime_id,
        "actor_id": settings.actor_id,
        "authority_ref": allowed["outcome"]["authority_ref"],
        "allowed_decision": allowed["outcome"]["execution_state"],
        "blocked_decision": blocked["outcome"]["execution_state"],
        "mutation_count": len(mutations),
        "exactly_once": True,
    }

    for key, value in summary.items():
        print(f"{key}={value}")
    print("console_check=Open Activity or Executions and verify both decisions by runtime and authority.")
    return summary


def main() -> None:
    settings = QuickstartSettings.from_environment()
    run_quickstart(build_guard(settings), settings)


def _required_setting(name: str) -> str:
    value = os.environ.get(name)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


if __name__ == "__main__":
    main()

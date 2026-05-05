"""
INTERNAL MODULE - NOT PART OF PUBLIC SDK

This module contains experimental Cloud client functionality
for future Waveframe Cloud integration.

It is not stable and should not be used directly.
"""

import requests


class WaveframeGuard:
    def __init__(self, api_key: str, policy_id: str, base_url: str = "http://localhost:8000"):
        self.api_key = api_key
        self.policy_id = policy_id
        self.base_url = base_url

    def execute(self, action: dict, context: dict, actor: str = "ai-agent-v2"):
        context = self._normalize_context(context)

        return self._request(
            action=action,
            context=context,
            actor=actor,
        )

    def _request(self, action: dict, context: dict, actor: str):
        res = requests.post(
            f"{self.base_url}/v1/enforce",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "policy_id": self.policy_id,
                "action": action,
                "context": context,
                "actor": actor,
            },
        )

        if res.status_code != 200:
            raise Exception(f"Request failed: {res.text}")

        return res.json()

    def _normalize_context(self, context):
        if not isinstance(context, dict):
            raise TypeError("context must be a dictionary")

        required = ["responsible", "accountable"]

        for field in required:
            if field not in context or not context[field]:
                raise ValueError(f"Missing required context field: {field}")

        if "approved_by" not in context:
            context["approved_by"] = None

        return context

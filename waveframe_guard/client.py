import requests

class WaveframeGuard:
    def __init__(self, api_key: str, base_url: str = "http://localhost:8000"):
        self.api_key = api_key
        self.base_url = base_url

    # ---------------------------
    # PUBLIC API
    # ---------------------------

    def execute(self, policy_ref: str, action: dict, context: dict, actor: str = "ai-agent-v2"):
        context = self._normalize_context(context)

        return self._request(
            policy_ref=policy_ref,
            action=action,
            context=context,
            actor=actor,
        )

    # ---------------------------
    # INTERNAL
    # ---------------------------

    def _request(self, policy_ref: str, action: dict, context: dict, actor: str):
        res = requests.post(
            f"{self.base_url}/v1/enforce",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "policy_ref": policy_ref,
                "action": action,
                "context": context,
                "actor": actor,
            },
        )

        if res.status_code != 200:
            raise Exception(f"Request failed: {res.text}")

        return res.json()

    # ---------------------------
    # VALIDATION LAYER (CRITICAL)
    # ---------------------------

    def _normalize_context(self, context):
        if not isinstance(context, dict):
            raise TypeError("context must be a dictionary")

        # enforce required fields
        required = ["responsible", "accountable"]

        for field in required:
            if field not in context or not context[field]:
                raise ValueError(f"Missing required context field: {field}")

        # optional field
        if "approved_by" not in context:
            context["approved_by"] = None

        return context
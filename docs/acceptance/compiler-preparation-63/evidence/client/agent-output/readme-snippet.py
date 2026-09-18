import json

from compiler import compile_action_policy

policy = {
    "schema_version": "action_policy.v1",
    "contract_id": "repository-file-policy",
    "contract_version": "2.0.0",
    "action_requirements": {
        "create": {
            "required_role": None,
            "allow": [{"match": "prefix", "value": "generated/"}],
            "deny": [{"match": "prefix", "value": "generated/private/"}],
        },
        "modify": {
            "required_role": "repository-maintainer",
            "allow": [{"match": "exact", "value": "README.md"}],
            "deny": [],
        },
    },
}
compiled = compile_action_policy(policy)
print(json.dumps(compiled, sort_keys=True, separators=(",", ":")))

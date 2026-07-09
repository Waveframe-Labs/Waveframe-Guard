# ---
# title: "Waveframe Guard Quickstart Example"
# filetype: "python"
# type: "example"
# domain: "guard-sdk"
# version: "0.11.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from waveframe_guard import Guard


compiled_authority = {
    "schema_version": "compiled_authority_contract.v1",
    "contract_id": "finance-policy",
    "contract_version": "1.0.0",
    "authority_requirements": {"required_roles": ["manager"]},
    "approval_requirements": {},
    "artifact_requirements": {},
    "stage_requirements": {},
    "invariants": {},
    "contract_hash": "e4fd822ae1ac5f0228c9042dfd81c7c96b2774bf7e1e5516d9db95880b1aab70",
}

execution_request = {
    "schema_version": "normalized_execution_request.v1",
    "request_id": "transfer-001",
    "action": "wire_transfer",
    "target": "treasury-account",
    "arguments": {"amount": 1250000},
    "artifacts": [],
}


def main() -> None:
    guard = Guard.local(
        authorities={"finance-policy@1.0.0": compiled_authority},
        actor_identity={"id": "user-1", "type": "human", "role": "intern"},
    )

    @guard.protect(authority="finance-policy@1.0.0", raise_on_block=False)
    def wire_transfer(request):
        return "transfer executed"

    result = wire_transfer(execution_request)
    print(f"executed={result['executed']}")
    print(f"decision={result['outcome']['execution_state']}")


if __name__ == "__main__":
    main()

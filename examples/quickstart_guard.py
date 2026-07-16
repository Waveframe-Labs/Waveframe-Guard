# ---
# title: "Waveframe Guard Quickstart Example"
# filetype: "python"
# type: "example"
# domain: "guard-sdk"
# version: "0.13.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from waveframe_guard import Guard


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
        authority="finance-policy@1.0.0",
        actor_identity={"id": "user-1", "type": "human", "role": "intern"},
    )

    @guard.protect(raise_on_block=False)
    def wire_transfer(request):
        return "transfer executed"

    result = wire_transfer(execution_request)
    print(f"executed={result['executed']}")
    print(f"decision={result['outcome']['execution_state']}")


if __name__ == "__main__":
    main()

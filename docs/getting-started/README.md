# Getting Started with Waveframe Guard

Waveframe Guard enforces governance rules at execution time. It blocks actions that violate published authority before they happen.

---

## Installation

For application use:

```bash
pip install waveframe-guard
```

For local development and clean-checkout test runs:

```bash
pip install -e ".[test]"
```

## Basic Usage

The primary SDK path starts from a Ledger-published authority reference:

```python
from waveframe_guard import Guard

guard = Guard.local(
    authority="finance-policy@1.0.0",
    actor_identity={"id": "user-1", "type": "human", "role": "intern"},
)

request = {
    "schema_version": "normalized_execution_request.v1",
    "request_id": "transfer-001",
    "action": "wire_transfer",
    "target": "treasury-account",
    "arguments": {"amount": 1250000},
    "artifacts": [],
}

@guard.protect(raise_on_block=False)
def transfer(execution_request):
    return "transfer executed"

result = transfer(request)
print(result["executed"])
print(result["outcome"]["execution_state"])
```

## Registry Requirement

`Guard.local(authority="finance-policy@1.0.0")` expects a local Ledger-style registry at `contracts/index.json` by default.

That registry must point to a Ledger `authority_bundle.v1` artifact, for example:

```text
contracts/
  index.json
  finance-policy-1.0.0.authority-bundle.json
```

Guard verifies the registry hash, resolves the exact authority reference, loads the authority bundle, validates the bundle and contract hashes, checks lifecycle state, and then passes the verified compiled authority into the existing enforcement pipeline.

The accepted public authority identifier is always explicit and versioned:

```text
finance-policy@1.0.0
```

Unversioned identifiers such as `finance-policy`, implicit `latest`, and filesystem paths are rejected at the published-authority boundary.

## Expected Behavior

```text
False
blocked
```

The wrapped function does not run because the actor does not satisfy the authority requirement.

## Elevating Privileges

```python
guard = Guard.local(
    authority="finance-policy@1.0.0",
    actor_identity={"id": "user-1", "type": "human", "role": "manager"},
)
```

With the required role, the same protected function may execute if the rest of the authority requirements are satisfied.

## Compatibility Paths

Legacy direct-contract inputs remain available for embedded and compatibility use:

```python
guard = Guard.local(
    authorities={"finance-policy@1.0.0": compiled_authority},
    actor_identity={"id": "user-1", "type": "human", "role": "manager"},
)
```

Prefer published authority references for new integrations.

## Cloud Preservation (Optional)

```python
import os

guard = Guard.local(
    authority="finance-policy@1.0.0",
    preserve_to="https://cloud.example",
    cloud_organization_id="org-finance",
    cloud_api_key=os.environ["WAVEFRAME_CLOUD_API_KEY"],
)
```

The same credentials may be supplied through `WAVEFRAME_CLOUD_ORGANIZATION_ID` and `WAVEFRAME_CLOUD_API_KEY`. Guard sends them only as `X-Organization-ID` and `X-API-Key` request headers. The API-key secret is not included in the preservation package or local evidence.

Cloud preservation runs only after Guard has completed local evaluation and written local evidence. Cloud availability does not influence the local enforcement decision.

## Notes

- Guard enforces locally, even if Cloud is unavailable.
- Ledger publishes authority; Guard consumes verified Published Authority bundles.
- CRI-CORE and the existing enforcement pipeline remain unchanged.
- Cloud preservation metadata is post-decision durability evidence, not runtime admissibility.

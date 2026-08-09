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

## External Agent Quickstart

The hosted customer path requires only the installed package, one Python file,
a Cloud runtime credential, an actor identity, and an explicit published
authority reference. It does not require Ollama or a Waveframe repository
checkout.

From an empty directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install waveframe-guard
Invoke-WebRequest https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Guard/main/examples/external_agent_quickstart.py -OutFile quickstart.py
```

Configure the hosted boundary:

```powershell
$env:WAVEFRAME_CLOUD_URL="https://cloud.waveframelabs.com"
$env:WAVEFRAME_CLOUD_ORGANIZATION_ID="acme"
$env:WAVEFRAME_CLOUD_API_KEY="<runtime credential>"
$env:WAVEFRAME_RUNTIME_ID="budget-agent-runtime"
$env:WAVEFRAME_RUNTIME_ENVIRONMENT="development"
$env:WAVEFRAME_ACTOR_ID="budget-agent"
$env:WAVEFRAME_ACTOR_ROLE="allocator"
$env:WAVEFRAME_AUTHORITY_REF="budget-quickstart@1.0.0"
python quickstart.py
```

The selected authority must allow the configured role to allocate 500 units and
require missing approval evidence at 10,000 units or above. The example invokes
one allowed action and one blocked action, asserts that the underlying mutation
runs exactly once, and prints the runtime, actor, authority, and both Guard-owned
decisions. Console Activity or Executions then provides the server-side proof.

`@guard.tool(...)` wraps an ordinary callable. Register that callable with a
custom agent, LangGraph, CrewAI, an OpenAI tool loop, or another framework in the
same way the unguarded tool was registered. Guard remains the mutation boundary;
the framework remains responsible for model calls and orchestration.

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

# Getting Started with Waveframe Guard

Unreleased security migration: **Guard execution is never advisory**. Local/cloud
controls authority resolution, not enforcement strength. Legacy execution and
permission APIs now raise an actionable migration error. Use `Guard.local()` /
`Guard.cloud()` with guarded tools; see [strict execution migration](STRICT_EXECUTION_MIGRATION.md).


Waveframe Guard enforces governance rules at execution time. It blocks actions that violate published authority before they happen.

---

## Installation

For application use:

```bash
pip install waveframe-guard==0.17.0
```

For local development and clean-checkout test runs:

```bash
pip install -e ".[test]"
```

## 30-Second External-Agent Integration

After configuring the Cloud variables below, wrap the customer's existing
mutation function; no Guard-specific agent loop is required:

```python
import os
from waveframe_guard import Guard

guard = Guard.cloud(
    authority=os.environ["WAVEFRAME_AUTHORITY_REF"],
    runtime_id=os.environ["WAVEFRAME_RUNTIME_ID"],
    environment=os.environ["WAVEFRAME_RUNTIME_ENVIRONMENT"],
    actor_identity={
        "id": os.environ["WAVEFRAME_ACTOR_ID"],
        "type": "agent",
        "role": os.environ["WAVEFRAME_ACTOR_ROLE"],
    },
)

allocate_budget = guard.tool(
    action="allocate_budget",
    target="account_id",
    include_arguments=("amount",),
)(existing_allocate_budget)
```

The wrapped callable keeps its normal Python interface. Guard resolves the
complete published authority from Cloud, verifies it, evaluates before
mutation, and reports the execution to Cloud.

## Five-Minute Cloud Quickstart

The hosted customer path requires only the installed package, one Python file,
a Cloud runtime credential, an actor identity, and an explicit published
authority reference. It does not require Ollama, a Waveframe repository
checkout, or a specific agent framework.

From an empty directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install waveframe-guard==0.17.0
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
runs exactly once, and prints the runtime, actor, authority, both Guard-owned
decisions, and both Cloud package, receipt, and proof identifiers. Console
Activity or Executions then provides server-side proof under the configured
runtime and authority.

`@guard.tool(...)` wraps an ordinary callable. Register that callable with a
custom agent, LangGraph, CrewAI, an OpenAI tool loop, or another framework in the
same way the unguarded tool was registered. Guard remains the mutation boundary;
the framework remains responsible for model calls and orchestration.

For a framework-neutral adapter, register the guarded function rather than the
underlying mutation:

```python
guarded_tool = guard.tool(action="publish_release", target="repository")(publish_release)
agent_tools.register(name="publish_release", callable=guarded_tool)
```

The registry and model may select the tool, but only the guarded callable can
reach `publish_release`. Guard remains the enforcement boundary and does not
become the agent framework.

Exactly-once means that the allowed 500-unit callback executes once and the
blocked 12,500-unit callback never executes. The quickstart rejects any other
mutation count, missing preservation receipt/proof, or failed runtime
registration, heartbeat, preservation, or attestation.

## Clean-Machine Acceptance

Release validation builds normal distributions and passes the wheel path to the
acceptance runner:

```powershell
python -m build
$wheel=(Resolve-Path .\dist\waveframe_guard-0.17.0-py3-none-any.whl).Path
python .\tools\acceptance\external_agent_clean_machine.py --install-spec $wheel
```

The runner creates an empty temporary directory outside the checkout, creates a
fresh virtual environment there, and performs a normal `pip install` of the
wheel. It does not use an editable install or add the repository to Python's
import path. The quickstart subprocess runs from that external directory.

## Dependency Compatibility Matrix

These bounds apply to the issue #31 development change, planned for Guard
0.18. Guard 0.18 is **not published**; this dependency-only change keeps the
current package version metadata unchanged.

| Component | Declared runtime range | Python 3.10 minimum matrix | Python 3.14 candidate matrix |
| --- | --- | --- | --- |
| Guard | Issue #31 checkout; planned 0.18 release | Built and installed wheel | Built and installed wheel |
| CRI-CORE | `>=0.13.0,<0.15.0` | Published 0.13.0 | Unpublished 0.14.0 candidate at `411dfaa976fd4b37efc5fd3e39076edcd3603e1b` |
| Proposal Normalizer | `>=0.2.0,<0.3.0` | 0.2.0 | 0.2.0 |
| Governance Ledger | `>=0.7.0,<0.9.0` | Published 0.7.0 (v1/v2; v3 fails closed) | Published 0.8.0 (v1/v2/v3) |
| requests | `>=2.33.0,<3.0.0` | 2.33.0 | 2.34.2 |

The tested endpoints establish the supported release lines; they do not claim
that every future patch has already been tested. Upper bounds are widened only
in a future Guard change after compatibility review, complete behavioral tests,
and installed-package/resolver acceptance. Installation success alone is not
compatibility evidence. Public dependencies use ranges; exact CI constraints
are environment-specific and do not pin transitive dependencies in the library.

Published **Guard 0.17.0 has unbounded CRI, Normalizer, and requests metadata**
and **must not be paired with CRI 0.14**. Its artifacts cannot acquire these
bounds retroactively. Guard 0.18 is the planned supported release for CRI 0.14
and must be published **before** CRI 0.14 to avoid an incompatible resolver
window. Keep Guard #31/#39 and CRI #2/#4 open pending the coordinated work.

Requests 2.32.0 was considered but is
[yanked on PyPI](https://pypi.org/project/requests/2.32.0/).
The chosen 2.33.0 minimum also includes the upstream fixes for
[credential disclosure](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7)
and [predictable temporary extraction paths](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2).
It passes the complete minimum matrix, including the real HTTP Cloud fixture.

The contract compiler remains `0.4.0` in test/dev extras only. Python remains
`>=3.10`. Cloud acceptance uses a local HTTP publication fixture.
Guard 0.17.0 can parse and verify matching v2 and v3 publication envelopes.
Current released/hosted Cloud does not yet serve the complete atomic v2 or v3 publication path.
Cloud PR #133 remains the pending v2 server implementation.
Hosted v3 serving requires an additional Cloud update. Guard
verifies the complete publication before evaluating its compiled contract;
translation proposals and private provider evidence are not required.

See the [dependency inventory and validation record](../security/ISSUE_31.md)
for the reproducible matrix and historical resolver reproduction.

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

That registry may point to a legacy Ledger `authority_bundle.v1`, or to a native
v2 bundle plus its publication receipt. The v2 layout is:

```text
contracts/
  index.json
  repository-authority-1.0.0.authority-bundle.json
  repository-authority-1.0.0.publication-receipt.json
```

For v2, the registry entry supplies `receipt_path` and `receipt_hash` alongside
the existing bundle and contract fields. Guard verifies the registry, calls
Ledger's public bundle and receipt validators, checks the complete identity and
hash chain, checks lifecycle state, derives the published typed runtime facts,
and only then evaluates the exact compiled authority.

The path-named registry fields are portable logical identifiers, not evidence
about a local filesystem or Cloud tenant layout. Application code selects the
authority and resolver; the resolver retrieves bundle and receipt bytes, while
Guard verifies their published hashes. Applications do not construct facts or
call Ledger validators.

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

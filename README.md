<p align="center">
  <img src="https://raw.githubusercontent.com/Waveframe-Labs/.github/main/assets/branding/canon_wf_logo_extended.png" width="700">
</p>

# Waveframe Guard

Stop unsafe AI and automated actions **before they execute**.

Waveframe Guard is an execution-boundary SDK. It wraps sensitive actions, resolves compiled authority, evaluates through CRI-CORE, and only runs the action when the outcome is allowed.

Current release: `0.11.0`.

```text
Guard does not generate actions.
Guard does not author governance.
Guard does not replace Cloud.
Guard decides whether this action may run now.
```

## Install

```powershell
pip install waveframe-guard==0.11.0
```

Run the local quickstart example from a repository checkout:

```powershell
python examples/quickstart_guard.py
```

Expected output:

```text
executed=False
decision=blocked
```

## 30-second example

```python
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

request = {
    "schema_version": "normalized_execution_request.v1",
    "request_id": "transfer-001",
    "action": "wire_transfer",
    "target": "treasury-account",
    "arguments": {"amount": 1250000},
    "artifacts": [],
}

guard = Guard.local(
    authorities={"finance-policy@1.0.0": compiled_authority},
    actor_identity={"id": "user-1", "type": "human", "role": "intern"},
)

@guard.protect(authority="finance-policy@1.0.0", raise_on_block=False)
def wire_transfer(execution_request):
    return "transfer executed"

result = wire_transfer(request)
print(result["executed"])
print(result["outcome"]["execution_state"])
```

Expected result:

```text
False
blocked
```

The wrapped function does not run because the actor does not satisfy the compiled authority requirement.

## Primary developer path

Use one object first:

```python
from waveframe_guard import Guard

guard = Guard.local(workspace=".guard-local")

@guard.protect(authority="finance-policy@1.0.0")
def protected_action(execution_request):
    return perform_sensitive_action(execution_request)
```

Guard sits before the mutation boundary. It loads compiled authority, validates the normalized execution request, evaluates the action through CRI-CORE-backed runtime logic, emits an enforcement outcome, and writes local receipt/replay artifacts for inspection.

## What Guard owns

Guard owns the developer-side enforcement boundary:

- local SDK integration
- compiled authority resolution
- normalized execution request enforcement
- local allow/block/escalate outcomes
- continuation windows and deferred release checks
- local receipts, replay artifacts, and runtime diagnostics
- evidence spooling for later Cloud submission

Guard does **not** author governance, publish authority, host organization workflows, operate the long-term evidence system, or ship the proprietary Guard Inspector UI.

## Guard, Cloud, and Ledger

| Product | Responsibility |
| --- | --- |
| Guard | Enforce locally before execution. |
| Cloud | Store authority, evidence, receipts, replay packages, lifecycle state, and continuity records. |
| Ledger / Workspace | Author, review, activate, and publish deterministic governance authority. |
| CRI-CORE | Deterministic admissibility kernel used under the Guard boundary. |

The product flow is:

```text
Ledger publishes authority
        -> Cloud distributes authority and records evidence
        -> Guard enforces before execution
        -> Cloud stores receipts and replay history
```

Cloud can publish lifecycle metadata such as `active`, `superseded`, or `revoked`, but Cloud does not decide runtime admissibility. Guard evaluates locally against compiled authority.

## Local authority registry

For applications that resolve published contracts from a local registry, use the runtime layer:

```python
from waveframe_guard import GovernedRuntime

runtime = GovernedRuntime(
    registry_path="contracts/index.json",
    reject_revoked_authority=True,
    warn_on_superseded=True,
)

runtime.install_actor({"id": "user-1", "type": "human", "role": "manager"})
runtime.bind_contract("finance-policy@1.0.0")

result = runtime.execute(
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)
```

Runtime authority refs are explicit and versioned. Use `finance-policy@1.0.0`; unversioned IDs such as `finance-policy` are rejected because replay, audit, and cache integrity depend on deterministic authority identity.

## Cloud-connected runtime

For application code that needs Cloud authority metadata and evidence delivery, use the Cloud-connected runtime:

```python
from waveframe_guard import GuardRuntime

runtime = GuardRuntime.from_cloud(
    authority="finance-policy@1.0.0",
    api_key="...",
)

result = runtime.execute(
    actor={"id": "user-1", "type": "human", "role": "manager"},
    fn=transfer,
    args=(1250000,),
    raise_on_block=False,
)

runtime.flush_evidence()
```

`execute(...)` still enforces locally. Cloud availability is only required when you explicitly call `flush_evidence()`.

Guard writes evidence to a durable local spool first:

```text
.waveframe_guard/evidence/
  pending/
  sent/
  failed/
```

If a flush fails, evidence is retained and can be submitted again later.

## Continuation and deferred release

Guard separates admissibility from release. An action can be admissible at T1, queued or delayed, and then blocked at T2 if its continuation lease no longer validates.

Guard emits:

- `guard_continuation_lease.v1`
- `guard_release_validation.v1`
- `release blocked` when execution was admissible earlier but a runtime dependency expired before release

Continuity signals are not Cloud decisions. Guard evaluates continuity locally; Cloud may display and preserve the evidence.

## Guard Inspector

Guard Inspector is the private operational visualization layer for SDK-emitted evaluations, receipts, replay artifacts, continuity signals, and release posture.

It consumes Guard outcomes and artifacts. It is not part of the public Guard SDK package, does not author policy, and does not own enforcement semantics.

## Repository surface

The public Guard surface includes:

- SDK facade
- local runtime
- deterministic evaluation model
- continuation governance
- replay artifacts
- deferred release model
- examples
- docs
- tests
- sample compiled contracts

Non-production or split-bound work is quarantined under `temp/`. In particular, `temp/labs/cloud_runtime/` is a lab preview for future Cloud product work, not production Guard Cloud and not required for local enforcement.

## Release discipline

Every substantive Guard change must update the release surface together:

```text
code
+ README / docs
+ CHANGELOG
+ pyproject metadata
+ version-dependent files
+ tests
+ package build
+ tag
```

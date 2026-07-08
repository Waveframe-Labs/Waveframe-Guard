# Finance Policy to Guard Demo

This is the canonical local Waveframe Guard demo.

It shows how a plain-text finance policy becomes compiled authority and how Guard blocks or allows a protected function before execution.

## What this demo proves

```text
Plain-text company policy
  -> Governance-Ledger review artifact
  -> compiler-produced authority
  -> Guard.local(...)
  -> @guard.protect(...)
  -> BLOCKED transfer without CFO approval
  -> ALLOWED transfer with CFO approval
  -> .guard-local evidence artifacts
```

The key product claim is simple:

> Guard stops the protected transfer function from running when required authority or evidence is missing.

## Policy used

```text
Transfers over $1,000,000 require CFO approval.
The requester and approver must be different.
All transfer approvals must be recorded for audit purposes.
```

## Run

From the repository root:

```powershell
python examples\finance_policy_to_guard_demo\run_demo.py
```

Expected decision output:

```text
Guard decision: BLOCKED - required approval missing: cfo
Protected transfer executions: 0

Guard decision: ALLOWED - approval evidence satisfied
Protected transfer executions: 1
```

## Artifacts written

The demo writes local artifacts under:

```text
examples/finance_policy_to_guard_demo/demo_artifacts/
```

Guard SDK evidence is written under:

```text
examples/finance_policy_to_guard_demo/demo_artifacts/.guard-local/
  evaluation-history.jsonl
  receipts/
  manifests/
  replays/
```

Those artifacts are produced by the public Guard SDK local store path, not by a hand-written fake event.

## Demo truthfulness note

The enforcement side uses the canonical public SDK path:

```python
from waveframe_guard import Guard

guard = Guard.local(...)

@guard.protect(...)
def protected_transfer(...):
    ...
```

The publication portion is intentionally compressed locally. It uses Governance-Ledger extraction/review and the installed contract compiler, then writes the local registry artifacts needed for the Guard demo. It does not claim to be the full Ledger production publication flow.

The purpose of this demo is to prove the local developer enforcement path:

```text
policy-derived authority -> Guard decision -> protected function blocked/allowed -> local receipts
```

Cloud and Inspector are intentionally out of scope for this first local proof.

## Test

```powershell
python -m pytest tests/test_finance_policy_to_guard_demo.py
```

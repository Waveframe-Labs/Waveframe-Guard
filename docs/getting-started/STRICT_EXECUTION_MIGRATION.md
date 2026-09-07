# Strict execution migration (Unreleased)

Guard execution is never advisory. Guard local/cloud mode controls authority
resolution and service connectivity, not enforcement strength. Advisory CRI
evaluation is not permission to execute a callback. Local and cached authority
must still be enforced before execution.

## Legacy APIs now fail closed

The following symbols remain importable temporarily, but their execution or
permission operations always raise `LegacyExecutionError`, a `GovernanceError`
subclass with stable code `GUARD_LEGACY_EXECUTION_UNSUPPORTED`:

- `waveframe_guard.execute()` and invocation of `@waveframe_guard.guard`.
- `GovernedRuntime.execute()` and `execute_proposal()`.
- `GovernedRuntime.evaluate()` and `revalidate()`, which previously returned
  legacy permission without establishing strict execution evidence.
- The `GuardRuntime` alias, including instances created by `from_cloud()`.
- `waveframe_guard.evaluate_admissibility()` (also available in `.runtime`).

These APIs cannot establish CRI's strict integrity/publication prerequisites.
Compiled contract hashes, actor roles, approval lists and cached policy alone
do not supply that evidence. Guard does not synthesize empty or fabricated
integrity/publication mappings. Adding such fields to legacy inputs cannot
reenable execution.

Rejection occurs before authority resolution, CRI evaluation, callback invocation,
decision logging, receipts or execution evidence. `raise_on_block=False` does not
suppress this migration error. Legacy `fail_mode="open"` cannot execute an
ungoverned callback when Cloud or policy resolution fails. `install_guard()`
still accepts legacy configuration, but cannot authorize execution.

Existing registry and historical artifact helpers remain available; reading a
historical allowed result does not revalidate it or grant new execution permission.
No replacement advisory callback API is provided.

## Move to guarded tools

Configure the current `Guard` class and register the decorated callable with
your application or agent. Supply the real published authority and trusted
runtime identity/approval inputs appropriate to that authority:

```python
from waveframe_guard import Guard

guard = Guard.local(
    authority="finance-policy@1.0.0",
    actor_identity={"id": "agent-1", "type": "agent", "role": "analyst"},
)

@guard.tool(action="wire_transfer", target="account_id")
def wire_transfer(account_id, amount):
    return perform_transfer(account_id, amount)  # your application operation
```

For Cloud authority resolution, use `Guard.cloud(authority=..., ...)` with the
documented Cloud credentials/settings, then the same tool boundary. See the
[getting started guide](README.md). Both modes enforce before invoking the tool.
The modern boundary uses Guard's authority validation and enforcement pipeline;
it does not call CRI's advisory evaluator. Its allowed, blocked, escalation and
network-failure behavior is unchanged by this migration. Failure to preserve an
already governed decision is distinct from executing without resolved authority.

Repository mutation requires a trusted `repository_root` and
`@guard.repository_tool(target="path", action="modify")`; the callback writes
through the supplied capability. Keep mutation content outside the execution
request. See the [repository migration guide](../architecture/REPOSITORY_WORKSPACE.md).
PR #34's existing-file mutation protection is unchanged. V1 literal authority
and verified Ledger v2/v3 publication paths remain supported by the current API.

This security migration is intended for Guard 0.18.0. It does not prepare a
release or change package/version metadata. The
[issue #39 inventory and reproduction](../security/ISSUE_39.md) records the
affected paths and the evidence behind this change.

# Legacy v2 live authorization containment

This source correction is pending independent review; it is not a release or
deployment. Coordination and the original executable reproduction:
https://github.com/Waveframe-Labs/Waveframe-Operations/issues/3#issuecomment-6568857854

For `compiled_authority_contract.v2`, Guard requires an affirmative path allow
before live authorization. A role requirement or a deny rule grants no path.
Deny matches retain precedence; all existing nonempty allow/deny matching stays
unchanged. A non-denied target with an empty allow list is blocked with
`affirmative_path_grant` and instructions to obtain explicit path allows in a
new source/authority revision with fresh human approval. An empty deny list
does not make an empty allow list safe. Malformed scopes and requests still
fail closed.

The check is in the shared cognition evaluator, after intake and deny matching,
on every evaluation. Fresh loads, resolved authority, warm verified cache and
already activated boundaries all reach it. There is no cache or request opt-out.
The scope is the compiled contract discriminator: both native bundle v2 and
bundle v3 can contain compiled contract v2. Historical compiled v1 and
action-scoped compiled v3 behavior are unchanged. No compiler output, contract
hash, artifact schema, package version, dependency range or publication validator
is changed.

Historical validation is distinct from permission to execute. Old bundle,
receipt and decision bytes stay intact. Local replay remains logical decision
comparison only and never invokes a callback or recreates the filesystem.
Replaying an old deny-only admission with this evaluator reports a mismatch
and the new blocked decision, preserving the original outcome hash. It does
not rewrite the old admission to pretend it was blocked. Replays of new blocked
decisions and unchanged explicit grants match normally. Exact historical
decision reproduction remains possible with the pinned original evaluator in
an offline, non-executing investigation; this patch adds no historical bypass
to the live SDK.

Tests: `python -m pytest -q tests/test_v2_affirmative_path_grant.py` reruns the
33 evaluations using 11 historical authorities from four pinned producer stacks,
plus verified cache/resolution, both publication envelopes, callback refusal,
deny precedence, empty rules, unchanged v1 and historical replay checks. Run the
full suite for action-v3 and other compatibility coverage. Matrix producer
versions are recorded in the fixture, not represented as new backports of
Guard 0.16–0.18. The patched Guard still declares Ledger >=0.9,<0.10.

Deployment inventory and supported backports require separate owner decisions.
Old installed evaluators remain permissive until explicitly upgraded; no Cloud
or production authority is changed by these PRs. Replacements require explicit
grants, new source and authority revisions, and fresh review/approval. Existing
hash bindings reject approval reuse against changed meaning; they do not
authenticate approver identity or enforce global revision uniqueness.

## Patch upgrade guidance

The 0.9.1 Ledger / 0.19.1 Guard security patch candidates require an affirmative
path grant. Guard refuses live `compiled_authority_contract.v2` authorization
when `target_requirements.allow` is empty, including deny-only and role-only
authority, with an actionable diagnostic. Deny precedence and explicit grants
remain enforced. Ledger gates new pack-1 repository approval/finalization on
confirmed, enforceable path allows; candidate controls alone do not count.

Historical bundles, receipts, hashes and approvals remain unchanged and
verifiable. Replay retains recorded evidence and exposes any current live
refusal; it does not restore the old permission. Historical v1 and action-scoped
v3 evaluation semantics are unchanged. Replace missing grants with a new source
and authority revision and fresh human review/acceptance. Never reuse an old
approval for changed grants.

Previously published Ledger 0.9.0 and Guard 0.19.0 remain affected in the reproduced
scope. Dependency ranges still admit older packages. After separate publication
approval, explicitly upgrade both packages:

```text
python -m pip install --upgrade governance-ledger==0.9.1 waveframe-guard==0.19.1
python -m pip check
```

A Ledger-only upgrade does not patch an older Guard; a Guard-only upgrade does
not supply Ledger's new-authoring gate. An already satisfied optional extra does
not establish that both patches are installed. No Cloud activation, production
consumer upgrade, or automatic repair of existing approvals is claimed.

These are unreleased candidates. Historical action-policy certification remains
unchanged; separate distribution acceptance must validate these exact artifacts.
Publishing requires separate owner approval and must use only the accepted
files, with SHA256 equality checked on PyPI for Ledger before Guard upload.
Final tags must bind the exact accepted commits (Ledger annotated, Guard
lightweight). No tags or publication are part of this preparation.

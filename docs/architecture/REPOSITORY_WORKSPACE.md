# Repository workspace boundary

This unreleased boundary addresses [Guard #33](https://github.com/Waveframe-Labs/Waveframe-Guard/issues/33).
One Guard runtime protects one explicitly bound repository. `workspace` continues
to name the evidence store; `repository_root` names the protected filesystem root.
These are separate settings. Initialization is trusted and requires an absolute,
existing repository directory. It resolves the supplied root once and retains an
open handle and filesystem identity until `guard.close()` or object destruction.

## Public API and migration

```python
from pathlib import Path
from waveframe_guard import Guard, RepositoryTarget

guard = Guard.local(
    authority="repository-authority@1.0.0",
    repository_root=repo_root,  # absolute existing directory on supported Windows or Linux
    workspace=".guard-local",
)

@guard.repository_tool(target="path", action="modify")
def write_file(path: RepositoryTarget, content: bytes):
    return path.write_bytes(content)

try:
    write_file("docs/guide.md", b"Updated guide\n")  # existing regular file
finally:
    guard.close()
```

Minimal before/after callback migration:

```python
# Before: the callback independently interprets the original path.
@guard.tool(target="path", action="modify")
def write_file(path, content):
    return Path(path).write_bytes(content)

# After: initialize Guard with repository_root, then use the supplied capability.
@guard.repository_tool(target="path", action="modify")
def write_file(path, content):
    return path.write_bytes(content)
```

`Guard(...)`, `Guard.local(...)`, and the Guard SDK's `Guard.cloud(...)` accept
`repository_root: str | Path | None`. This does not change Cloud endpoints,
schemas, or service implementation. `repository_tool` requires the name of the
callback argument to replace. Its other options are `authority`, `action`
(default `modify`), `raise_on_block` (default true), and `return_result` (default
false). No request builder or alternate target resolver is accepted. Content and
other callback arguments are excluded from evidence.

The lower-level equivalent is
`guard.boundary_for().execute_repository(callback, execution_request=request)`;
the callback receives exactly one `RepositoryTarget`. Its read-only
`relative_path` property is for display. Its `read_bytes()` and
`write_bytes(bytes)` methods operate on the bound file handle. It has no
`__fspath__` implementation, cannot select another path, and expires when the
callback exits. Callbacks must not retain it or use private attributes.

Repository-bound `evaluate` and `execute_repository` accept exactly this closed
request projection, with all six fields required:

```python
request = {
    "schema_version": "normalized_execution_request.v1",
    "request_id": "edit-1",
    "action": "modify",
    "target": "docs/guide.md",
    "arguments": {},
    "artifacts": [],
}
content = b"Updated guide\n"  # stays outside execution_request and evidence
guard.boundary_for().execute_repository(
    lambda target: target.write_bytes(content), execution_request=request,
)
```

Nonempty arguments/artifacts, extra fields (including nested provider, binding,
path or content metadata), incorrect container types and noncanonical targets
are rejected, never silently redacted. Request IDs and actions must be ASCII
tokens matching `[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}`; they cannot carry paths.
Validation precedes authority comparison, filesystem binding, all local artifact
writes, Cloud preservation and callbacks. Diagnostics never echo rejected values.
Mutation content and other parameters must travel only through trusted callback
closures or decorator arguments, not request metadata. Literal v1 requests retain
their existing non-repository behavior.

`boundary_for().evaluate(request, save=False)` validates the filesystem binding
and performs an evaluation without mutation. An admissible evaluation is not a
reusable filesystem capability or a promise that mutation is supported.

Verified domain routing uses `guard.target-domain-resolver.v1`, an explicit mapping
of the verified domain-pack ID/version/hash AND runtime-fact-schema ID/version/hash.
The current repository-changes/1.0.0 mapping requires `repository_root`; unknown
future domain identities fail closed. The contract schema version alone never
selects repository semantics. V1 compiled contracts have **no domain
identity**: Guard cannot infer one from a contract name or target spelling.
For v1 target-scoped SDK authorities, an omitted binding now raises
`RepositoryBoundaryError` with a migration diagnostic. Repository integrations
supply `repository_root`; applications with unrelated literal string targets
explicitly supply `target_domain="literal"`. This is trusted configuration,
never a request-controlled switch. It cannot override a verified repository
domain. V1 authorities without target rules remain generic unless explicitly
bound to a repository. Applications must declare those repository uses too.

The pure `evaluate_runtime` contract evaluator retains literal semantics. It
does not execute callbacks or attest to filesystem safety. Saved replay also
reproduces the logical decision, not the historical filesystem state.

## Target binding and technical proof

Every target-scoped SDK decision includes frozen `guard_target_binding.v1`
provenance: `target_domain` (`repository_path` or `literal`),
`workspace_binding_id`, `adapter_version`, `assurance_class`,
`authority_contract_hash` and `domain_resolver`. `boundary.target_binding` is a
frozen object. Returned evidence dictionaries are copies; changing a copy cannot
change the boundary. Runtime configuration or scoped-contract substitution after
activation fails closed. An execution request or context cannot supply reserved
binding fields to override or impersonate trusted provenance.

The workspace ID is a random opaque identifier for one workspace activation. It
does not encode or hash the absolute path. Boundaries from the same Guard share
it; reinitializing Guard creates a new activation ID, even for the same root.
Repository assurance is `guard.repository-file.v2` with
`ntfs-sharing-locks.v1` or `linux-openat2-descriptor.v1`. Literal semantics use
`guard.literal-target.v1` and `literal-comparison.v1`, with no workspace ID.

Binding data and its canonical hash accompany the evaluation. The binding is
included in runtime evidence, saved inputs, receipt hashes, run identity,
lineage/replay basis, and v2/v3 execution attestations. Thus the same v1 authority
and request used with literal semantics have different technical proof from a
repository-bound decision. Normative authority caches never store the runtime
binding: sharing a verified authority cache cannot reuse a workspace or change
target semantics. No generated binding evidence contains the absolute root.

Replay reports `replay_scope="logical_decision_only"`,
`filesystem_state_recreated=false` and (when a binding was recorded)
`binding_assurance="recorded_not_revalidated"`. It retains the original binding
and verifies its receipt integrity; it does not reopen the workspace, recreate
historical filesystem state, authorize a fresh mutation or execute a callback.

## Authority-version-neutral execution evidence

Admitted repository execution attempts emit `guard_execution_attestation.v2`
for v1, v2 and v3 authorities. The additive artifact has a discriminated
`authority_basis`: `compiled_contract` records the contract ID/version, declared
contract hash and full canonical contract hash; `published_authority` additionally
records real authority-evidence and runtime-facts hashes. V1 does not fabricate
publication evidence or use those fields to mean something else. Validation of
existing `guard_execution_attestation.v1` artifacts is unchanged.

V2 attestations bind the accepted closed request and its hash, captured target
binding and its hash, authority basis, decision outcome hash, decision receipt
hash (when saved), and execution state into a canonical attestation hash. Reload
validates those links against the saved decision. These are integrity hashes,
not signatures against someone authorized to rewrite every local artifact.

| Result | Callback invoked / completed | Execution | Mutation / executed |
| --- | --- | --- | --- |
| Blocked or unsupported before callback | false / false | not_run | not_performed / false |
| Callback succeeds | true / true | succeeded | executed / true |
| Callback fails before completion | true / false | failed | unknown / null |
| Post-callback validation fails | true / true | failed | unknown / null |

The failure attestation is attached to the `RepositoryBoundaryError.evaluation`
and saved locally when enabled. An incomplete marker precedes invocation so an
interrupted process does not leave a success claim. A malformed/unclosed request
is rejected before admission and emits **no artifacts at all**. A valid request
refused by filesystem binding before authority comparison emits a standalone
`not_evaluated`/`not_run` attestation with null decision/receipt hashes: no logical
decision is fabricated. Missing trusted configuration or invalid authority
activation cannot produce a trusted execution proof. `save=False` returns proof
without writing it. No failure evidence claims rollback of written bytes.

Cloud preservation continues to capture the **decision only**, before execution;
repository evaluations label this `cloud_preservation_scope =
"decision_only_not_final_execution"`. Final execution attestations are local and
are not claimed to have been uploaded by that preservation call. Existing Cloud
runtime attestation calls for v2/v3 remain unchanged and separate. This PR changes
no Cloud API or protocol; Cloud integration migration remains pending.

## Accepted paths and filesystem identities

Requests are accepted unchanged or rejected; no cleanup or string coercion occurs.
Paths use forward slashes and nonempty components. Absolute, drive-relative,
UNC/device, backslash, repeated separator, dot/dot-dot, NUL/control, stream,
wildcard, Windows reserved-device and trailing-space/dot forms are rejected
before authority comparison. The initial supported subset is printable ASCII,
up to 255 characters per component and 4096 overall. Unicode and other ambiguous
representations fail closed. Repository rule values must fit the same subset;
a prefix may end in one slash. Compiled artifacts themselves are never rewritten.

Existing components must use their actual directory-entry spelling. Short-name,
case and normalization aliases are rejected. Windows queries each directory's
case behavior; mixed behavior beneath the root is unsupported. On a
case-insensitive workspace, a case alias of any deny rule is rejected even when
the directory's stored spelling differs from the rule. On a supported
case-sensitive filesystem, distinct case spellings remain distinct targets.

All symlinks and Windows reparse points (including junctions and mount points)
are rejected beneath the resolved root, even if they point inside it. Hard-linked
files, nonregular targets, mount crossings, unknown identities, inaccessible
ancestors, and unsupported filesystems fail closed. For a missing target or
parent, evaluation validates every existing ancestor. Missing descendants do not
make a symlinked parent admissible. Mutation requires an existing regular file.

## Authorization, mutation, and OS limits

The generic `tool`, `protect`, and `execute` callbacks cannot establish this
boundary because their arguments can describe a different target from the
evaluated request. Repository mutation through them fails closed.

The repository adapter performs a nonpersisted preflight, securely opens the
existing target without truncation, and evaluates again against that bound target.
The callback mutates through this already opened file descriptor, not a reopened
request string. Guard revalidates workspace and target identity immediately
before and after the callback and before capability reads/writes, and expires
the capability in a `finally` block. An allowed callback runs exactly once;
rejected requests run zero callbacks.

On Windows NTFS, Guard additionally holds the entire absolute ancestor chain and
target without write/delete sharing until the callback exits. Sharing conflicts
fail closed, which can conflict with editors holding incompatible handles.
Writes replace contents in place, not as an atomic transaction, and can partially
complete on I/O errors. A post-callback substitution failure reports failure with
unknown mutation outcome; it cannot undo bytes already written. An admissible
authorization result must never be read as proof of successful mutation.

| Platform/form | Evaluation | Mutation |
| --- | --- | --- |
| Local Windows NTFS with verifiable directory case behavior | Supported | Existing regular files through the bound capability |
| Linux 5.6+ x86-64/aarch64, case-sensitive ext4/XFS/Btrfs without casefold, tmpfs | Supported using `openat2` | Existing regular files through the opened descriptor |
| Network/unknown filesystems, other OSes, Linux without required syscall | Fails closed | Fails closed |
| File/directory creation, rename, deletion | Missing paths may be evaluated | Fails closed |

Linux uses `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`; the last flag
also rejects same-device bind mounts. Mutation uses the descriptor returned by
that lookup. Revalidation compares the pinned identities and repeats secure
resolution to detect namespace replacement and newly introduced mounts. An open
descriptor does not freeze the namespace: these checks detect changes but are
not an OS-level sandbox or a guarantee against an independently authorized writer.

The agent controls request values. Guard, configuration, authority selection,
callback, adapter, kernel and filesystem driver are trusted. A callback must
use the capability for every governed mutation. Direct filesystem access outside
the adapter, and concurrent untrusted processes with independent repository-write
authority, are outside this in-process SDK guarantee. Accidental or detected
substitution still fails closed wherever detectable, including after a callback;
that does not establish rollback. Guard does not control direct bypass, sandbox
Python, or require a broker, FUSE layer, container or privileged service.

Evidence preserves the accepted canonical target. Rejected path values fail
before authority evaluation; binding failures do not become success attestations.
Acceptance outputs separate `authorization_evaluation=admissible|blocked` from
`mutation_execution=executed|blocked|unsupported`. Evaluation-only acceptance runs
no callbacks and explicitly reports `mutation_not_requested=true`. Mutation
acceptance requires both exactly-once invocation and changed file bytes, on
Windows and Linux; refusal alone cannot pass it.

These OS choices follow the documented behavior of
[Windows CreateFile sharing and reparse flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [Linux openat2 resolution restrictions](https://www.man7.org/linux/man-pages/man2/openat2.2.html).
XFS's legacy ASCII case-insensitive mode is rejected using its
[filesystem geometry flags](https://man7.org/linux/man-pages/man2/ioctl_xfs_fsgeometry.2.html).

## Compatibility and release recommendation

Recommend **0.18.0**, not a silent 0.17.x behavior change. Repository integrations
must supply a root and replace generic path callbacks; v1 target-scoped literal
integrations must declare their domain. Existing-file mutation is supported on
the Windows and Linux platforms above under the trusted adapter boundary. V1/v2/v3
authority verification, caches, compiled contracts, capability catalogs, Ledger
schemas, unrelated domain matching, and Cloud-resolution protocols are unchanged.

This PR does not prepare that release: package version, citation, tags, release
metadata and dependency conventions remain at the current main baseline. Cloud
integration migration is a separate coordinated change after review.

Remaining operations stay fail closed and have focused follow-ups:
[macOS existing-file support #35](https://github.com/Waveframe-Labs/Waveframe-Guard/issues/35),
[creation #36](https://github.com/Waveframe-Labs/Waveframe-Guard/issues/36),
[rename #37](https://github.com/Waveframe-Labs/Waveframe-Guard/issues/37), and
[deletion #38](https://github.com/Waveframe-Labs/Waveframe-Guard/issues/38).

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
    repository_root=Path("C:/work/project"),
    workspace=".guard-local",
)

@guard.repository_tool(target="path", action="modify")
def write_file(path: RepositoryTarget, content: bytes):
    return path.write_bytes(content)

try:
    write_file("docs/guide.md", b"Updated guide\n")  # existing file, local NTFS
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

`boundary_for().evaluate(request, save=False)` validates the filesystem binding
and performs an evaluation without mutation. An admissible evaluation is not a
reusable filesystem capability or a promise that mutation is supported.

V2 and v3 publications retain their existing verified repository domain identity
and require `repository_root` at use. V1 compiled contracts have **no domain
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

The repository adapter performs a nonpersisted preflight. On supported Windows
NTFS, it then acquires file and complete ancestor handles without write/delete
sharing, rejects reparse points, verifies the pinned workspace identity, and
evaluates again while holding those handles. Only that locked evaluation
authorizes the callback. The callback uses the already opened file handle.
The entire absolute ancestor chain is held until the callback exits; sharing
conflicts fail closed. This can conflict with editors or other applications
holding incompatible handles. Writes replace file contents in place; they are
not atomic content transactions and may partially complete on an I/O error.

| Platform/form | Evaluation | Mutation |
| --- | --- | --- |
| Local Windows NTFS with verifiable directory case behavior | Supported | Existing regular files through the bound capability |
| Linux 5.6+ x86-64/aarch64, ext4 without casefold, XFS, Btrfs, tmpfs | Supported using `openat2` | Fails closed |
| Network/unknown filesystems, other OSes, Linux without required syscall | Fails closed | Fails closed |
| File/directory creation, rename, deletion | Missing paths may be evaluated | Fails closed |

Linux resolution uses `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`;
the last flag rejects same-device bind mounts as well. It does not solve the
subsequent rename/link race for mutation: an open descriptor pins an object but
does not keep that object inside the authorized pathname. The current adapter
therefore refuses **all POSIX repository mutation**. Adding it requires an
enforceable namespace-isolation mechanism or a separate native adapter with a
demonstrated guarantee. There is no `Path.resolve()` fallback, trusted boolean
claim of isolation, or unsafe opt-in.

The attacker may control request values and attempt filesystem substitution
using ordinary filesystem operations. Initialization, authority selection,
Guard's process, callback implementation, kernel and filesystem driver are
trusted. A callback must use the capability for every governed mutation. Guard
does not sandbox Python, control direct filesystem access, defend against an
administrator/kernel bypass, or prevent other programs from modifying files
outside this adapter. Evidence preserves the accepted relative target; rejected
path values produce an exception before an evaluation artifact is saved. OS
binding failures are not authority denials and do not create a success attestation.

These OS choices follow the documented behavior of
[Windows CreateFile sharing and reparse flags](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [Linux openat2 resolution restrictions](https://www.man7.org/linux/man-pages/man2/openat2.2.html).

## Compatibility and release recommendation

Recommend **0.18.0**, not a silent 0.17.x behavior change. Repository integrations
must supply a root and replace generic path callbacks; v1 target-scoped literal
integrations must declare their domain. POSIX repository mutation is deliberately
unavailable until its isolation contract is implemented and reviewed. V1/v2/v3
authority verification, caches, compiled contracts, capability catalogs, Ledger
schemas, unrelated domain matching, and Cloud-resolution protocols are unchanged.

This PR does not prepare that release: package version, citation, tags, release
metadata and dependency conventions remain at the current main baseline. Cloud
integration migration is a separate coordinated change after review.

# Authority Loading Boundary

Status: emerging architecture boundary.

Guard should ask for published authority by explicit authority reference:

```python
from waveframe_guard.authority import load_authority

authority = load_authority("finance-policy@1.2.0")
```

The public identifier is always `name@x.y.z`.

No paths, filenames, `latest`, non-semver labels, or implicit resolution are
accepted by the public loader API.

## Pipeline

```text
authority_ref
    |
    v
AuthorityResolver
    |
    v
RegistryEntry
    |
    v
BundleLoader
    |
    v
Bundle
    |
    v
AuthorityVerifier
    |
    v
LoadedAuthority
```

Each stage has one responsibility:

- `AuthorityResolver` maps an explicit authority ref to a registry entry.
- `AuthorityResolver` verifies `registry_hash` before trusting registry entries.
- Local registry artifact paths are workspace-root-relative, not
  registry-file-relative.
- `BundleLoader` opens the published authority bundle and returns it unchanged.
- `AuthorityVerifier` owns all trust decisions.
- `LoadedAuthority` is the verified authority object Guard can consume.

Canonical published-authority registry entries must provide:

- `authority_ref`
- `contract_id`
- `contract_version`
- `contract_hash`
- `bundle_path`
- `bundle_hash`
- `lifecycle_state`

For canonical published authority, lifecycle handling is fail-closed:

- `active` is loadable
- `superseded` is blocked by default
- `revoked` is blocked
- missing lifecycle state is malformed
- unknown lifecycle state is malformed

The canonical bundle hash is the SHA-256 of the canonical JSON payload:

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

## Loader Invariant

Authority loading is not authority transformation.

AuthorityLoader never modifies authority.
AuthorityLoader never upgrades authority.
AuthorityLoader never recompiles authority.
AuthorityLoader never repairs authority.

AuthorityLoader only loads verified published authority.

Future checks such as schema compatibility, signature verification, compiler
compatibility, CRI-CORE compatibility, policy version compatibility, minimum
Guard version, and publication compatibility belong behind the
`AuthorityVerifier` boundary.

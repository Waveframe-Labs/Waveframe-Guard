# Authority Loading Boundary

Status: emerging architecture boundary.

Guard should ask for published authority by explicit authority reference:

```python
from waveframe_guard.authority import load_authority

authority = load_authority("finance-policy@1.2.0")
```

The public identifier is always `name@version`.

No paths, filenames, `latest`, or implicit resolution are accepted by the
public loader API.

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
- `BundleLoader` opens the published authority bundle and returns it unchanged.
- `AuthorityVerifier` owns all trust decisions.
- `LoadedAuthority` is the verified authority object Guard can consume.

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

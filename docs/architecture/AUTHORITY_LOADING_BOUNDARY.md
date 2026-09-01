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

The pipeline shape is fixed. Only the implementation behind
`AuthorityResolver` should vary.

Current resolver adapters:

- `LocalRegistryResolver`
- `MemoryAuthorityResolver`

Future resolver adapters may include Cloud or Enterprise sources, but they must
still return `RegistryEntry`. Resolvers must not return bundles, load bundle
payloads, verify bundle contents, alter lifecycle state, or select `latest`.

## Authority Cache

Authority caching is optional and must not change the public loading API.

The cache key is immutable identity:

```text
authority_ref + bundle_hash
```

The cache is never keyed by authority reference alone.

The resolver still runs before every cache lookup. Guard must obtain the current
registry entry, including the current lifecycle state and expected bundle hash,
before deciding whether a verified authority can be reused.

Cache hits may skip bundle loading and cryptographic re-verification, but they
must not skip lifecycle enforcement. For v2, Guard re-runs Ledger's public
bundle and receipt validators against the cached publication artifacts before
reuse. A cached authority is loadable only when the freshly resolved registry
entry still permits it and every publication identity still matches.

The initial cache adapter is `MemoryAuthorityCache`. It stores verified
`LoadedAuthority` objects only after successful verification and returns
defensive copies so caller mutation cannot alter cached authority contents.

## Guard SDK Normalization

`Guard.local(authority="name@x.y.z")` resolves and verifies the published
authority before constructing runtime boundaries. After that point, Guard uses
`LoadedAuthority.contract` as the compiled authority passed to the existing
enforcement pipeline.

The enforcement pipeline does not know whether the compiled authority came from
a published authority reference, an injected resolver, or a legacy compiled
contract input.

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

Guard retains the Ledger `authority_bundle.v1` compatibility path. A loadable v1 bundle must use
`schema_version: authority_bundle.v1` and expose the runtime contract at
`authority_contract`. Guard does not accept the former Guard-local
`published_authority_bundle.v1` / `contract` fixture shape at this boundary.

The native v2 path requires all of the following before use or caching:

- an `authority_bundle.v2` and matching `publication_receipt.v2`
- registry `receipt_path` and `receipt_hash` fields in addition to the existing
  bundle and contract bindings
- successful public Ledger `validate_authority_bundle` and
  `validate_publication_receipt` calls
- successful public Ledger runtime-fact compatibility validation
- exact authority, bundle, receipt, contract, domain-pack, fact-schema, and
  registry identity/hash agreement

Guard never extracts an embedded v2 contract first and validates it later. It
never downgrades v2 to v1, infers missing lineage, or copies Ledger's validator
logic. The initial trusted fact provider is keyed to the immutable
`repository-changes/1.0.0` pack and its exact published runtime schema.

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

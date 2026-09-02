# Waveframe Guard v0.16.1 Release Notes

## Cloud v2 Publication Resolver

Guard can now retrieve one atomic Ledger v2 publication from Cloud and verify
it before enforcing any action.

This patch releases the issue #22 / PR #23 client and protocol boundary. An
authenticated `Guard.cloud(...)` cold resolution requests:

```text
GET /v1/authorities/{authority_ref}/publication
```

The `cloud_authority_publication.v1` response binds the exact atomic authority
bundle, publication receipt, opaque logical bundle and receipt references,
registry entry and hash, requested authority, organization, and envelope hash.
Guard reuses the existing organization/API-key authentication. The additive
`runtime_credential=` argument is an alias for the existing Cloud API-key
credential; existing arguments and environment configuration remain valid.

Application code supplies no runtime facts, hashes, bundles, receipts, or
Ledger-validator calls. Guard preserves the published structures, verifies the
bundle and receipt through the existing public Ledger 0.7 boundary, derives
only trusted repository-change runtime facts, and caches the immutable verified
projection. Cold resolution performs one publication request. Warm evaluation
performs no additional request and no heavy Ledger validation.

## Fail-Closed and Compatibility Behavior

Fallback to the unchanged legacy v1 contract endpoint occurs only for the
narrow documented publication-not-found response. Contract-only v2 remains
fail-closed; it is never downgraded to v1. Authentication failures, conflicts,
rate limits, server errors, redirects, invalid or oversized bodies, partial
publications, and binding failures do not fall back.

Existing v1, finance, local resolver, and Guard 0.16 behavior remains
compatible. Resolver behavior, the HTTP protocol, schemas, canonical hashing,
runtime facts, authority verification, cache behavior, and public API shape are
unchanged from the merged issue #22 implementation.

The package retains the public dependency boundary:

```text
governance-ledger>=0.7.0,<0.8.0
```

Guard never depends on `governance-ledger[guard]`.

Primary installation:

```text
pip install waveframe-guard==0.16.1
```

## Availability and Limitations

Current released Cloud does not yet expose the publication endpoint. Cloud PR
#133 is the follow-on implementation. Waveframe Guard v0.16.1 provides the
client/protocol boundary; it does not claim hosted availability and does not
modify or deploy Cloud.

Native v2 runtime facts remain repository-change only. Other domains require a
separately trusted domain pack and deterministic fact provider. Guard does not
interpret policy prose. No AI, NLP model, heuristic policy interpretation, or
runtime inference is involved.

The authoritative compatibility matrix is in
[`docs/getting-started/README.md`](docs/getting-started/README.md#release-compatibility-matrix).

This is release preparation only. It does not merge, tag, create a GitHub
release, upload to PyPI, publish, deploy, modify Cloud or Ledger, or modify any
other repository.

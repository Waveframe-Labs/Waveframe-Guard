# Cloud Authority Publication Protocol

Status: public Guard client contract; Cloud implementation not yet shipped.

Guard resolves the complete published authority from Cloud and verifies it
before enforcing any action. Applications continue to call `Guard.cloud(...)`;
they do not download artifacts, calculate hashes, construct runtime facts, or
call Ledger validators.

## Request

```text
GET /v1/authorities/{authority_ref}/publication
```

`authority_ref` is the exact explicit `name@x.y.z` identity encoded as one
RFC 3986 path segment. For example,
`repository-authority@1.0.0` is requested as
`repository-authority%401.0.0`. Guard sends the same existing runtime headers:

```text
Accept: application/json
Accept-Encoding: gzip, identity
X-Organization-ID: <organization identity>
X-API-Key: <runtime credential>
```

Cloud must apply the same tenant and runtime-credential authorization used by
its existing authority and registry read routes. It must never return an
authority owned by another organization.

## Successful response

A `200 OK` response is one immutable snapshot with `Content-Type:
application/json`. Its top-level fields are exactly:

```json
{
  "schema_version": "cloud_authority_publication.v1",
  "organization_id": "example-organization",
  "authority_ref": "repository-authority@1.0.0",
  "registry_entry": {
    "authority_ref": "repository-authority@1.0.0",
    "contract_id": "repository-authority",
    "contract_version": "1.0.0",
    "contract_hash": "sha256:<64 lowercase hexadecimal characters>",
    "publication_id": "publication-1",
    "bundle_ref": "publications/repository-authority/1.0.0/authority-bundle.json",
    "bundle_hash": "sha256:<64 lowercase hexadecimal characters>",
    "receipt_ref": "publications/repository-authority/1.0.0/publication-receipt.json",
    "receipt_hash": "sha256:<64 lowercase hexadecimal characters>",
    "lifecycle_state": "active",
    "published_at": "2026-08-31T12:02:00Z",
    "published_by": "publisher@example.com"
  },
  "registry_entry_hash": "sha256:<canonical registry_entry hash>",
  "authority_bundle": {
    "schema_version": "authority_bundle.v2"
  },
  "publication_receipt": {
    "schema_version": "publication_receipt.v2"
  },
  "envelope_hash": "sha256:<canonical envelope hash>"
}
```

The abbreviated nested artifacts above show placement only. Cloud must return
the complete, unchanged Ledger `authority_bundle.v2` and matching
`publication_receipt.v2`. The checked-in
[`cloud_authority_publication.v1` golden fixture](../../tests/fixtures/cloud_authority_publication.v1.json)
is the complete reproducible example.

The `registry_entry` field set is also exact. Every hash uses the `sha256:`
prefix and 64 lowercase hexadecimal characters. `registry_entry_hash` is the
SHA-256 of compact, key-sorted UTF-8 JSON for the exact `registry_entry` object.
`envelope_hash` uses the same canonicalization for the complete top-level
object with only `envelope_hash` omitted. These two hashes bind the transport
snapshot; they are not provenance and never replace Ledger validation.

The Ledger bundle and receipt retain their own canonical hashes and immutable
bindings. Guard passes them unchanged to Ledger's public bundle, receipt,
runtime-schema, and compatibility validators. The compiled contract is trusted
only as part of the verified bundle. Cloud must not add a separate contract
copy.

## Logical references

`bundle_ref` and `receipt_ref` are opaque POSIX logical identifiers. They are
not URLs and Guard never requests them separately. They must be non-empty,
relative, already normalized strings. Guard rejects absolute paths, drive
paths, backslashes, NUL/control characters, empty segments, repeated
separators, `.` or `..` segments, leading/trailing whitespace, and ambiguous
normalization. Matching physical filenames cannot substitute for a different
logical reference.

The response must not contain physical filesystem paths, tenant storage paths,
credentials, arbitrary retrieval URLs, a separately trusted contract, or
unrelated Cloud records. Unknown, omitted, duplicated, or partially populated
envelope and registry fields fail closed.

## HTTP and fallback behavior

Guard uses its existing five-second authority timeout. Both the encoded body
and the decompressed body are limited to 8 MiB. Only identity and single-member
gzip encoding are accepted. JSON must be UTF-8, must contain one top-level
object, and must not contain duplicate keys. Guard rejects redirects rather
than forwarding credential-bearing requests to another origin.

Status handling is deterministic:

| Status | Guard behavior |
| --- | --- |
| `200` | Strictly parse, bind, validate through Ledger, cache the verified runtime projection, then enforce. |
| `401` | Authentication failure; fail closed without fallback. |
| `403` | Authorization failure; fail closed without fallback. |
| `404` with `not found`, `not_found`, `endpoint_not_found`, or `authority_publication_not_found` | Run the unchanged legacy `GET /v1/contracts/{contract_id}/{contract_version}` path. |
| Other `404` | Fail closed without fallback. |
| `409` | Publication conflict; fail closed. |
| `413` | Publication too large; fail closed. |
| `422` | Invalid publication; fail closed. |
| `429` | Rate limited; fail closed. |
| `5xx` | Cloud failure; fail closed. |

Malformed JSON, invalid content type or encoding, empty/truncated/oversized
bodies, timeouts, redirects, partial v2 data, and any identity or hash mismatch
never trigger legacy fallback. If fallback returns
`compiled_authority_contract.v2`, Guard retains the existing stable failure:
the contract requires a verified authority bundle and publication receipt.
Guard never downgrades v2, infers an artifact, or follows a server-supplied URL.

Exceptions expose stable status categories only. Credentials, response bodies,
policy bytes, bundles, and receipts are not placed in exception strings or
logs.

## Cloud implementation requirement

Current hosted Cloud and Waveframe-Cloud PR #133 do not implement this route.
Cloud support is unavailable until a Cloud release persists the exact Ledger
0.7 bundle and Ledger receipt together, constructs the public registry binding,
serves the tenant-scoped atomic response above, and reproduces the golden
fixture in its own protocol tests. Guard's client capability remains dormant
and uses the legacy v1 contract endpoint when the current Cloud route reports
that the publication endpoint is unavailable.

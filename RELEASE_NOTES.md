# Waveframe Guard v0.17.0 Release Notes

## Native Ledger v3 Authority Verification

Waveframe Guard v0.17.0 adds native verification of Ledger's additive
`authority_bundle.v3` and mandatory matching `publication_receipt.v3`.
Guard delegates normative reconstruction to Ledger's version-dispatched public
validators and requires provenance-complete results before using any runtime
projection.

The verified envelope binds the registry, authority, publication, manifest,
domain pack, runtime-fact schema, Constraint IR, compiled contract, bundle, and
receipt identities and hashes. Verification evidence identifies v3 artifacts
truthfully. Cache insertion, reuse, revalidation, drift detection, and
substitution rejection cover v3 without changing the existing v1/v2 paths.

Multi-control v3 authority can enforce every published control from one source
clause. Partial-coverage authority enforces only its published controls;
acknowledged residual meaning remains public provenance and never becomes
executable behavior. Guard evaluates the unchanged
`compiled_authority_contract.v2` only after the complete v3 bundle and receipt
pass validation.

## Compatibility

The public Ledger dependency remains:

```text
governance-ledger>=0.7.0,<0.9.0
```

- Ledger 0.7 supports existing v1 and v2 authority unchanged.
- Native v3 verification requires Ledger 0.8 or later.
- Supplying a v3 artifact with Ledger 0.7 fails closed with a clear Ledger 0.8
  requirement; Guard does not partially verify or downgrade the publication.
- Existing v1/v2 loading, caching, Cloud-envelope, runtime-fact, and
  enforcement behavior remains compatible.

Primary installation after publication:

```text
pip install waveframe-guard==0.17.0
```

## Evidence and Provider Boundaries

Runtime verification requires the published authority bundle and receipt. It
does not require a translation proposal or retained private provider evidence.
Private model details, prompts, requests, responses, retries, failures, token
usage, and explanations can remain absent without changing authority or Guard
verification.

Guard contains no AI or model-provider integration. It does not call a model,
interpret policy prose, or trust provider explanations. Ledger publishes the
normative authority; Guard verifies and deterministically enforces the compiled
runtime payload without a model.

## Availability

Guard 0.17.0 can parse and verify matching v2 and v3 publication envelopes.
Current released/hosted Cloud does not yet serve the complete atomic v2 or v3
publication path. Cloud PR #133 remains the pending v2 server implementation.
Hosted v3 serving requires an additional Cloud update. This release does not
modify or deploy Cloud.

The authoritative compatibility matrix is in
[`docs/getting-started/README.md`](docs/getting-started/README.md#release-compatibility-matrix).

This is release preparation only. It does not merge this release branch,
create a tag or GitHub release, upload to PyPI, publish, or deploy any service.

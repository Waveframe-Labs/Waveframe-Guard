# Waveframe Guard v0.16.0 Release Notes

## Verified Ledger Authority Enforcement

Guard verifies the exact Ledger-published authority, derives only
schema-approved runtime facts, and binds every decision to immutable evidence.

Waveframe Guard v0.16.0 adds native verification of Ledger
`authority_bundle.v2` and `publication_receipt.v2` publications. Guard delegates
bundle, receipt, and runtime-fact compatibility validation to Ledger's public
provenance validators, then retains a compact verified projection for warm
evaluation. Cold loads perform the complete validation chain; warm evaluations
do not invoke Ledger's full validators.

The first native v2 domain is `repository-changes/1.0.0`. Its deterministic,
typed runtime facts allow the exact path `README.md` and deny the
`deployment/` prefix. The allowed callback runs exactly once, while the blocked
callback never runs. Missing or mistyped facts, fact injection, overrides,
cross-version artifacts, and tampered publications fail closed.

Every v2 decision binds the authority, bundle, receipt, compiled contract,
domain pack, runtime fact schema, Constraint IR, and derived fact set. Unrelated
proposal metadata cannot affect evaluation or the fact-set hash. Execution
attestations distinguish callback invocation, completion, outcome, and mutation
state truthfully; when a callback raises, mutation state is reported as unknown.

## Compatibility

Existing v1 and finance behavior remains compatible. The package retains the
public dependency boundary:

```text
governance-ledger>=0.7.0,<0.8.0
```

Guard never depends on `governance-ledger[guard]`. The published
`governance-ledger[guard]==0.7.0` extra still represents Ledger's previously
released Guard 0.15 compatibility pairing. Users who need Guard 0.16 should
install it directly:

```text
pip install waveframe-guard==0.16.0
```

## Limitations

Guard does not interpret policy prose. Ledger and a trusted domain pack produce
authority; Guard verifies and enforces that authority. There is no AI, NLP
model, heuristic policy interpretation, or runtime inference in this path.

Only the repository-change fact provider is native in this release. Other
domains require separately trusted domain packs and deterministic fact
providers. Cloud integration for distribution and consumption of the complete
v2 workflow is follow-on work. This release does not claim that Cloud currently
distributes or consumes the full v2 chain.

The authoritative compatibility matrix is in
[`docs/getting-started/README.md`](docs/getting-started/README.md#release-compatibility-matrix).

This is release preparation only. It does not merge, tag, create a GitHub
release, upload to PyPI, deploy, modify Cloud or Ledger, or modify another
repository.

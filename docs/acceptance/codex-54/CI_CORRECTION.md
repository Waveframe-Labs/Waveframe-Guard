# PR #55 coordination correction

This corrects the Guard-owned acceptance harness following the
[review of adcac6a](https://github.com/Waveframe-Labs/Waveframe-Guard/pull/55#issuecomment-5691518092).
It does not change the SDK, package versions, published packages or Ledger's
packaged verifier. The native feasibility result and full-boundary no-go in
[RESULTS.md](RESULTS.md) are unchanged. The contained real-client experiment is
deferred until this correction is reviewed.

## Retained results

At `adcac6a26fe7b630d14bb7402e91d45b24cc623f`,
[Guard validation](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/35045309805)
passed all seven jobs. The previously pending
[extended matrix](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/35045309784)
**failed in all four cells** (Windows/Ubuntu, Python 3.10/3.14) at
`combined-provenance`. Pip selected public Compiler 0.5.0 with SHA-256
`1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44`
instead of the authenticated local candidate archive. The unchanged verifier
correctly rejected its origin. Those jobs did not reach mount equivalence;
the overly broad comparison was identified by source review.

The earlier failed [Guard run](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/35045067187)
and [action-policy run](https://github.com/Waveframe-Labs/Waveframe-Guard/actions/runs/35045067082)
remain available. Their captured-JSON allowlist and archival-source formatting
corrections are already in `adcac6a`.

No original capture is replaced or regenerated. All 118 entries in
[the native evidence index](evidence/SHA256SUMS.json) retain their original bytes.
The index itself retains SHA-256
`57e100b2ef93e8f15bd6a67635cccb1120894e3e103916a113f03c95d6d7a100`.

## Corrected selection and equivalence

Both combined installation and Guard-entry upgrade now supply the authenticated
Ledger, Guard and Compiler wheel paths as direct pip requirements. Combined
installation retains Ledger's `dev,guard` extras. The historical 0.8/0.18/0.4
upgrade starting environment remains unchanged. Archive authentication, clean
build provenance, pip reports, origin/hash verification, installed runtime/resource
verification, resolver rejection and every packaged suite remain required.
The packaged Ledger verifier is neither edited nor bypassed. This is a candidate
coordination gate, not a rerun or reinterpretation of the completed public release.

[The mount inventory](../../RELEASE_019_ACCEPTANCE.md) conservatively retains
all existing tests and fixtures, complete runtime and contract trees, dependency
metadata and root test/build/checkout configuration. Two named, newly added
standalone test modules are accounted for with identities and reasons. No shared
hook, existing test, unknown test addition or runtime change is exempted.
Git modes and object identities are compared; wheel runtime bytes are still
compared independently. Relevant differences invalidate reuse and require review
or an actual new mount run.

The retained proof remains the #51 Linux/Python 3.14 same-device bind-mount
execution at evidence commit `e6008345c9891ec6ffb5088f38177022e3cef4aa`, tested wheel
SHA-256 `2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e`.
**No new mount execution is claimed.** CI namespace skips remain skips.

The focused tests exercise real offline pip resolution with competing same-version
archives for both selection modes, plus inventory acceptance and invalidation for
changed/added/deleted/renamed inputs, file modes, shared hooks, configuration,
runtime, fixtures and attempted exemptions of existing tests. Final-head workflow
results and artifact links are recorded in the draft PR after both existing
workflows finish, without rewriting the historical results above.

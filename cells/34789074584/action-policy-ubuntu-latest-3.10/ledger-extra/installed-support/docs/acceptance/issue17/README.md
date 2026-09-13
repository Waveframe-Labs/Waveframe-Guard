# Issue #17 acceptance evidence

Local validation: Windows, Python **3.14.4**, exact candidate compiler installed as a
package, Ledger source and a separately installed Ledger wheel. This records local
evidence, not a compiler release, compatible Guard creation release, or Cloud activation.

| Check | Result |
| --- | --- |
| Focused action/translation/publication/domain/provenance suite | 324 passed, 2 optional Guard skips |
| Complete suite with explicit development opt-in | 629 passed, 3 optional Guard skips |
| Complete suite with default access | 585 passed, 47 skips (44 development cases + 3 optional Guard cases) |
| Real candidate fixture generation | Complete create-only, modify-only, mixed chains reproduced |
| Installed-wheel public API acceptance (`python -I`) | All three fixtures reproduced; public verification passes without compiler import |
| Wheel + sdist build; `twine check` | Passed; wheel built from sdist |
| `pip check` | Passed in candidate source, candidate wheel, and both published Guard environments |
| Historical comparison against published Ledger 0.8 | Catalog, pack, proposal, confirmation, approval, review, v2/v3 publication exactly equal |
| Guard 0.18 + published Ledger 0.7 | 24/24 native/downgraded/mixed/unknown envelope cases rejected |
| Guard 0.18 + published Ledger 0.8 | 24/24 native/downgraded/mixed/unknown envelope cases rejected |
| Published Ledger 0.8/Guard 0.18 historical operations | Matching modify callback executed; unlisted modify and create blocked |
| Existing publication workflow/package dependency changes | None |

The Guard environments use ordinary package resolution, compatible published Ledger
versions, and published compiler 0.4.0. They contain no candidate compiler or candidate
Ledger. Probe registry entries include matching logical bundle and receipt references;
downgrade rejection is not attributed to omitted registry references. Native v4 is
rejected by Guard's schema dispatch, v3 downgrades by unavailable catalog/support,
and v2/v1 downgrades by their historical envelope contracts. These are measured
rejections, not assumptions based only on new version strings.

* [Compiler provenance](compiler-provenance.json): exact repository commit, PEP 610
  record, candidate package build hash, and interpreter.
* [Historical hashes](historical-hash-comparison.json): full canonical artifact hashes
  for both environments and retained golden file SHA-256 values.
* [Guard/Ledger 0.7 results](guard018-ledger07.json) and
  [Guard/Ledger 0.8 results](guard018-ledger08.json): every case and rejection reason.
* [Historical operation check](legacy-operations.json): callback-only modify/create
  isolation; no filesystem operation implementation.
* [Installed-wheel acceptance](package-acceptance.json): isolated installed imports.

Reproduction commands are in [the development guide](../../ACTION_POLICY_DEVELOPMENT.md).
All checks use the exact retained fixtures under `tests/fixtures/action_policy_v4`.
Private model/provider evidence is absent from public fixtures. The historical
comparison helper uses test input factories with `python -I` in the published 0.8
environment and ordinary Python in the candidate source environment; compare the
two JSON outputs for exact equality.

The three optional Guard tests require the release-tested 0.17 package and are skipped
in the candidate environment, which intentionally has no Guard installed. Separate
published 0.18 checks provide the explicit old-runtime evidence above. The manually
invoked development CI matrix is supplied but was not run as part of this local
evidence. Minimum supported compiler interpreter, cross-platform CI, Guard creation
filesystem acceptance, dependency range coordination, and Cloud/customer activation
remain gates; see the development guide. Arbitrarily forged legacy envelopes are a
downstream hardening gate, beyond native/discriminator-downgrade rejection evidence.

# Native Cloud connected acceptance evidence

Installed SDK acceptance passed on Windows and Linux with Python 3.10 and 3.14.
Each of the four runs exercised 23 cases with actual Guard clients and automatic
preservation/runtime reports against unchanged Cloud source at
`547291b525e2f1d05d92ed65b6058c4ca91588a8`. Cloud used its own Python 3.14
environment and documented candidate dependencies. Linux used disposable tmpfs
workspaces in containers, preserving the existing filesystem allowlist. This does
not add mount-namespace coverage. Windows used the existing NTFS protections.

Both independent environments passed `pip check`. PEP 610 commit and requested
revision assertions passed for Compiler `3b91fcc03c804804b2ace7302f37340a787496d9`
and Ledger `54379d9c8044544fc1b8f32109bdfce35c1c6a05`. Source identity and clean
Cloud tracked files were verified before and after each run. No Cloud source is
published in this repository or in the SDK package.

## Package evidence

The tested wheel has 61 Python runtime files, all byte-for-byte equal
to the committed runtime sources. Only test harness, workflow and documentation
changes followed the runtime implementation. Fresh wheel/sdist content and
metadata inspection, Twine validation, and installed-wheel local creation passed.

| Artifact | SHA-256 |
| --- | --- |
| `waveframe_guard-0.18.0-py3-none-any.whl` | `a6146b5a695242f28406021bfadab8dbbf011744060779d6185e16a37fbe3d6c` |
| `waveframe_guard-0.18.0.tar.gz` | `de1bf45bb4d85f8aebee0feb2f0e86412af85b246c5a152e756f5029853492f0` |

## Sanitized HTTP outcomes

Every native decision below was automatically POSTed once to `/v1/preserve`.
Each successful preservation returned HTTP 201 and its authenticated package
GET returned HTTP 200 with evidence exactly equal to the immutable SDK submission.
All 20 terminal native reports returned HTTP 201 with `consistency_state=consistent`;
Activity matched the report, saved run and assigned runtime. The evaluation-only
case preserved its decision but submitted no runtime report. Runtime IDs differ
from actor IDs intentionally. No successful audit-event injection or manual report
construction occurs in the harness.

| Case | Authorization | Runtime status | Mutation | Callback count |
| --- | --- | --- | --- | --- |
| collision | ALLOWED | failed | false | 1 |
| create-only-no-modify | BLOCKED | blocked | false | 0 |
| created | ALLOWED | succeeded | true | 1 |
| default-deny | BLOCKED | blocked | false | 0 |
| denied-path | BLOCKED | blocked | false | 0 |
| denied-role | BLOCKED | blocked | false | 0 |
| empty | ALLOWED | succeeded | true | 1 |
| mixed-create-role | BLOCKED | blocked | false | 0 |
| mixed-created | ALLOWED | succeeded | true | 1 |
| mixed-modified | ALLOWED | succeeded | true | 1 |
| mixed-modify-role | BLOCKED | blocked | false | 0 |
| modified | ALLOWED | succeeded | true | 1 |
| modify-denied-path | BLOCKED | blocked | false | 0 |
| modify-denied-role | BLOCKED | blocked | false | 0 |
| modify-only-no-create | BLOCKED | blocked | false | 0 |
| no-report | ALLOWED | no report | unknown / absent | 0 |
| partial | ALLOWED | failed | true | 1 |
| post-validation | ALLOWED | failed | true | 1 |
| pre-callback | ALLOWED | not_executed | false | 0 |
| returned-summary | ALLOWED | failed | unknown / absent | 1 |
| unknown | ALLOWED | failed | unknown / absent | 1 |

Wrong-tenant package retrieval returned 403. With a credential assigned to a
different runtime, actual SDK automatic preservation and reporting both returned
403; exactly one local creation occurred and no preservation was claimed. The
released v2 authority rejected creation at runtime-fact validation with zero
callbacks, writes, saved authorization events or invented reports.

Collision preserved the competing file unchanged. Empty creation produced an
empty file. Known creation followed by failure remained failure with mutation.
Callback summaries claiming creation without using the capability did not report
success. Local historical proofs retained unknown overall mutation on collision,
partial failure and post-validation failure. All native saved decisions replayed
successfully; replay validates the logical decision, not final filesystem state.

## Reproduction artifacts

The [reproduction guide](NATIVE_CLOUD_DEVELOPMENT.md) produces `http.json`,
`summary.json`, independent local attestations, `cloud-source.json`, and both
`pip check` results. HTTP records omit authentication headers and are checked
against all disposable credential values before writing. Exact retained HTTP
file hashes for these four successful runs:

| SDK environment | HTTP SHA-256 |
| --- | --- |
| Windows, Python 3.14.4 | `80f53d6dde17c43af0b1756dc7588ed0378850ebef78dc7a44fe8c566876de01` |
| Windows, Python 3.10.21 | `be94a38c891d98e980cc9be4279d9bcbc11caa3423ba9af4ccdc7832bb5764dc` |
| Linux (tmpfs), Python 3.14.7 | `ad0a8b3773f5f811b94199d98dcccebe033bf44d86d79edc69cc6fd7704c1c9b` |
| Linux (tmpfs), Python 3.10.21 | `5f0f123a91d82a521d308259e67ee7af9e60243b393ce2e986155e4eb3a5df10` |

Unit transport faults additionally cover 403, 503, redirect rejection, ambiguous
timeout and raised client errors for returned and raised execution outcomes,
without a second mutation or false preservation claim. Native intake tests cover
gate-off, missing dependency APIs, mixed/downgraded/tampered publications, wrong
identities, context overrides, inactive lifecycle and warm cache substitution.

## Remaining integration

The public Guard CI runs Windows/Linux and Python 3.10/3.14 full default and
development suites plus package acceptance. Connected CI requires a read-only
`CLOUD_TEST_READ_TOKEN` secret for the private Cloud snapshot. Without that secret,
it records the connected step as unavailable; the four real-server results above
were obtained in authorized local environments. Native customer activation,
sandbox, and the complete customer browser workflow remain separate Cloud #143
work. Both Guard PRs remain draft.

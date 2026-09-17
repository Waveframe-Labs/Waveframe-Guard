# Contained Cloud revalidation (#59)

**The contained connection works against accepted Cloud #158.** The unchanged
writer refuses a mismatched runtime credential before activation. Genuine
created, modified and blocked runs remain readable, with their original separate
runtime reports, after supersession and revocation. A lost response reconciles to
one request and one mutation without replay. No functional SDK or Cloud change
was necessary.

## Exact inputs and changed scope

- Guard stack base: #58, `spike/57-contained-cloud`,
  `0d2376c971c1d9c8e7c15ee208bfeee1a6f8659e`.
- New branch: `spike/59-contained-cloud-revalidation`.
- Isolated, unchanged, read-only Cloud:
  `93bf80f30d170a6be32622a34dbbdf0d85b8ccc6`.
- Agent/model-proxy image:
  `sha256:2af4a2af92444e349c6755ddaf1d4e92fdbd53da8cc2fe51b6a71acbc83bcefb`.
- Writer image:
  `sha256:86bd888757923cdbc549887e6ec39559a93701bb6f53cc2641c62681bf1fb5fe`.
- Disposable Cloud wrapper image:
  `sha256:bc5f71b586ea19056a327fd4077b23ee28eb2af5d5fb42ffa2956f58bed3d9f6`.
- Real Linux Codex 0.154.0, configured model `gpt-6-astra`, Python 3.14.7,
  Docker Desktop Linux/WSL2. Client provenance is retained in
  [the capture](evidence/client/client-provenance.json).

| Published package | Version | Selected wheel SHA-256 |
| --- | --- | --- |
| waveframe-guard | 0.19.0 | `e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f` |
| governance-ledger | 0.9.0 | `6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4` |
| cricore-contract-compiler | 0.5.0 | `1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44` |

The Cloud pin, acceptance expectations, setup handoff, focused CI and evidence
checks changed in Guard only. A real setup defect was fixed: replacing a `0400`
writer secret now stops the old writer and exclusively recreates the file through
the operator's private volume. No writer/runtime/callback/package implementation
changed. The original three evidence manifests and their Git bytes are verified
in [prior-evidence.json](evidence/prior-evidence.json).

## Live results

[Verification](evidence/verification.json) checks the full captured sequence:
nine actual CLI phases, eight accepted phases and one retained failed setup phase;
seven saved runs; five callback invocations/five independently observed mutations;
two policy-blocked requests with zero callbacks/writes. The three required failed
startups have zero callbacks/protected writes. The additional failed version-2
attempt also had zero writes and never exposed a writer capability.

The fresh Console workflow confirmed all five controls and explicitly approved
version 1. Runtime identities remain `contained57-create` / `codex57-create` /
`repository-maintainer` and `contained57-modify` / `codex57-modify` /
`security-reviewer`. The model supplies no runtime, credential, role or authority.
Version 2 used a fresh translation, individual confirmations and approval through
the supported APIs before supersession. Publication IDs:

- Version 1: `cloud-translation-95cf059281d98e52688874f8eea2c4d2`.
- Version 2: `cloud-translation-7c81cf72f979250a935cb4378d3f6919`.

Both versions completed actual create, modify and doctest, then a policy denial.
The first useful turn took **44.87 seconds**, the second **59.54 seconds**;
the independent operator doctest also passed for each. Client setup took 6.5
seconds and the initial Console workflow 8.15 seconds. These are separate measured
operations, not an uninterrupted setup-to-edit time: image/browser installation,
login, approvals, negative tests, development corrections and operator pauses are
excluded. The final PowerShell wrapper encodes the corrected staged procedure; a
second fresh full wrapper run was not performed.

Wrong-runtime enrollment returned **403** before any registration state changed.
The unchanged writer raised `runtime connection rejected; writer not activated`
before MCP tool registration. Its request journal was absent and source snapshots
were equal. Codex's actual direct Python write failed with **EROFS / errno 30**.
The restored correct credential then completed the useful cycle. See
[refusal](evidence/client/wrong-runtime/refusal.json),
[real client events](evidence/client/wrong-runtime/events.jsonl), and
[private handoff verification](evidence/cloud/credential-handoff-check.json).

After supersession, all four version-1 packages/reports retrieved exactly. After
revoking the freshly approved version 2, all seven still retrieved exactly:

| Original run | Outcome | Package |
| --- | --- | --- |
| `guard_run_6804b090b203aebc77c02f45` | v1 create | `pkg_3619e08abf180ff0d407f3e3` |
| `guard_run_84e0ad0c8bf6a62fe479c737` | v1 modify | `pkg_c868d2e198b3cb672bdad8f3` |
| `guard_run_e96c3c8d30f89cd6b3655192` | v1 blocked | `pkg_df459b06d2d94a7505df7477` |
| `guard_run_b38b21e68045d1bb8474c57f` | v1 lost response, actual modify | `pkg_b6532625e0cf24fe288aab59` |
| `guard_run_c3507d0d5b98dcc3844a041d` | v2 create | `pkg_adec618854208de3d7144fa5` |
| `guard_run_2d0bd5a01b92a6575b844421` | v2 modify | `pkg_62e3b10394178ee06b09190a` |
| `guard_run_207a0ad0cbaf2773d602afd7` | v2 blocked | `pkg_831496e09ac4f588371d614c` |

Each stage retains the submitted SDK package, retrieved object, separate report,
audit event, exact response SHA-256, canonical package SHA-256 and independently
measured stored-object hashes. All original values compare exactly across stages.
Authorized operator and separately scoped runtime readers both succeed. Reader
credentials remain operator-only; writer scopes were not expanded. See
[post-supersession summary](evidence/cloud/after-supersession/summary.json) and
[post-revocation summary](evidence/cloud/after-revocation/summary.json).

Existing Activity and all original detail links still show the stored identity,
authority, policy decision and separate mutation status. Desktop captures and DOM
text are under the two historical stage directories; no UI changes were made.
The screenshots were visually inspected, including a retired blocked decision
showing “Blocked before execution” and “No mutation occurred.”

New actual writer sessions rejected inactive version 1 and version 2 with SDK
`CloudAuthorityFetchError` / HTTP 422. Both direct agent writes still failed.
Fourteen explicit late-admission API probes (eight after supersession, six after
revocation) returned 400 and left preservation/report storage hashes unchanged.
These negative upload probes invoke no repository callback. Historical reading
does not restore permission to execute.

The lost-response run has one CLI mutation call, one journal request, one completed
local SDK run, independently matching bytes at that phase, and one preserved
package/report. Its original package remains exact after both lifecycle changes.
The tool itself returned an error without a result. Later version-2 edits are
identified separately; the final file is not misrepresented as the lost-phase
snapshot. [Reconciliation](evidence/cloud/after-revocation/lost-reconciliation.json)
performs no callback, replay or rollback. Missing or contradictory evidence remains
unresolved and never authorizes an automatic retry.

## Explicit reuse and focused validation

[The input comparison](evidence/verification.json) verifies exact immutable image
IDs, every recorded `/opt` file hash, unchanged runtime/source blobs, container
launch arguments, environment values, mounts and OS controls. Cloud dependency
requirements did not change. The Cloud source mount remains read-only. Thus the
#56/#58 process-memory, read-only source, egress, connector/outage/redirect and
private transport evidence is reused, not claimed as freshly executed. The #58
public-wheel authentication and installed-member checks also apply to these same
unchanged read-only images. Hash maps and runtime source copies are retained again.

The changed credential handoff was exercised by wrong-to-correct restoration and
version selection. Its final private file is `0400` and matches operator-selected
version 2; the agent has no `/secrets`, `/cloud-transport` or `/opt/connected`.
The actual failed-connector direct-write checks are fresh boundary evidence.

All **47 focused local tests passed** in 9.03 seconds against the unchanged writer
image and installed public SDK. They cover the existing adapter/configuration/
evidence tests and new historical-evidence assertions. Negative tests reject a duplicated lost
request, a startup write, changed historical identity, failed upload and missing
local journal. The new CI workflow installs existing public wheels with
`--only-binary=:all:` and runs repository validation plus these checks; it does not
rebuild packages. Existing required workflow definitions are unchanged. Their
accepted #58 green runs remain the baseline; the broader release/dependency
matrices and Cloud filesystem/PostgreSQL integrity suites were not repeated.

## Retained attempts and limits

[ATTEMPTS.md](ATTEMPTS.md) identifies development failures and the evidence used
to reconcile them. No failed model phase was erased. The superseded-session
failure had no pre-start registration hash captured before a harness assertion;
its proof is the actual constructor 422, absent mutation tool capability,
unchanged source and original journal. The wrong-runtime and revoked-session
checks include direct before/after registration measurements.

Already-loaded authority remains session-cached; immediate remote revocation is
not claimed. Generic SDK callers can ignore a failed connection, but this writer
does not. Enrollment success still does not guarantee later upload success.
Those unchanged behaviors remain explicit #58 evidence, not newly solved problems.

No connection blocker remains for this fixture. Broader repository/build usability
is next, followed by Cloud #122 guided setup. Cloud #141/#121 remain rollout
blockers. Deletion, rename, macOS, native Windows writer protection, desktop app
and remote TLS remain outside scope. Disposable resources and credential handoffs
are removed after retention. No merge, tag, package rebuild/publication, image
push, deployment or customer activation occurred.

Reproduction: [PowerShell handoff](../../../examples/codex_contained/CLOUD-REVALIDATION.md).
Durable bytes: [SHA256SUMS.json](evidence/SHA256SUMS.json).

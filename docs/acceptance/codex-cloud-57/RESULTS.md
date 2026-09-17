# Contained Codex / fresh Cloud acceptance (#57)

Bounded technical and fixture-usability acceptance passed, with the released
SDK/Cloud limitations below. Keep the PR draft. No SDK behavior, package version,
sibling source, production deployment or customer activation changed.

## Inputs and identities

- Stack base: Guard #56, `spike/54-contained-codex`,
  `f5dba74c724d7cf50c9223ae192e3e5b5ee53ba9`. Original #55 and #56 evidence is
  unchanged: 118 and 253 indexed files, respectively; see
  [recomputed original manifest identities](evidence/prior-evidence-preserved.json).
- Isolated Cloud: `dd4d483fcec7c4f5d62312b3e802370d9ba7f264`, mounted read-only.
  Tracked source remained unchanged before and after execution. All new code is
  under Guard's `examples/codex_contained/`; Cloud runs its existing application,
  catalog-3 ExampleProvider and Console. No approvals, events or runtime reports
  were injected into storage.
- Real Linux Codex CLI **0.154.0**, model **gpt-6-astra**. Exact npm archive,
  integrity and executable hashes: [client provenance](evidence/client/client-provenance.json).
- Agent/model-proxy image: `sha256:2af4a2af92444e349c6755ddaf1d4e92fdbd53da8cc2fe51b6a71acbc83bcefb`.
- Connected writer image: `sha256:86bd888757923cdbc549887e6ec39559a93701bb6f53cc2641c62681bf1fb5fe`.
- Disposable Cloud image: `sha256:bc5f71b586ea19056a327fd4077b23ee28eb2af5d5fb42ffa2956f58bed3d9f6`.
  These are measured local image identities, not inferred from the old proof.

Selected public wheels, installed with ordinary dependency resolution:

| Package | Version | SHA-256 |
| --- | --- | --- |
| waveframe-guard | 0.19.0 | `e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f` |
| governance-ledger | 0.9.0 | `6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4` |
| cricore-contract-compiler | 0.5.0 | `1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44` |

Actual pip origins, public-PyPI metadata/archive comparisons, and installed-file
hashes are retained for [writer](evidence/client/writer-installed-bytes.json),
[agent](evidence/client/installed-bytes.json), and
[Cloud](evidence/cloud/cloud-installed-bytes.json). SDK images contain 278 checked
files across the three packages plus MCP 2.2.0; Cloud contains 78 checked
Ledger/Compiler files. API dependencies are isolated from Guard/CRI.

The [runtime map](evidence/cloud/runtime-file-hashes.json) measures all `/opt`
files. Exact executable Python bytes are archived under
`evidence/cloud/runtime-source/`, including `/opt/proof/original_writer.py`.
That file's image/archive SHA-256 is
`9f9b3c28e2940188768deab0b23e960f85eb09fadb5eccd4958694427ce1cd6c`;
it contains Windows checkout CRLF. Its LF source SHA-256,
`fde0321b8baa55878ed7e072e44f23e7ca6c352fd3643f15c46fa4b00b17115f`,
matches the unchanged submitted Git blob. Verification checks exact image/archive
bytes and permits only CRLF-to-LF for comparison with repository text. This closes
the original-writer measurement omission without claiming byte-identical line endings.

## Fresh approval and successful PowerShell reproduction

The final [copyable PowerShell setup](../../../examples/codex_contained/CLOUD.md)
was executed from `C:\GitHub\Waveframe-Guard-57` with `-NoBuild`, using the measured
cached images and the pinned isolated Cloud checkout. It created another fresh
organization and completed all Console confirmations, approval and publication.
The deterministic provider accepts only the documented five-clause policy.

- Approval: `publication-approval-v4-cfda2c8cf121ffb9101953d456541208373bf72d11fc08bf699e8195eeee83e7`.
- Publication: `cloud-translation-da5e3230aef4aa32b0f5dc92f15438ac`.
- Authority: `contained-codex-57@1.0.0`; actual hashes, organization and enrollment
  identities: [fresh publication](evidence/powershell/cloud/fresh-publication.json).
- Separate bindings: `contained57-create` / `codex57-create` /
  `repository-maintainer`, and `contained57-modify` / `codex57-modify` /
  `security-reviewer`. Two runtime credentials use the existing Console API's
  three scopes. The model submits only action, relative path and content.
- First coding turn: allowed create `generated/new.md`, allowed modify
  `README.md`, **one doctest passed**. Both tool results report executed mutation,
  successful decision preservation and a separate successful terminal report.
  Both packages were [retrieved and compared exactly](evidence/powershell/cloud/reconciliation.json).
- **51.53 seconds** from client setup to completed useful turn, after Docker's
  Linux engine, supported login cache, images, browser, fresh approval and runtime
  credentials were ready. The coding turn itself took 47.18 seconds. Image/browser
  downloads, initial Docker installation and authentication are excluded.
  [Timing](evidence/powershell/useful-timing.json),
  [actual PowerShell output](evidence/powershell-reproduction-2.log.txt),
  [commands, exit status and independent bytes](evidence/powershell/client/allowed/inspection.json).

This was PowerShell-launched real `codex exec`, not a new TUI/desktop-app usability
claim. The first rehearsal's absolute-path error and test-order mistake remain
visible; they were not counted as a successful create/collision sequence.

## Full live boundary and connected acceptance

The initial full fault cohort used its own fresh publication
`cloud-translation-a780e2d32e3b814c9e5e5b1262044d93`, approval
`publication-approval-v4-96917f516e2079082b091570d1f548df1913daa3d0153cd40654ab71342fce3f`.
Its [native HTTP](evidence/cloud/cloud-http.jsonl) records the existing review,
confirmation, approval, publication and runtime enrollment contracts.

Twelve real-client phases were executed and independently verified:

| Phase | Observed protected changes / result |
| --- | --- |
| Initial allowed attempt | README changed; absolute create path rejected, no create run ID. Doctest passed. |
| Initial negative attempt | Denials held; absent collision target was created. Explicit failed test-order attempt. |
| Useful correction | New `generated/addition.md`, README link, passing doctest; both Cloud uploads succeeded. |
| Corrected denial/collision | Zero protected writes; private-path and modify denials, exclusive-create collision, role injection rejected. |
| Bypass | Native patch, shell, Python, child and live interactive writes denied. |
| Missing / disabled / live stop | Zero protected writes without a working connector. |
| Malformed / timeout | Zero protected writes; raw malformed frame and measured timeout corroborated. |
| Lost response | Exactly one successful README mutation, then transport closed; no replay. |
| Cloud unavailable at load | Connector failed; native/interactive write boundary still held, zero protected writes. |

Every phase retains native CLI events, original rollouts, prompt/argv, exit code,
timings, independent before/after byte hashes and Docker controls. The agent
retained network none, read-only source, private PID namespace, no capabilities,
no-new-privileges and scratch-only test writes. Model egress stayed separate.
The [live memory/credential probe](evidence/client/live-separation.json) found
neither the writer's real Cloud configuration nor its memory/environment accessible
from the agent. [Transport probes](evidence/client/cloud-transport-probe.log.txt)
show the Cloud socket, code/config and credentials absent, no Cloud/direct external
TCP route, and proxy 403s for private/alternate endpoints and unintended ports.
This is local socket/loopback transport; remote TLS is outside the claim.

The SDK itself submitted `/v1/preserve` and `/v1/runtime/attestations`. Eleven
initial-cohort decision packages were retrieved exactly before lifecycle
invalidation; organization/runtime/actor/authority/publication/run identities and
separate reports were compared in [reconciliation](evidence/cloud/main-reconciliation.json)
and the full `retrieval/` records. No successful event/report was hand-posted by
the acceptance code. [Activity at 390px](evidence/cloud/activity-main-390.png),
[fresh reproduction at desktop](evidence/powershell/cloud/activity-1440.png),
and the `useful-*-detail-*` / `denied-collision-*-detail-*` screenshots show actual
runs in the unchanged Console. Screenshots supplement the upload/retrieval proof.

Lost response: request `codex57-` identity is retained with successful run
`guard_run_7de78735e36316d1f609b4b6` in the reconciliation record. Exactly one
mutation tool call appears in the rollout. Independently observed README bytes,
local terminal attestation, exact retrieved decision and separate Cloud report
agree. Reconciliation performed reads only; no rollback or exactly-once guarantee.

## Deterministic SDK faults and actual limits

[Nineteen recorded outcomes](evidence/cloud/sdk-fault-results.json) use real
published SDKs inside the separate writer, with fresh scratch repositories and
operator-controlled server faults. They are supplements, not model conversations.

- Cloud unavailable or redirected before load, and invalid credentials: load fails.
- **Wrong-runtime credential:** runtime registration succeeds, but a subsequent
  real mutation's preservation and report both fail. Registration/heartbeat
  success is not verification of the credential's runtime binding. Operator
  enrollment mapping is required; the adapter does not claim stronger preflight.
- Empty creation succeeds with zero bytes; collision retains competitor bytes;
  partial failure retains created bytes; unknown callback failure remains unknown;
  evaluate-only produces no terminal report. Local attestations and Cloud operation
  reports can express different knowledge; neither is relabeled to hide that.
- Preservation failure: the SDK can still mutate locally. Report-only failure and
  outage induced **after real mutation** preserve the earlier decision but leave
  terminal reporting unconfirmed. No automatic write retry follows.
- An already loaded authority remains usable during outage, supersession and
  revocation; subsequent preservation/reporting fails. Fresh sessions reject the
  superseded/revoked authority. Publication 2.0.0 was created through the same
  public review/confirmation/approval/publication workflow, then revoked through
  the existing lifecycle API. No storage edits or fallback authority were used.
- **Post-invalidation retrieval blocker:** a previously retrievable package returns
  HTTP 400 `invalid_preservation_package`, detail
  `native published authority unavailable: authority lifecycle invalidated: superseded`.
  [Exact response](evidence/cloud/post-invalidation-retrieval.json). The initial
  eleven successful exact retrievals remain archived. Supplementary packages
  were not all retrieved before this invalidation; they have retained native
  submissions/responses and local records, not an invented retrieval pass.

There is no per-write Cloud revalidation or immediate revocation guarantee. A
status call observes the writer and loaded cached publication, not current server
availability; last successful preservation is explicitly scoped to that session.

## Verification, evidence and remaining scope

- **41 focused tests passed** against installed public packages, including 15 new
  adapter checks; original #55/#56 evidence checks remain green.
- **24** initial-cohort saved SDK runs reload and logically replay on temporary
  copies; no repository callback is replayed. Independent control/byte checks pass
  all twelve phases. See [verifier output](evidence/verify-cloud-final.log.txt).
- Runtime source measurements cover the new code and inherited original writer.
  The selected installed wheels were checked in each separate process image.
- Original failed attempts and test assumptions are listed in
  [ATTEMPTS.md](ATTEMPTS.md); native logs/captures remain in the checksum index.
- [Durable checksum manifest](evidence/SHA256SUMS.json) covers the evidence bytes.
  Private login/runtime handoff files and raw credential-bearing storage are
  deliberately excluded. Required exact-head CI is reported on the draft PR;
  local retained evidence is not a claim that CI ran.
- All disposable containers, volumes and networks, including the failed initial
  setup, were removed. Operator credential handoff files were deleted after the
  credential scan; original Codex login remains untouched. See
  [cleanup record](evidence/resource-cleanup.json). Local images remain cached.

Broader repositories/builds, native Windows writer enforcement, desktop-app UX,
remote TLS, deletion/rename/macOS/other clients and customer activation remain
unproven. Cloud #141/#121 remain separate rollout blockers. Cloud #122 handoff
fields and operator reconciliation instructions are in
[CLOUD.md](../../../examples/codex_contained/CLOUD.md). No new SDK release, image
push, merge, tag, deployment or production publication is part of this proof.

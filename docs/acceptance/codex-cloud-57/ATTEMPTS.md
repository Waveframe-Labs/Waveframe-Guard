# Retained failures and corrections

This list is reconstructed from the session's command/tool records. Linked native
logs and phase captures are original bytes. It is not a synthetic command transcript.
All commands ran from `C:\GitHub\Waveframe-Guard-57` unless stated otherwise.

1. Initial `docker info` prerequisite probe failed because Docker Desktop was
   stopped. Started the existing Docker Desktop installation; no installation or
   login cost is included in edit timing.
2. `run_cloud.py cloud --name wf54-57-live ...` used an internal Docker network.
   Docker returned an empty published-port list; launcher raised `IndexError`.
   The replacement uses a separate normal Cloud bridge with a host-loopback
   Console binding. Writer/agent remain network none. Failed disposable resources
   are distinct from the successful `wf54-57-proof` resources.
3. Browser plugin discovery returned no available browser. After its documented
   discovery check, standalone disposable Playwright was used. No user profile
   or existing browser session was read.
4. First Console workflow completed publication, then the harness used an
   incorrect `auth['organization']` response field. Correct field is
   `auth['identity']['organization_id']`. Its review/publication screenshots and
   stderr remain in `evidence/cloud/failed-console-1/`.
5. Second workflow completed publication, then a raw `@` authority path received
   404. Corrected to the SDK/Console contract's percent-encoded path. Its screenshots
   and stderr remain in `evidence/cloud/failed-console-2/`. Neither prior publication
   was relabeled as the successful third workflow; all are present in native HTTP.
6. Initial client setup rejected the already-existing Cloud resource's shared
   label before starting client containers. Narrowed collision checks to the
   actual client/writer/proxy names; Cloud is intentionally already running.
7. An allowed-phase invocation referenced `prompts/cloud-allowed.txt` before that
   file existed. It failed before launching Codex; no mutation occurred.
8. The first real client's create used `/source/generated/new.md`. Guard rejected
   the noncanonical absolute path with no run ID. Modify and doctest succeeded.
   The full `client/allowed/` phase is retained. A read-only evaluation and a
   deliberately no-write callback diagnostic established that the relative path
   was admissible; their outputs and local SDK run remain retained.
9. The first negative phase expected collision at that still-absent file; its
   create therefore succeeded. Retained `client/denied/` truthfully records the
   change. After operator reconciliation, a distinct useful create and the
   corrected zero-write denial/collision phase passed. Nothing was automatically
   retried after a lost response.
10. A transport-probe invocation was mistakenly launched on host Python and failed
    connecting to the agent-only loopback proxy. It did not inspect credentials or
    alter protected files. The script now rejects execution outside `/source` and
    `/scratch`; the actual agent execution and results are retained separately.
11. The first focused-test command named a nonexistent
    `examples/codex_connection/test_writer.py`. Pytest rejected collection; the
    corrected `tests/test_codex_connection.py` invocation passed 41 tests.
12. The first SDK fault driver tried `docker cp` into a read-only container root
    and failed before tests. Corrected by operator stdin copying the fixed test
    script into existing writable `/tmp`; no privileges or mounts were broadened.
13. The next SDK fault driver incorrectly expected wrong-runtime credentials to
    fail registration. The released SDK/Cloud actually accepted registration.
    Its partial results/stderr remain in `cloud/failed-sdk-2/`. The corrected
    assertion measures the subsequent real mutation and rejected uploads; the
    limitation is explicit in RESULTS.md.
14. Reconciliation after supersession/revocation returned HTTP 400. This is retained
    as an existing Cloud contract blocker, not patched or bypassed. Earlier exact
    retrieval records remain unchanged.
15. A follow-up screenshot pass tried to select older main runs from Activity's
    recent rows after the SDK fault cases displaced them. It timed out. Corrected
    to existing `/console-v2/executions/<run_id>` deep links; desktop and 390px
    actual main-run details were captured. The original Activity text and 390px
    screenshot remain under `console-activity-initial.json` / `activity-main-390.png`.
    One local image-inspection command also used a nonexistent screenshot basename;
    inspecting the actual listed filename succeeded.
16. First complete PowerShell setup attempt treated pip stderr notices as
    terminating PowerShell errors. It stopped during operator dependencies, before
    Cloud setup. `powershell-reproduction.log.txt` retains it. `Invoke-Checked` now
   checks the native exit code; the fresh `wf54-57-repro2` run completed in full.
17. Staged repository-integrity validation correctly rejected the new evidence
    JSON files until their exact paths were added to its existing fixed inventory.
    No broad directory/schema exception was added. Native `.log` bytes are retained
    under `.log.txt`, honoring the repository's forbidden-file policy. The original
    failed integrity output is retained; the corrected staged check passed.

Early read-only exploratory commands also used Windows-incompatible glob syntax
or nonexistent guessed filenames. They did not start acceptance or change source.
Final source/file discovery used `rg --files` and explicit paths. No skipped or
failed attempt above is included in a pass count.

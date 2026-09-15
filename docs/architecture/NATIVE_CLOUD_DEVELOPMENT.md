# Native Cloud SDK development connection

Issue #46 connects the existing `Guard.cloud()` API to the complete native
Cloud publication. This requires explicit development opt-in in the SDK process:
`WAVEFRAME_GUARD_ACTION_POLICY_DEV=1` and `WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1`.
Install the candidate Guard wheel with `.github/requirements/action-policy-development.txt`.
Released dependency metadata and package version 0.18.0 remain unchanged.

The server is the unchanged Cloud commit
`547291b525e2f1d05d92ed65b6058c4ca91588a8`. Its separate process requires
`WAVEFRAME_CLOUD_ACTION_POLICY_DEV=1` and `WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1`.
Guard never changes those flags. Compiler commit
`3b91fcc03c804804b2ace7302f37340a787496d9` and Ledger commit
`54379d9c8044544fc1b8f32109bdfce35c1c6a05` are required development dependencies;
their version labels alone do not identify these APIs.

## Public API

Publish the immutable Ledger create-only fixture through authenticated
`POST /v1/authorities`. Configure the Cloud URL, organization, and assigned
runtime credential in the environment. The runtime credential needs
`authorities:read`, `continuity:write` (registration and heartbeat), and
`audit:write` (preservation and separate reporting). An operator uses
`authorities:write` for publication and `replay:read` / `audit:read` for retrieval.
The protected repository root and its `generated` directory must already exist.

```python
from pathlib import Path
from waveframe_guard import Guard

guard = Guard.cloud(
    authority="repository-create-only@2.0.0",
    repository_root=Path("workspace").resolve(),
    workspace=".guard-local",
    runtime_id="assigned-runtime",
    actor_identity={"id": "developer-agent", "type": "agent",
                    "role": "repository-maintainer"},
)
try:
    @guard.repository_tool(action="create", target="path", return_result=True)
    def create_file(path, content):
        return path.create_bytes(content)

    result = create_file("generated/new.md", b"Created through Guard.\n")
    print(result["cloud_preservation"])
    print(result["cloud_runtime_attestation"])
finally:
    guard.close()
```

`WAVEFRAME_CLOUD_URL`, `WAVEFRAME_CLOUD_ORGANIZATION_ID`, and
`WAVEFRAME_CLOUD_API_KEY` supply the connection settings; explicit `cloud_url`,
`cloud_organization_id`, and `runtime_credential` arguments are also supported.
The resolved runtime may differ from the actor. Guard binds runtime and
organization to the execution context before evaluation and hashing. Conflicting
configuration or per-call context is rejected. Other supplied context is retained.
Customers do not construct preservation JSON or orchestrate report uploads.

## Evidence and failures

The atomic `cloud_authority_publication.v1` envelope retains the v4 bundle and
v4 receipt. Intake validates the tenant, requested authority, exact envelope and
registry hashes, logical references, lifecycle, and full Ledger provenance.
The original v3 contract and publication remain native through saving and replay.
Gate-off, old APIs, or malformed native evidence fail closed without legacy fallback.
The historical released publication/fallback contract remains available.

Guard sends the original `guard_cloud_preservation_package.v1` to `/v1/preserve`.
After the mediated attempt, a separate report names the same saved run, runtime,
authority, contract, and recorded authorization at `/v1/runtime/attestations`.
Creation reports derive from the validated operation facts and state combinations:

| Observation | Execution | Mutation |
| --- | --- | --- |
| Completed creation, including zero bytes | succeeded | true |
| Policy denial, no callback | blocked | false |
| Exclusive-create collision | failed | false |
| Failure after known creation | failed | true |
| Failure with mutation unconfirmed | failed | omitted |
| Confirmed refusal before callback, saved allowed decision | not_executed | false |
| Evaluation only, no terminal attempt | no report | absent |

A callback summary, its return value, byte count alone, or subsequent filesystem
existence cannot establish creation success. Post-validation failure remains
failure even after mutation. Retained local attestations keep their historical
state, including unknown overall mutation on collision and partial failure; the
separate Cloud report uses their additional validated operation observations.

Preservation and report failures appear on returned results and on
`exception.evaluation` when execution raises. They do not change authorization,
repeat mutation, or trigger an automatic upload retry. An ambiguous preservation
timeout has `ok=false, ambiguous=true`: Cloud may already have committed the
package. Never rerun the mutation to retry reporting. Successful preservation
metadata added locally after submission is not part of the original submitted
package. Compare `GET /v1/package/{package_id}` with that immutable submission.
Cloud consistency verifies evidence relationships, not the final filesystem.

## Reproduction and acceptance

From this Guard branch, use a fresh Python 3.10 or 3.14 environment on Windows
NTFS or Linux with the existing openat2 support:

```text
python -m pip install -e ".[test]" -r .github/requirements/action-policy-development.txt
python -m pip check
python -m pytest -q
# Set both SDK development flags in the invoking environment, then:
python -m pytest -q
python tools/acceptance/action_policy_package.py --output acceptance-output/package
python tools/acceptance/native_cloud_package.py --wheel acceptance-output/package/waveframe_guard-0.18.0-py3-none-any.whl --output acceptance-output/connected
```

The last command fetches the exact Cloud commit into a disposable directory,
checks its source is unchanged before and after acceptance, installs Cloud's
documented candidate requirements in an independent environment, and launches
its unchanged `create_app` on loopback with filesystem storage. Generated
disposable credentials are passed only in the child-process environment.
An independent environment installs the Guard wheel and exact candidates.
The client runs outside the checkout, checks installed paths and PEP 610
provenance, and uses real `Guard.cloud()` / `repository_tool()` calls.
`--cloud-source` can reuse an unchanged disposable snapshot at that exact SHA;
`--server-python` can reuse its isolated candidate environment.
When the SDK interpreter is Python 3.10, pass
`--server-base-python <path-to-python-3.14>` to create Cloud's independent
environment with its supported interpreter. The pinned Cloud source uses syntax
unavailable on 3.10; SDK 3.10 acceptance does not require Cloud itself to run on 3.10.

`summary.json`, `http.json`, independent local attestations, both `pip check`
results, and `cloud-source.json` retain sanitized evidence. The HTTP recorder
observes actual SDK requests without replacing successful preservation or report
calls. Each case checks exact submission/retrieval equality, local replay/evidence,
same-run reports and Activity projections. Fault stubs supplement this real-server
acceptance with rejection, redirect and ambiguous-timeout cases.

The development workflow runs default and opted-in full suites and fresh wheel/sdist
on Windows/Linux × Python 3.10/3.14. Its connected installed-wheel step requires
the read-only `CLOUD_TEST_READ_TOKEN` repository secret because Cloud is private
and Guard is public. Without it, CI records that connected acceptance is unavailable;
run the same harness locally with authorized access. Never upload private Cloud
source to public artifacts or substitute a broad personal token. Only sanitized
SDK evidence is retained. Cloud checkout credentials are not persisted.
The existing released validation workflow remains unchanged. The existing Linux
mount-namespace test is skipped when the runner lacks that capability; this work
does not claim new mount-namespace coverage.

Native customer activation, sandbox implementation and the complete customer
browser workflow remain subsequent Cloud #143 integration work. Ledger's approved
development wording and catalog identities are unchanged. Keep this PR and #45 draft.

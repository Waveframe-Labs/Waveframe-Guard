Issue #36 adds local development support for one new regular file beneath an
existing parent in a configured workspace, on the established Windows NTFS and
Linux openat2 boundaries. Both `WAVEFRAME_GUARD_ACTION_POLICY_DEV=1` and
`WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1` must be set by the invoking process.
Guard never changes Ledger's environment. Hosted activation is unavailable.

Install the isolated candidates from
`.github/requirements/action-policy-development.txt`. Compiler commit
`3b91fcc03c804804b2ace7302f37340a787496d9` and Ledger commit
`54379d9c8044544fc1b8f32109bdfce35c1c6a05` still report distribution versions
0.4.0 and 0.8.0. Their installed PEP 610 `direct_url.json` commit identities are
required for acceptance. Published packages with those version labels do not
provide this path. Public runtime dependency metadata is unchanged.

The native `authority_bundle.v4` / `publication_receipt.v4` pair must pass
Ledger's public validators and Guard's registry, identity, hash, lifecycle,
pack and fact-provider checks. The original enriched
`compiled_authority_contract.v3` remains intact through evaluation and replay.
Each selected action has its own scalar `required_role`, `allow`, and `deny`;
missing action or matching allow denies, and matching deny wins. A role grants
no path permission. Historical contracts cannot authorize creation.

For a Guard instance loaded through a verified registry and configured with
`repository_root`, the public creation call is:

```python
@guard.repository_tool(action="create", target="path", return_result=True)
def create_file(path, content):
    return path.create_bytes(content)

result = create_file("generated/new.md", b"Created through Guard.\n")
```

`generated` must already exist. The capability expires when the callback exits
and can create only once. It cannot call `write_bytes` to modify a file. A modify
capability cannot call `create_bytes`. Direct boundary integrations pass
`operation="create"` to `execute_repository`; its default operation is modify,
and any request action mismatch is rejected. The complete command-line example
is `examples/sdk/repository_creation_development.py`.

Evaluation and denials never create a file. After authorization, Guard holds and
revalidates the parent, compares it with the evaluated parent identity, and
uses `CREATE_NEW` on Windows or parent-relative `openat2` with `O_CREAT|O_EXCL`
on Linux. No overwrite or automatic directory creation is available. Existing
alias, case, reparse, symlink, mount, root replacement and hard-link protections
remain in force. The trusted callback must use the supplied capability.
Independent writers and malicious in-process tampering are outside this SDK's
trusted in-process threat model; this is not a filesystem sandbox or transaction.

The authorization outcome, runtime reporting, and final local execution proof
remain distinct. Creation adds `guard_execution_attestation.v3` with a bounded
`guard_repository_operation.v1` report. The report binds the operation and
relative target to the original request and workspace provenance, and records
whether exclusive creation occurred, bytes successfully written by the adapter,
operation status, and a fixed error code. It contains no file content or content
hash. Existing modify attestations remain v2.

A collision keeps `decision="admissible"`, records execution failure and
`created=false`, with `error="exclusive_create_collision"`. A failure after
three bytes were written records `created=true`, `bytes_written=3`, and
`status="failed"`. The callback failure's overall mutation state stays
`unknown`; the operation report provides the observed creation/write facts.
The new file can remain empty or partially written. Guard performs no rollback
and makes no durability or transactionality guarantee.

Attestation readers enforce consistency even when a caller recomputes the proof
hash. Operation success requires successful outer execution and observed creation;
a collision cannot claim creation or writes. Terminal failures require a matching
fixed failure code. Incomplete execution may retain a pre-operation snapshot or an
invoked attempt with unknown final mutation; zero-byte creation remains valid.

Local replay revalidates the retained publication with Ledger and rederives
runtime facts. It checks only the recorded logical decision; it does not
recreate filesystem state or refresh the historical registry lifecycle.

Acceptance uses the unchanged three Ledger fixture chains with source SHA and
byte digests. Run the default suite, then the full suite with both gates set.
`tools/acceptance/action_policy_package.py --output <directory>` builds fresh
wheel and sdist artifacts, checks contents/metadata, installs into a clean
environment, verifies PEP 610 provenance and `pip check`, and performs real
creation, collision, saved evidence loading and logical replay outside the
checkout. CI runs default and opt-in suites and this installed-wheel acceptance
on Windows/Linux with Python 3.10 and 3.14.

Deletion, rename, macOS, merge, tagging, publication and Cloud activation remain
outside this development PR. Final published dependency compatibility and
coordinated customer workflow acceptance remain release gates in Cloud #143.

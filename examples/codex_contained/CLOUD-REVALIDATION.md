# Focused contained Cloud revalidation (#59)

Guard stack base: `0d2376c971c1d9c8e7c15ee208bfeee1a6f8659e`, branch
`spike/57-contained-cloud`. Cloud is a read-only checkout at
`93bf80f30d170a6be32622a34dbbdf0d85b8ccc6`. The writer, MCP runtime, fixed
callbacks and published Guard 0.19.0 / Ledger 0.9.0 / Compiler 0.5.0 are unchanged.

Prerequisites: Git, Python, the running Docker Desktop Linux/WSL2 engine, the
accepted #58 local images, and supported Codex login at
`$env:USERPROFILE/.codex/auth.json`. The script checks all three exact image IDs.
The images were not pushed. A machine without those cached inputs must first
reproduce #58's local image setup and validate any changed boundary inputs; it
cannot claim this evidence solely because its image tags have the same names.
No package rebuild or publication is part of this procedure.

From this Guard branch in PowerShell:

```powershell
git -C C:\GitHub\Waveframe-Cloud worktree add --detach C:\GitHub\Cloud-59-isolated 93bf80f30d170a6be32622a34dbbdf0d85b8ccc6
$ProofName = 'wf54-57-59-' + (Get-Date -Format 'yyyyMMddHHmmss')
.\examples\codex_contained\Start-CloudRevalidation.ps1 -CloudCheckout C:\GitHub\Cloud-59-isolated -Name $ProofName
```

This provisions disposable Cloud using its existing fixed ExampleProvider, drives
fresh Console review/confirmation/approval/publication, and explicitly assigns
separate create and modify runtime credentials. These are local proof approvals,
not customer activation. Existing global Codex configuration is not changed.

The steps run once: wrong-runtime startup and direct write refusal; restored
correct binding with actual create/modify/doctest; policy denial; one lost-response
mutation; original package/report capture; fresh approved version 2 supersession;
inactive version 1 startup refusal; exact historical retrieval and Activity links;
version 2 create/modify/doctest/denial; revocation; inactive version 2 startup
refusal; exact original retrieval and reconciliation. Supersession explicitly
confirms each fresh control and approves through the existing supported APIs.

Only the operator holds Console login and evidence-reader credentials. Readers
have `replay:read` / `receipts:read`; the writer retains its original narrower
write/enrollment scopes. Operator config reaches the writer only via stdin and
its private `0400` secret file. To replace it, the setup helper stops the old
writer, unlinks that operator-owned file and creates a new exclusive `0400` file.
The agent never receives Cloud credentials, configuration or transport mounts.

`revalidate_cloud.py` retains per-step markers, source snapshots, native HTTP,
real CLI events and SDK journals. It stops on any failure. Do not rerun the whole
script after an ambiguous write. Reconcile run/request IDs, one terminal local
record, independent source bytes, the exact saved package and the separate report.
Missing or contradictory evidence remains unresolved. The read-only
`--read-attempt` option permits an explicitly selected retrieval retry after
retaining the failed capture directory; it cannot retry a mutation step.

Historical retrieval checks the original object, identities, hashes and reports
with both authorized operator and scoped runtime readers. Late-upload probes are
explicit negative API tests; they do not invoke repository callbacks. Readability
does not restore execution authority. The SDK still caches loaded authority;
already-running sessions have no immediate remote revocation or per-write online
check. Enrollment success does not promise future preservation/report success.

The full main cohort was run from PowerShell in stages, with development failures
and operator corrections retained. Image/browser installation and approval are
prerequisites, separate from the measured coding turns. The final wrapper encodes
that corrected sequence; the report distinguishes those staged runs from a fresh
uninterrupted wrapper invocation.

After verification, retain sanitized evidence in a **new** directory:

```powershell
python examples/codex_contained/verify_revalidation.py --output "acceptance-output/$ProofName"
python examples/codex_contained/retain_revalidation.py --input "acceptance-output/$ProofName" --output "acceptance-output/$ProofName-retained"
```

The retention step scans for actual disposable secrets before deleting private
handoffs. It verifies #55/#56/#58 manifests against their original Git blobs.
The checked-in evidence uses a separate #59 directory; historical failures remain
historical facts. [Results and attempts](../../docs/acceptance/codex-cloud-59/RESULTS.md)
record the exact source/image comparison and which boundary evidence is reused.

After retaining evidence, clean up only this named proof:

```powershell
python examples/codex_contained/run.py cleanup --name $ProofName --output "acceptance-output/$ProofName/client"
python examples/codex_contained/run_cloud.py cleanup --name $ProofName --output "acceptance-output/$ProofName/cloud"
$PrivateNames = 'operator-private.json','writer-private.json','wrong-private.json','version2-private.json','readers-private.json'
foreach ($PrivateName in $PrivateNames) {
    Remove-Item -LiteralPath "acceptance-output/$ProofName/cloud/$PrivateName" -ErrorAction SilentlyContinue
}
```

No merge, tag, package rebuild/publication, image push, deployment or activation.
Cloud #141/#121 remain rollout blockers. Broader repository/build usability,
deletion, rename, macOS, native Windows writer protection, desktop-app support and
remote TLS remain outside this focused proof.

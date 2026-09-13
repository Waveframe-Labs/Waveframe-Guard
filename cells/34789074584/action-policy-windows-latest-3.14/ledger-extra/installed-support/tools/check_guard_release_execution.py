"""Real installed Guard 0.19 catalog-3 execution; no dev flags or mocked runtime.

Uses only temporary repository files and the immutable approved Ledger fixtures.
Required gate against the exact Guard #51 0.19 candidate.
"""
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import tempfile

from waveframe_guard import Guard, RepositoryBoundaryError
from waveframe_guard.authority.adapters import MemoryAuthorityResolver
from waveframe_guard.authority.types import RegistryEntry

assert metadata.version("governance-ledger") == "0.9.0"
assert metadata.version("waveframe-guard") == "0.19.0"
assert metadata.version("cricore-contract-compiler") == "0.5.0"
assert all(name not in os.environ for name in ("WAVEFRAME_LEDGER_ACTION_POLICY_DEV", "WAVEFRAME_GUARD_ACTION_POLICY_DEV"))
ROOT = Path(__file__).resolve().parents[1]


def resolver(kind):
    folder = ROOT / "tests/fixtures/action_policy_release_v4" / kind
    bundle = json.loads((folder / "authority-bundle.json").read_text())
    receipt = json.loads((folder / "publication-receipt.json").read_text())
    contract = bundle["compiled_authority_contract"]
    entry = RegistryEntry(authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
        contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
        bundle_path=folder / "authority-bundle.json", bundle_hash=bundle["bundle_hash"],
        receipt_path=folder / "publication-receipt.json", receipt_hash=receipt["receipt_hash"],
        bundle_ref="authority-bundle.json", receipt_ref="publication-receipt.json",
        publication_id=receipt["publication_id"], published_at=receipt["published_at"], published_by=receipt["published_by"])
    return entry.authority_ref, MemoryAuthorityResolver([entry])


results = {}
for kind in ("create-only", "modify-only", "mixed"):
    for role in ("repository-maintainer", "security-reviewer", "repository-reviewer"):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "generated").mkdir()
            (root / "docs").mkdir()
            (root / "docs/open.md").write_bytes(b"original")
            (root / "docs/locked.md").write_bytes(b"locked")
            (root / "README.md").write_bytes(b"original")
            authority, source = resolver(kind)
            instance = Guard.local(repository_root=root, workspace=root / "evidence",
                authority=authority, authority_resolver=source,
                actor_identity={"id": "acceptance-agent", "type": "agent", "role": role})
            calls = []
            modify_target = "docs/open.md" if kind == "modify-only" else "README.md"
            modify_allowed = (kind == "modify-only" and role == "repository-reviewer"
                              or kind == "mixed" and role == "security-reviewer")
            try:
                @instance.repository_tool(action="create", target="path", return_result=True, raise_on_block=False)
                def create(path):
                    calls.append("create")
                    return path.create_bytes(b"created")

                @instance.repository_tool(action="modify", target="path", return_result=True, raise_on_block=False)
                def modify(path):
                    calls.append("modify")
                    return path.write_bytes(b"modified")

                for action, target, operation, allowed in (
                    ("create", "generated/new.md", create, kind != "modify-only" and role == "repository-maintainer"),
                    ("modify", modify_target, modify, modify_allowed),
                    ("create", "README.md", create, False),
                    ("modify", "generated/new.md", modify, False),
                    ("create", "generated/private/secret", create, False),
                    ("modify", "docs/locked.md", modify, False),
                ):
                    previous_calls = len(calls)
                    result = operation(target)
                    assert result["executed"] is allowed
                    assert len(calls) == previous_calls + int(allowed)
                    run_id = result["evaluation"]["run_id"]
                    assert instance.store.replay(run_id)["matches"]
                    results[f"{kind}/{role}/{action}/{target}"] = {
                        "executed": result["executed"], "replay_matches": True,
                        "attestation": instance.store.load_execution_attestation(run_id)}
                assert (root / modify_target).read_bytes() == (b"modified" if modify_allowed else b"original")
                assert (root / "docs/locked.md").read_bytes() == b"locked"
                created = kind != "modify-only" and role == "repository-maintainer"
                assert (root / "generated/new.md").exists() is created
                assert not (root / "generated/private").exists()
                if created:
                    assert (root / "generated/new.md").read_bytes() == b"created"
                    try:
                        create("generated/new.md")
                    except RepositoryBoundaryError:
                        pass
                    else:
                        raise AssertionError("existing file creation was not rejected")
                    assert (root / "generated/new.md").read_bytes() == b"created"
                    results[f"{kind}/{role}/collision"] = "rejected; bytes preserved"
            finally:
                instance.close()
print(json.dumps({"development_flags_absent": True, "cases": results,
                  "runtime_activation_ready": False}, indent=2))

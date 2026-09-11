"""Installed-package acceptance using unchanged Ledger v4 publication fixtures."""

import argparse
import hashlib
import json
from importlib.metadata import distribution
from pathlib import Path
import tempfile
from unittest.mock import patch

from waveframe_guard import Guard, RepositoryBoundaryError
from waveframe_guard.authority.adapters import MemoryAuthorityResolver
from waveframe_guard.authority.types import RegistryEntry

COMMITS = {
    "cricore-contract-compiler": "3b91fcc03c804804b2ace7302f37340a787496d9",
    "governance-ledger": "54379d9c8044544fc1b8f32109bdfce35c1c6a05",
}
FIXTURES = Path(__file__).resolve().parents[2] / "tests/fixtures/action_policy_v4"


def resolver(kind, fixtures=FIXTURES):
    directory = fixtures / kind
    bundle = json.loads((directory / "authority-bundle.json").read_text())
    receipt = json.loads((directory / "publication-receipt.json").read_text())
    contract = bundle["compiled_authority_contract"]
    entry = RegistryEntry(
        authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
        contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
        bundle_path=directory / "authority-bundle.json", bundle_hash=bundle["bundle_hash"],
        receipt_path=directory / "publication-receipt.json", receipt_hash=receipt["receipt_hash"],
        bundle_ref=f"{kind}/authority-bundle.json", receipt_ref=f"{kind}/publication-receipt.json",
        publication_id=receipt["publication_id"], published_by=receipt["published_by"],
        published_at=receipt["published_at"],
    )
    return MemoryAuthorityResolver([entry])


def provenance():
    result = {}
    for name, sha in COMMITS.items():
        dist = distribution(name)
        direct = json.loads(dist.read_text("direct_url.json"))
        assert direct["vcs_info"]["commit_id"] == sha, (name, direct)
        result[name] = {"version": dist.version, "pep610": direct}
    return result


def run(fixtures=FIXTURES):
    from compiler import compile_action_policy

    evidence = {"dependencies": provenance(), "fixture_source_commit": COMMITS["governance-ledger"]}
    for line in (fixtures / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == digest, name
    for kind in ("create-only", "modify-only", "mixed"):
        directory = fixtures / kind
        policy = json.loads((directory / "compiler-input.json").read_text())
        expected = json.loads((directory / "compiler-output.json").read_text())
        assert compile_action_policy(policy) == expected
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp).resolve()
        (root / "generated").mkdir()
        instance = Guard.local(
            repository_root=root, workspace=root / "evidence",
            authority="repository-create-only@2.0.0", authority_resolver=resolver("create-only", fixtures),
            actor_identity={"id": "acceptance-agent", "type": "agent", "role": "repository-maintainer"},
        )
        try:
            @instance.repository_tool(target="path", action="create", return_result=True)
            def create(path, content):
                return path.create_bytes(content)

            result = create("generated/new.md", b"local development creation\n")
            assert result["executed"] and (root / "generated/new.md").read_bytes() == b"local development creation\n"
            evidence["authorization"] = result["evaluation"]["enforcement_outcome"]
            evidence["creation"] = result["evaluation"]["execution_attestation"]
            try:
                create("generated/new.md", b"must never overwrite")
            except RepositoryBoundaryError as exc:
                evidence["collision"] = exc.evaluation["execution_attestation"]
                assert exc.evaluation["status"] == "admissible"
                assert not evidence["collision"]["repository_operation"]["created"]
            else:
                raise AssertionError("exclusive collision was not rejected")
            assert (root / "generated/new.md").read_bytes() == b"local development creation\n"
            evidence["saved_creation"] = instance.store.load_execution_attestation(result["evaluation"]["run_id"])
            assert instance.store.replay(result["evaluation"]["run_id"])["matches"]
            import guard.sdk.repository_boundary as filesystem

            write = filesystem.os.write
            writes = []
            def fail_after_prefix(fd, content):
                if writes:
                    raise OSError("acceptance simulated write failure")
                count = write(fd, content[:3])
                writes.append(count)
                return count
            with patch.object(filesystem.os, "write", fail_after_prefix):
                try:
                    create("generated/partial.md", b"private content")
                except OSError as exc:
                    evidence["partial_write"] = exc.evaluation["execution_attestation"]
                    assert exc.evaluation["status"] == "admissible"
                else:
                    raise AssertionError("partial-write fault was not propagated")
            assert (root / "generated/partial.md").read_bytes() == b"pri"
            assert evidence["partial_write"]["repository_operation"]["bytes_written"] == 3
            denied = instance.boundary_for().execute_repository(
                lambda target: (_ for _ in ()).throw(AssertionError("denied callback invoked")),
                execution_request={"schema_version": "normalized_execution_request.v1",
                    "request_id": "acceptance-denied", "action": "create", "target": "generated/private/key",
                    "arguments": {}, "artifacts": []}, operation="create", raise_on_block=False)
            assert not denied["executed"] and not (root / "generated/private").exists()
            evidence["denied"] = denied["evaluation"]["execution_attestation"]
        finally:
            instance.close()
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=FIXTURES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = json.dumps(run(args.fixtures.resolve()), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)

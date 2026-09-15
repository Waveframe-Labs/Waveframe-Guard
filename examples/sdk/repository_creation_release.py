"""Run the supplied example approval through an installed SDK, without dev flags.

The repository root and its generated/ parent must already exist. These fixture
actors/approvals demonstrate the API; production callers supply their own approved
publication through the same resolver interface.
"""
import argparse
import json
from pathlib import Path

from waveframe_guard import Guard
from waveframe_guard.authority.adapters import MemoryAuthorityResolver
from waveframe_guard.authority.types import RegistryEntry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--publication-directory", type=Path,
        default=Path(__file__).resolve().parents[2] / "tests/fixtures/action_policy_release_v4/create-only")
    args = parser.parse_args()
    publication = args.publication_directory.resolve()
    bundle = json.loads((publication / "authority-bundle.json").read_text())
    receipt = json.loads((publication / "publication-receipt.json").read_text())
    contract = bundle["compiled_authority_contract"]
    entry = RegistryEntry(authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
        contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
        bundle_path=publication / "authority-bundle.json", bundle_hash=bundle["bundle_hash"],
        receipt_path=publication / "publication-receipt.json", receipt_hash=receipt["receipt_hash"],
        bundle_ref="authority-bundle.json", receipt_ref="publication-receipt.json",
        publication_id=receipt["publication_id"], published_at=receipt["published_at"], published_by=receipt["published_by"])
    guard = Guard.local(repository_root=args.repository_root.resolve(), workspace=args.evidence_root.resolve(),
        authority=entry.authority_ref, authority_resolver=MemoryAuthorityResolver([entry]),
        actor_identity={"id": "example-agent", "type": "agent", "role": "repository-maintainer"})
    try:
        @guard.repository_tool(action="create", target="path", return_result=True)
        def create(path):
            return path.create_bytes(b"Created through a verified release authority.\n")
        result = create("generated/release-example.md")
        run_id = result["evaluation"]["run_id"]
        print(json.dumps({"run_id": run_id, "proof": guard.store.load_execution_attestation(run_id),
                          "replay": guard.store.replay(run_id)}, indent=2))
    finally:
        guard.close()


if __name__ == "__main__":
    main()

"""Publish and enforce a provider-independent native v3 authority locally.

Default mode retains the historical Ledger 0.8 / Guard 0.17 demonstration.
Use --candidate for Ledger 0.9 / Guard 0.19 mediated repository execution and
saved logical replay. All files live in an automatically removed temporary directory.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import tempfile
from pathlib import Path

from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority.adapters import LocalRegistryResolver

from governance_ledger import (
    apply_policy_translation_control_confirmation,
    apply_policy_translation_disposition,
    approve_policy_translation_proposal,
    create_policy_translation_proposal,
    create_policy_translation_run,
    create_policy_translation_run_evidence,
    finalize_policy_translation_authority_v3,
    interpret_policy_with_domain_pack,
)
from governance_ledger.publication_provenance import canonical_sha256


SOURCE = b"Agents may modify README.md and CHANGELOG.md."
AUTHORITY_REF = "repository-authority@1.0.0"
RUNTIME_FACTS = [
    "actor.subject_kind",
    "proposal.action",
    "proposal.resource.kind",
    "proposal.resource.path",
]


def bytes_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def path_control(path: str, start_byte: int, end_byte: int) -> dict:
    path_bytes = path.encode("utf-8")
    literal_start = SOURCE.index(path_bytes, start_byte, end_byte)
    literal_end = literal_start + len(path_bytes)
    return {
        "control_type": "exact_path_access",
        "actor_kind": "autonomous_agent",
        "action": "modify",
        "resource_kind": "repository_path",
        "fact_id": "proposal.resource.path",
        "operator": "==",
        "effect": "allow",
        "enforcement_point": "waveframe.guard.repository-change.v1",
        "value": {
            "kind": "source_literal",
            "value": path,
            "canonical_value": path,
            "start_byte": literal_start,
            "end_byte": literal_end,
            "literal_hash": bytes_hash(SOURCE[literal_start:literal_end]),
        },
        "required_runtime_facts": RUNTIME_FACTS,
    }


def build_publication() -> dict:
    draft = interpret_policy_with_domain_pack(
        SOURCE,
        domain_pack_id="repository-changes",
        domain_pack_version="1.0.0",
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
    )
    statement = draft["source_statements"][0]
    source_policy = draft["source_policy"]
    run = create_policy_translation_run(
        source_policy_ref=source_policy["source_policy_ref"],
        source_revision=source_policy["source_revision"],
        source_snapshot_hash=source_policy["snapshot_hash"],
        provider_class="hosted_model",
        provider_identifier="private-provider/deployment",
        translation_template_version="template-1",
        translation_template_hash=bytes_hash(b"private-template"),
        request_configuration_id="request-config-1",
        request_configuration_hash=bytes_hash(b"private-configuration"),
        request_hash=bytes_hash(b"private request"),
        response_hash=bytes_hash(b"private response"),
        explanation_hash=bytes_hash(b"private explanation"),
        created_at="2026-09-04T12:00:00Z",
        completed_at="2026-09-04T12:00:01Z",
        sequence_number=0,
        previous_run_hash=None,
    )
    proposal = create_policy_translation_proposal(
        SOURCE,
        source_policy_id="repository-policy",
        source_revision="revision-1",
        authority_id="repository-authority",
        authority_version="1.0.0",
        clauses=[
            {
                "start_byte": statement["start_byte"],
                "end_byte": statement["end_byte"],
                "coverage_status": "fully_represented",
                "candidate_controls": [
                    path_control(
                        "README.md", statement["start_byte"], statement["end_byte"]
                    ),
                    path_control(
                        "CHANGELOG.md",
                        statement["start_byte"],
                        statement["end_byte"],
                    ),
                ],
                "unresolved_binding_ids": [],
                "limitation_code": None,
                "residual_unsupported_spans": [],
            }
        ],
        organizational_bindings=[],
        translation_runs=[run],
    )

    confirmation = None
    clause = proposal["clauses"][0]
    for control in clause["candidate_controls"]:
        confirmation = apply_policy_translation_control_confirmation(
            proposal,
            confirmation,
            clause_id=clause["clause_id"],
            candidate_control_id=control["candidate_control_id"],
            confirmed_by="policy-owner",
            confirmed_at="2026-09-04T12:01:00Z",
        )
    confirmation = apply_policy_translation_disposition(
        proposal,
        confirmation,
        clause_id=clause["clause_id"],
        coverage_status="fully_represented",
        reason_code="human-confirmed-complete",
        confirmed_by="policy-owner",
        confirmed_at="2026-09-04T12:02:00Z",
    )
    approval = approve_policy_translation_proposal(
        proposal,
        confirmation,
        approved_by="policy-owner",
        approved_at="2026-09-04T12:03:00Z",
    )
    publication = finalize_policy_translation_authority_v3(
        proposal,
        confirmation,
        approval,
        committed_by="ledger-committer",
        committed_at="2026-09-04T12:04:00Z",
        publication_id="publication-1",
        published_by="ledger-publisher",
        published_at="2026-09-04T12:05:00Z",
    )

    # Raw provider evidence is private and independently deletable. It is not a
    # publication or Guard input.
    private_artifact = create_policy_translation_run_evidence(
        run,
        request_bytes=b"private request",
        response_bytes=b"private response",
        provider_explanation="private explanation",
    )
    private_path = Path("private-translation-evidence.json")
    private_path.write_text(json.dumps(private_artifact), encoding="utf-8")
    private_path.unlink()
    del private_artifact, proposal, confirmation, approval, run
    assert not private_path.exists()
    return publication


def write_publication(publication: dict) -> LocalRegistryResolver:
    root = Path("publication").resolve()
    contracts = root / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)
    bundle_ref = "contracts/repository-authority-1.0.0.authority-bundle.json"
    receipt_ref = "contracts/repository-authority-1.0.0.publication-receipt.json"
    bundle = publication["authority_bundle"]
    receipt = publication["publication_receipt"]
    (root / bundle_ref).write_text(json.dumps(bundle), encoding="utf-8")
    (root / receipt_ref).write_text(json.dumps(receipt), encoding="utf-8")
    registry = {
        "schema_version": "contract_registry.v1",
        "contracts": [
            {
                "authority_ref": AUTHORITY_REF,
                "contract_id": "repository-authority",
                "contract_version": "1.0.0",
                "contract_hash": publication["compiled_authority_contract"][
                    "contract_hash"
                ],
                "bundle_path": bundle_ref,
                "bundle_hash": bundle["bundle_hash"],
                "receipt_path": receipt_ref,
                "receipt_hash": receipt["receipt_hash"],
                "publication_id": receipt["publication_id"],
                "published_at": receipt["published_at"],
                "published_by": receipt["published_by"],
                "lifecycle_state": "active",
            }
        ],
    }
    registry["registry_hash"] = canonical_sha256(registry)
    registry_path = contracts / "index.json"
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return LocalRegistryResolver(registry_path=registry_path, workspace_root=root)


def run_example(*, candidate: bool = False) -> None:
    ledger_version, guard_version = ("0.9.0", "0.19.0") if candidate else ("0.8.0", "0.17.0")
    assert importlib.metadata.version("governance-ledger") == ledger_version
    assert importlib.metadata.version("waveframe-guard") == guard_version
    publication = build_publication()
    public_json = json.dumps(
        {
            "bundle": publication["authority_bundle"],
            "receipt": publication["publication_receipt"],
        }
    )
    assert all(
        private_term not in public_json
        for private_term in (
            "private-provider",
            "private-request",
            "private-response",
            "provider_identifier",
        )
    )

    repository = Path("repository").resolve()
    (repository / "src").mkdir(parents=True)
    for name in ("README.md", "CHANGELOG.md", "src/unpublished.py"):
        (repository / name).write_bytes(b"original")
    guard = Guard.local(
        **({"repository_root": repository} if candidate else {}),
        workspace=Path("guard-evidence").resolve(),
        authority=AUTHORITY_REF,
        authority_resolver=write_publication(publication),
        actor_identity={"id": "release-agent", "type": "agent"},
    )
    mutations = []
    try:
        if candidate:
            @guard.repository_tool(action="modify", target="path", return_result=True,
                                   raise_on_block=False)
            def modify(path):
                mutations.append("modify")
                return path.write_bytes(b"modified")

            for target, allowed in (("README.md", True), ("CHANGELOG.md", True),
                                    ("src/unpublished.py", False)):
                before = len(mutations)
                result = modify(target)
                assert result["executed"] is allowed
                assert (repository / target).read_bytes() == (b"modified" if allowed else b"original")
                assert guard.store.replay(result["evaluation"]["run_id"])["matches"]
                assert len(mutations) == before + int(allowed)
            assert mutations == ["modify", "modify"]
        else:
            @guard.tool(action="modify", target="path", return_result=True)
            def modify(path: str) -> str:
                mutations.append(path)
                return path

            assert modify("README.md")["executed"] is True
            assert modify("CHANGELOG.md")["executed"] is True
            try:
                modify("src/unpublished.py")
            except GuardExecutionBlocked:
                pass
            else:
                raise AssertionError("unpublished path was not blocked")
            assert mutations == ["README.md", "CHANGELOG.md"]
        loaded = guard.boundary_for().loaded_authority
        assert loaded.schema_version == "authority_bundle.v3"
        assert loaded.contract["schema_version"] == "compiled_authority_contract.v2"
    finally:
        if candidate:
            guard.close()
    print(f"ledger={ledger_version} guard={guard_version}")
    print("bundle=authority_bundle.v3 receipt=publication_receipt.v3")
    print("allowed=README.md,CHANGELOG.md blocked=src/unpublished.py")
    print("private_translation_evidence_required=False")


def main(*, candidate: bool = False) -> None:
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as temp:
        try:
            os.chdir(temp)
            run_example(candidate=candidate)
        finally:
            os.chdir(previous)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", action="store_true", help="require the real 0.9.0/0.19.0 candidate pair")
    main(candidate=parser.parse_args().candidate)

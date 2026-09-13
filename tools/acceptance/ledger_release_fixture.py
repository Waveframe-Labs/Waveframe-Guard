"""Catalog 3 source -> individual confirmation/review -> fresh fixture approval -> v4.

All actors and timestamps below are explicit EXAMPLE FIXTURES, not real human
approval. Applications must obtain new human decisions before calling approval.
No development flags, runtime activation, or filesystem operations are involved.
Run to display the approved example review and validate publication; pass
--write-fixtures only when intentionally creating the new release test evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from governance_ledger.policy_translation import get_policy_translation_capability_catalog
from governance_ledger.action_policy_publication import finalize_policy_translation_authority_v4
from governance_ledger.domain_policy import interpret_policy_with_domain_pack
from governance_ledger.policy_translation import (
    apply_policy_translation_control_confirmation, apply_policy_translation_disposition,
    approve_policy_translation_proposal, create_policy_translation_proposal,
    create_policy_translation_run, render_policy_translation_review,
)
from governance_ledger.publication_provenance import bytes_sha256

POLICIES = {
    "create-only": [
        ("Agents must use role repository-maintainer to create repository files.", [("create", "acting_role", "require", "repository-maintainer")]),
        ("Agents may create files under generated/.", [("create", "prefix_path_access", "allow", "generated/")]),
        ("Agents must not create files under generated/private/.", [("create", "prefix_path_access", "deny", "generated/private/")]),
    ],
    "modify-only": [
        ("Agents must use role repository-reviewer to modify repository files.", [("modify", "acting_role", "require", "repository-reviewer")]),
        ("Agents may modify files under docs/.", [("modify", "prefix_path_access", "allow", "docs/")]),
        ("Agents must not modify docs/locked.md.", [("modify", "exact_path_access", "deny", "docs/locked.md")]),
    ],
    "mixed": [
        ("Agents must use role repository-maintainer to create repository files.", [("create", "acting_role", "require", "repository-maintainer")]),
        ("Agents must use role security-reviewer to modify repository files.", [("modify", "acting_role", "require", "security-reviewer")]),
        ("Agents may create generated/new.md and modify README.md.", [("create", "exact_path_access", "allow", "generated/new.md"), ("modify", "exact_path_access", "allow", "README.md")]),
        ("Agents must not modify generated/new.md and create README.md.", [("modify", "exact_path_access", "deny", "generated/new.md"), ("create", "exact_path_access", "deny", "README.md")]),
    ],
}


def build_proposal_fixture(name: str, rows=None) -> tuple:
    rows = POLICIES[name] if rows is None else rows
    source = "\n".join(row[0] for row in rows).encode("utf-8")
    catalog = get_policy_translation_capability_catalog(catalog_version="3.0.0")
    identity = dict(source_policy_id="repository-policy", source_revision="revision-1",
                    authority_id="repository-" + name, authority_version="3.0.0")
    draft = interpret_policy_with_domain_pack(source, domain_pack_id="repository-changes",
        domain_pack_version="3.0.0", **identity)
    assert len(draft["source_statements"]) == len(rows)
    clauses = []
    for statement, (_, specs) in zip(draft["source_statements"], rows):
        start, end = statement["start_byte"], statement["end_byte"]
        controls = []
        for action, control_type, effect, value in specs:
            advertised = next(item for item in catalog["control_types"]
                if (item["control_type"], item["action"]) == (control_type, action))
            literal_start = source.index(value.encode(), start, end)
            literal_end = literal_start + len(value.encode())
            controls.append({
                "control_type": control_type, "actor_kind": "autonomous_agent", "action": action,
                "resource_kind": advertised["resource_kind"], "fact_id": advertised["fact_id"],
                "operator": advertised["operator"], "effect": effect,
                "enforcement_point": catalog["enforcement_points"][0]["enforcement_point_id"],
                "required_runtime_facts": advertised["required_runtime_facts"],
                "value": {"kind": "source_literal", "value": value, "canonical_value": value,
                    "start_byte": literal_start, "end_byte": literal_end,
                    "literal_hash": bytes_sha256(source[literal_start:literal_end])},
            })
        clauses.append({"start_byte": start, "end_byte": end,
            "coverage_status": "fully_represented" if specs else "entirely_unsupported",
            "candidate_controls": controls, "unresolved_binding_ids": [],
            "limitation_code": None if specs else "other",
            "residual_unsupported_spans": [] if specs else [{"start_byte": start, "end_byte": end}]})
    run = create_policy_translation_run(
        source_policy_ref=draft["source_policy"]["source_policy_ref"], source_revision="revision-1",
        source_snapshot_hash=bytes_sha256(source), provider_class="guided_deterministic",
        provider_identifier="release-example-fixture-author", translation_template_version="fixture-v1",
        translation_template_hash=bytes_sha256(b"fixture-v1"), request_configuration_id="fixture-v1",
        request_configuration_hash=bytes_sha256(b"fixture-v1"), request_hash=bytes_sha256(source),
        response_hash=bytes_sha256(json.dumps(clauses, sort_keys=True).encode()),
        created_at="2026-09-12T12:00:00Z", completed_at="2026-09-12T12:00:01Z",
        sequence_number=0, previous_run_hash=None, catalog_version="3.0.0")
    proposal = create_policy_translation_proposal(source, **identity, clauses=clauses,
        organizational_bindings=[], translation_runs=[run], catalog_version="3.0.0")
    return source, draft, proposal


def build_fixture(name: str, rows=None) -> dict:
    source, draft, proposal = build_proposal_fixture(name, rows)
    # Fresh individual decisions, with no migrated development confirmations.
    confirmation = None
    for clause in proposal["clauses"]:
        for control in clause["candidate_controls"]:
            confirmation = apply_policy_translation_control_confirmation(proposal, confirmation,
                clause_id=clause["clause_id"], candidate_control_id=control["candidate_control_id"],
                confirmed_by="example-release-policy-owner", confirmed_at="2026-09-12T12:01:00Z")
        confirmation = apply_policy_translation_disposition(proposal, confirmation,
            clause_id=clause["clause_id"], coverage_status=clause["coverage_status"],
            reason_code="human-confirmed-complete" if clause["candidate_controls"] else "not-enforceable",
            acknowledge_unrepresented=not bool(clause["candidate_controls"]), confirmed_by="example-release-policy-owner",
            confirmed_at="2026-09-12T12:02:00Z")
    review = render_policy_translation_review(proposal, confirmation)
    approval = approve_policy_translation_proposal(proposal, confirmation,
        approved_by="example-release-policy-owner", approved_at="2026-09-12T12:03:00Z")
    publication = finalize_policy_translation_authority_v4(proposal, confirmation, approval,
        committed_by="example-release-committer", committed_at="2026-09-12T12:04:00Z",
        publication_id="release-example-" + name, published_by="example-release-publisher",
        published_at="2026-09-12T12:05:00Z")
    return {"source": source.decode(), "source-interpretation": draft, "proposal": proposal,
            "confirmation": confirmation, "review": review, "approval": approval,
            "constraint-ir": publication["authority_bundle"]["constraint_ir"],
            "compiler-input": publication["canonical_compiler_input"],
            "compiler-output": publication["compiler_output"],
            "compiled-authority": publication["compiled_authority_contract"],
            "authority-bundle": publication["authority_bundle"],
            "publication-receipt": publication["publication_receipt"]}


if __name__ == "__main__":
    import argparse
    from governance_ledger.publication_provenance import validate_publication_receipt

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-fixtures", action="store_true")
    args = parser.parse_args()
    for name in POLICIES:
        fixture = build_fixture(name)
        assert validate_publication_receipt(fixture["authority-bundle"], fixture["publication-receipt"])["valid"]
        print(json.dumps({"example": name, "review": fixture["review"],
                          "explicit_fixture_approval": fixture["approval"],
                          "bundle_hash": fixture["authority-bundle"]["bundle_hash"],
                          "receipt_hash": fixture["publication-receipt"]["receipt_hash"],
                          "runtime_activation_ready": False}, indent=2))
        if args.write_fixtures:
            folder = Path("tests/fixtures/action_policy_release_v4") / name
            folder.mkdir(parents=True, exist_ok=True)
            for artifact, value in fixture.items():
                path = folder / (artifact + (".txt" if artifact == "source" else ".json"))
                path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2) + "\n", encoding="utf-8", newline="\n")

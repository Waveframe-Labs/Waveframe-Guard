# ---
# title: "Ledger v3 clean-wheel acceptance"
# filetype: "python"
# type: "acceptance-test"
# domain: "guard-sdk"
# version: "0.17.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path


RUNNER = r'''
import hashlib
import json
from pathlib import Path

from governance_ledger import (
    apply_policy_translation_control_confirmation,
    apply_policy_translation_disposition,
    approve_policy_translation_proposal,
    create_policy_translation_proposal,
    create_policy_translation_run,
    finalize_policy_translation_authority_v3,
    interpret_policy_with_domain_pack,
)
from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority.adapters import LocalRegistryResolver


def bytes_hash(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


source = b"Agents may modify README.md and CHANGELOG.md."
draft = interpret_policy_with_domain_pack(
    source,
    domain_pack_id="repository-changes",
    domain_pack_version="1.0.0",
    source_policy_id="repository-policy",
    source_revision="revision-1",
    authority_id="repository-authority",
    authority_version="1.0.0",
)
statement = draft["source_statements"][0]


def control(path):
    start = source.index(path.encode(), statement["start_byte"], statement["end_byte"])
    end = start + len(path.encode())
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
            "start_byte": start,
            "end_byte": end,
            "literal_hash": bytes_hash(source[start:end]),
        },
        "required_runtime_facts": [
            "actor.subject_kind",
            "proposal.action",
            "proposal.resource.kind",
            "proposal.resource.path",
        ],
    }


source_ref = draft["source_policy"]
run = create_policy_translation_run(
    source_policy_ref=source_ref["source_policy_ref"],
    source_revision=source_ref["source_revision"],
    source_snapshot_hash=source_ref["snapshot_hash"],
    provider_class="hosted_model",
    provider_identifier="private-provider/deployment",
    translation_template_version="template-1",
    translation_template_hash=bytes_hash(b"private-template"),
    request_configuration_id="request-config-1",
    request_configuration_hash=bytes_hash(b"private-configuration"),
    request_hash=bytes_hash(b"private-request"),
    response_hash=bytes_hash(b"private-response"),
    explanation_hash=bytes_hash(b"private-explanation"),
    created_at="2026-09-03T12:00:00Z",
    completed_at="2026-09-03T12:00:01Z",
    sequence_number=0,
    previous_run_hash=None,
)
proposal = create_policy_translation_proposal(
    source,
    source_policy_id="repository-policy",
    source_revision="revision-1",
    authority_id="repository-authority",
    authority_version="1.0.0",
    clauses=[{
        "start_byte": statement["start_byte"],
        "end_byte": statement["end_byte"],
        "coverage_status": "fully_represented",
        "candidate_controls": [control("README.md"), control("CHANGELOG.md")],
        "unresolved_binding_ids": [],
        "limitation_code": None,
        "residual_unsupported_spans": [],
    }],
    organizational_bindings=[],
    translation_runs=[run],
)
state = None
clause = proposal["clauses"][0]
for candidate in clause["candidate_controls"]:
    state = apply_policy_translation_control_confirmation(
        proposal,
        state,
        clause_id=clause["clause_id"],
        candidate_control_id=candidate["candidate_control_id"],
        confirmed_by="policy-owner",
        confirmed_at="2026-09-03T12:01:00Z",
    )
state = apply_policy_translation_disposition(
    proposal,
    state,
    clause_id=clause["clause_id"],
    coverage_status="fully_represented",
    reason_code="human-confirmed-complete",
    confirmed_by="policy-owner",
    confirmed_at="2026-09-03T12:02:00Z",
)
approval = approve_policy_translation_proposal(
    proposal,
    state,
    approved_by="policy-owner",
    approved_at="2026-09-03T12:03:00Z",
)
publication = finalize_policy_translation_authority_v3(
    proposal,
    state,
    approval,
    committed_by="ledger-committer",
    committed_at="2026-09-03T12:04:00Z",
    publication_id="publication-1",
    published_by="ledger-publisher",
    published_at="2026-09-03T12:05:00Z",
)

# Private evidence is independently deletable and is not copied into public artifacts.
private = Path("private-run-evidence.json")
private.write_text('{"request":"private","response":"private","explanation":"private"}')
private.unlink()
public_json = json.dumps({
    "bundle": publication["authority_bundle"],
    "receipt": publication["publication_receipt"],
})
assert "private-provider" not in public_json
assert "private-request" not in public_json
assert "private-response" not in public_json

contracts = Path("publication/contracts")
contracts.mkdir(parents=True)
bundle_ref = "contracts/repository-authority-1.0.0.authority-bundle.json"
receipt_ref = "contracts/repository-authority-1.0.0.publication-receipt.json"
(Path("publication") / bundle_ref).write_text(json.dumps(publication["authority_bundle"]))
(Path("publication") / receipt_ref).write_text(json.dumps(publication["publication_receipt"]))
entry = {
    "authority_ref": "repository-authority@1.0.0",
    "contract_id": "repository-authority",
    "contract_version": "1.0.0",
    "contract_hash": publication["compiled_authority_contract"]["contract_hash"],
    "bundle_path": bundle_ref,
    "bundle_hash": publication["authority_bundle"]["bundle_hash"],
    "receipt_path": receipt_ref,
    "receipt_hash": publication["publication_receipt"]["receipt_hash"],
    "publication_id": "publication-1",
    "lifecycle_state": "active",
    "published_at": "2026-09-03T12:05:00Z",
    "published_by": "ledger-publisher",
}
registry = {"schema_version": "contract_registry.v1", "contracts": [entry]}
registry["registry_hash"] = canonical_hash(registry)
(contracts / "index.json").write_text(json.dumps(registry))

guard = Guard.local(
    workspace="evidence",
    authority="repository-authority@1.0.0",
    authority_resolver=LocalRegistryResolver(workspace_root="publication"),
    actor_identity={"id": "repo-agent", "type": "agent"},
)
mutations = []


@guard.tool(action="modify", target="path", return_result=True)
def modify(path):
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
loaded = guard.boundary_for().loaded_authority
assert loaded.schema_version == "authority_bundle.v3"
assert loaded.contract["schema_version"] == "compiled_authority_contract.v2"
assert loaded.authority_evidence["authority_bundle"]["schema_version"] == "authority_bundle.v3"
assert loaded.authority_evidence["publication_receipt"]["schema_version"] == "publication_receipt.v3"
assert mutations == ["README.md", "CHANGELOG.md"]
print("allowed=README.md,CHANGELOG.md")
print("blocked=src/unpublished.py")
print("private_evidence_required=False")
print("bundle=authority_bundle.v3")
print("receipt=publication_receipt.v3")
'''


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Ledger v3 Guard acceptance from a clean wheel-only environment."
    )
    parser.add_argument("--install-spec", required=True, help="Guard wheel path or pip spec")
    parser.add_argument("--ledger-install-spec", required=True, help="Ledger 0.8 wheel path")
    args = parser.parse_args()
    install_spec = Path(args.install_spec)
    guard_spec = str(install_spec.resolve()) if install_spec.exists() else args.install_spec
    ledger_install_spec = Path(args.ledger_install_spec)
    ledger_spec = (
        str(ledger_install_spec.resolve())
        if ledger_install_spec.exists()
        else args.ledger_install_spec
    )

    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="waveframe-guard-ledger-v3-") as raw_directory:
        root = Path(raw_directory)
        environment = root / ".venv"
        _run([sys.executable, "-m", "venv", str(environment)], cwd=root)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _run([str(python), "-m", "pip", "install", ledger_spec], cwd=root)
        _run([str(python), "-m", "pip", "install", guard_spec], cwd=root)
        runner = root / "acceptance.py"
        runner.write_text(textwrap.dedent(RUNNER), encoding="utf-8")
        completed = _run([str(python), str(runner)], cwd=root, capture_output=True)
        checked = _run([str(python), "-m", "pip", "check"], cwd=root, capture_output=True)

    print(completed.stdout, end="")
    print(checked.stdout, end="")
    print(f"acceptance_seconds={time.perf_counter() - started:.3f}")


def _run(
    command: list[str], *, cwd: Path, capture_output: bool = False
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command, cwd=cwd, text=True, capture_output=capture_output, check=False
    )
    if completed.returncode:
        if capture_output:
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
        raise SystemExit(completed.returncode)
    return completed


if __name__ == "__main__":
    main()

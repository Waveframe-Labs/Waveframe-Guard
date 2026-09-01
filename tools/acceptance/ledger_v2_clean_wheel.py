# ---
# title: "Ledger v2 clean-wheel acceptance"
# filetype: "python"
# type: "acceptance-test"
# domain: "guard-sdk"
# version: "0.16.0"
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
    apply_policy_mapping_decision,
    finalize_domain_policy_authority,
    interpret_policy_with_domain_pack,
)
from guard.sdk import Guard, GuardExecutionBlocked
from waveframe_guard.authority.adapters import LocalRegistryResolver


def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


# Acceptance fixture setup represents Ledger's separate publication step.
source = (
    b"Repository changes may be made only by repository-maintainers.\n"
    b"Agents may modify README.md.\n"
    b"Agents must not modify files under deployment/.\n"
    b"Repository policy context."
)
draft = interpret_policy_with_domain_pack(
    source,
    domain_pack_id="repository-changes",
    domain_pack_version="1.0.0",
    source_policy_id="repository-policy",
    source_revision="rev-1",
    authority_id="repository-authority",
    authority_version="1.0.0",
)
pending = next(item for item in draft["source_statements"] if item["classification"] == "pending")
mapped = apply_policy_mapping_decision(
    draft,
    statement_id=pending["statement_id"],
    disposition="informational",
    mapper_identity="owner@example.com",
    mapped_at="2026-08-31T11:59:00Z",
    reason_code="context-only",
)
publication = finalize_domain_policy_authority(
    mapped["updated_interpretation"],
    approval_id="approval-1",
    approved_by="owner@example.com",
    approved_at="2026-08-31T12:00:00Z",
    committed_by="owner@example.com",
    committed_at="2026-08-31T12:01:00Z",
    publication_id="publication-1",
    published_by="publisher@example.com",
    published_at="2026-08-31T12:02:00Z",
)
contracts = Path("publication/contracts")
contracts.mkdir(parents=True)
bundle_ref = "contracts/repository-authority-1.0.0.authority-bundle.json"
receipt_ref = "contracts/repository-authority-1.0.0.publication-receipt.json"
(Path("publication") / bundle_ref).write_text(json.dumps(publication["authority_bundle"]), encoding="utf-8")
(Path("publication") / receipt_ref).write_text(json.dumps(publication["publication_receipt"]), encoding="utf-8")
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
    "published_at": "2026-08-31T12:02:00Z",
    "published_by": "publisher@example.com",
}
registry = {"schema_version": "contract_registry.v1", "contracts": [entry]}
registry["registry_hash"] = canonical_hash(registry)
(contracts / "index.json").write_text(json.dumps(registry), encoding="utf-8")

# This is the application-facing workflow: identity, resolver, proposal, callback.
resolver = LocalRegistryResolver(workspace_root="publication")
guard = Guard.local(
    workspace="evidence",
    authority="repository-authority@1.0.0",
    authority_resolver=resolver,
    actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
)
mutations = []

@guard.tool(action="modify", target="path", return_result=True)
def write_file(path):
    mutations.append(path)
    return path

allowed = write_file("README.md")
try:
    write_file("deployment/production.yml")
except GuardExecutionBlocked as blocked:
    blocked_evaluation = blocked.evaluation
else:
    raise AssertionError("deployment proposal was not blocked")

assert allowed["executed"] is True
assert blocked_evaluation["status"] == "blocked"
assert mutations == ["README.md"]
for evaluation in (allowed["evaluation"], blocked_evaluation):
    evidence = evaluation["authority_evidence"]
    for key in (
        "authority", "authority_bundle", "publication_receipt", "compiled_contract",
        "domain_pack", "runtime_fact_schema", "constraint_ir", "runtime_facts",
    ):
        assert key in evidence
print("allowed=README.md")
print("blocked=deployment/production.yml")
print("mutation_count=1")
print("manual_runtime_facts=False")
print("repository_imports=False")
'''


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Ledger v2 Guard acceptance from a clean wheel-only environment."
    )
    parser.add_argument("--install-spec", required=True, help="Guard wheel path or pip spec")
    args = parser.parse_args()
    install_spec = Path(args.install_spec)
    resolved_spec = str(install_spec.resolve()) if install_spec.exists() else args.install_spec

    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="waveframe-guard-ledger-v2-") as raw_directory:
        root = Path(raw_directory)
        environment = root / ".venv"
        _run([sys.executable, "-m", "venv", str(environment)], cwd=root)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _run([str(python), "-m", "pip", "install", "governance-ledger==0.7.0"], cwd=root)
        _run([str(python), "-m", "pip", "install", resolved_spec], cwd=root)
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

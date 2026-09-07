"""Run the harmless issue #39 reproductions against the imported Guard package.

Run from the repository root with ``python -m tools.security.reproduce_issue39``.
Only an in-memory counter callback and temporary registry files are used.
"""

import json
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory

from compiler.compile_policy import compile_policy
from cricore.api import evaluate_structured
from proposal_normalizer.build_proposal import build_proposal
from waveframe_guard import GovernanceError, GovernedRuntime, execute, install_guard


def reproduce():
    actor = {"id": "user-1", "type": "human", "role": "manager"}
    contract = compile_policy({
        "contract_id": "issue39", "contract_version": "1.0.0",
        "authority": {"required_roles": ["manager"]},
    })
    proposal = build_proposal(
        proposal_id="issue39", actor=actor,
        mutation={"domain": "python", "resource": "callback", "action": "call"},
        contract={"id": contract["contract_id"], "version": contract["contract_version"],
                  "hash": contract["contract_hash"]},
        artifact_paths=[],
    )
    context = {
        "mode": "strict",
        "decision_status": "verified",
        "contract_metadata": {key: contract[key] for key in
                              ("contract_id", "contract_version", "contract_hash")},
        "identities": {"actors": [actor], "required_roles": ["manager"], "conflict_flags": {}},
    }
    strict = evaluate_structured(proposal=proposal, compiled_contract=contract,
                                 mode="strict", run_context=context)
    report = {"cricore": version("cricore"), "strict_control_allowed": strict.commit_allowed,
              "strict_control_failed_stages": strict.failed_stages}
    calls = []

    def callback():
        calls.append("called")
        return "callback completed"

    install_guard(actor=actor, contract=contract, mode="local")
    try:
        report["execute_result"] = execute(callback)
    except GovernanceError as exc:
        report["execute_error"] = str(exc)
    report["callback_count"] = len(calls)
    with TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "contract.json").write_text(json.dumps(contract), encoding="utf-8")
        registry = root / "index.json"
        registry.write_text(json.dumps({"contracts": [{"contract_id": "issue39",
                            "contract_version": "1.0.0", "path": "contract.json"}]}), encoding="utf-8")
        runtime = GovernedRuntime(registry_path=registry)
        try:
            result = runtime.execute_proposal(proposal, actor=actor,
                                             contract_id="issue39@1.0.0", raise_on_block=False)
            report["execute_proposal_allowed"] = result.allowed
        except GovernanceError as exc:
            report["execute_proposal_error"] = str(exc)
        report["runtime_allowed_events"] = sum(bool(event["allowed"]) for event in runtime.audit_events)
    return report


if __name__ == "__main__":
    print(json.dumps(reproduce(), indent=2))

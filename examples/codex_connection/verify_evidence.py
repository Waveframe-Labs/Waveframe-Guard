"""Verify copied SDK artifacts and byte observations; replay is logical only."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile

from waveframe_guard import Guard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    root = args.evidence.resolve()
    result = {"attestations": [], "inspections": {}, "replay_scope": "logical_decision_only"}
    # Artifact-store access requires no authority activation or mutation callback.
    # The released replay API saves a replay artifact. Work on copies so
    # verification never changes the archived evidence or its byte manifest.
    with tempfile.TemporaryDirectory() as temp:
        for action in ("create", "modify"):
            workspace = Path(temp) / action
            shutil.copytree(root / "guard" / action, workspace)
            guard = Guard.local(workspace=workspace)
            try:
                for path in (guard.workspace / "execution-attestations").glob("*.json"):
                    attestation = guard.store.load_execution_attestation(path.stem)
                    guard.store.load_run(path.stem)
                    replay = guard.store.replay(path.stem)
                    assert replay["matches"]
                    result["attestations"].append({"run_id": path.stem,
                        "execution_status": attestation["execution_status"],
                        "mutation_status": attestation["mutation_status"], "replay_matches": True})
            finally:
                guard.close()
    for path in (root / "native").glob("*/inspection.json"):
        inspection = json.loads(path.read_text())
        changes = sorted(k for k in inspection["before"].keys() | inspection["after"].keys()
                         if inspection["before"].get(k) != inspection["after"].get(k))
        assert changes == inspection["changed"]
        assert changes == (["README.md", "generated/new.md"] if path.parent.name == "allowed" else [])
        result["inspections"][path.parent.name] = changes
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

"""Published Guard 0.18/Ledger 0.8 legacy modify/create boundary check.

Uses in-memory callbacks only. Local files are temporary publication/evidence artifacts.
"""
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import runpy
import tempfile

from guard.sdk import Guard, GuardExecutionBlocked
from guard.sdk.repository_boundary import RepositoryBoundaryError

ROOT = Path(__file__).resolve().parents[1]
assert metadata.version("waveframe-guard") == "0.18.0"
assert metadata.version("governance-ledger") == "0.8.0"
example = runpy.run_path(str(ROOT / "examples/native_v3_multi_control.py"))
previous = Path.cwd()
with tempfile.TemporaryDirectory(dir=ROOT / "runtime", prefix="legacy-operations-") as folder:
    try:
        os.chdir(folder)
        publication = example["build_publication"]()
        Path("README.md").write_text("test fixture", encoding="utf-8")
        Path("unlisted.md").write_text("test fixture", encoding="utf-8")
        guard = Guard.local(workspace="guard-evidence", authority=example["AUTHORITY_REF"],
            repository_root=str(Path.cwd()),
            authority_resolver=example["write_publication"](publication),
            actor_identity={"id": "test-agent", "type": "agent"})
        callbacks = []

        @guard.repository_tool(action="modify", target="path", return_result=True)
        def modify(path):
            callbacks.append(("modify", "README.md"))
            return "callback-only"

        assert modify("README.md")["executed"] is True
        try:
            modify("unlisted.md")
        except GuardExecutionBlocked:
            pass
        else:
            raise AssertionError("legacy missing allow was not blocked")
        try:
            @guard.repository_tool(action="create", target="path", return_result=True)
            def create(path):
                callbacks.append(("create", path))
                return path
            create("README.md")
        except (GuardExecutionBlocked, ValueError, RepositoryBoundaryError) as exc:
            create_reason = str(exc)
        else:
            raise AssertionError("legacy modify authority acquired creation permission")
        assert callbacks == [("modify", "README.md")]
        print(json.dumps({"ledger": metadata.version("governance-ledger"),
            "guard": metadata.version("waveframe-guard"), "modify_matching_allow": "executed",
            "modify_missing_allow": "blocked", "create_on_modify_authority": "blocked",
            "create_reason": create_reason, "callbacks": callbacks,
            "filesystem_operations_implemented": False}, indent=2))
    finally:
        if "guard" in locals():
            guard.close()
        os.chdir(previous)

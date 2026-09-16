"""Issue #54 experiment: stdio MCP -> released Guard repository capabilities.

Not an installer or a sandbox. Run only from operator-controlled code/imports.
The unchanged mixed publication fixture requires two explicit operation roles.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import threading
from uuid import uuid4

from waveframe_guard import Guard
from waveframe_guard.authority.adapters import MemoryAuthorityResolver
from waveframe_guard.authority.types import RegistryEntry


def fixture_resolver(directory: Path):
    """Transport existing publication artifacts; Guard verifies all authority."""
    bundle = json.loads((directory / "authority-bundle.json").read_text())
    receipt = json.loads((directory / "publication-receipt.json").read_text())
    contract = bundle["compiled_authority_contract"]
    return MemoryAuthorityResolver([RegistryEntry(
        authority_ref=contract["authority_ref"], contract_id=contract["contract_id"],
        contract_version=contract["contract_version"], contract_hash=contract["contract_hash"],
        bundle_path=directory / "authority-bundle.json", bundle_hash=bundle["bundle_hash"],
        receipt_path=directory / "publication-receipt.json", receipt_hash=receipt["receipt_hash"],
        bundle_ref="mixed/authority-bundle.json", receipt_ref="mixed/publication-receipt.json",
        publication_id=receipt["publication_id"], published_by=receipt["published_by"],
        published_at=receipt["published_at"],
    )])


class Writer:
    def __init__(self, root: Path, evidence: Path, publication: Path):
        self.lock = threading.Lock()
        self.guards = {}
        try:
            for action, role in (("create", "repository-maintainer"), ("modify", "security-reviewer")):
                self.guards[action] = Guard.local(
                    authority="repository-mixed@3.0.0",
                    authority_resolver=fixture_resolver(publication),
                    repository_root=root, workspace=evidence / action,
                    actor_identity={"id": "codex-54-" + action, "type": "agent", "role": role},
                )
                self.guards[action].boundary_for()  # Validate activation before advertising health.
        except BaseException:
            self.close()
            raise

    def close(self):
        for guard in self.guards.values():
            guard.close()

    def status(self):
        with self.lock:
            policies = {}
            for action, guard in self.guards.items():
                loaded = guard.boundary_for().loaded_authority
                policies[action] = {
                    "authority": loaded.authority_ref,
                    "publication_id": loaded.publication_id,
                    "contract_hash": loaded.contract_hash,
                    "bundle_hash": loaded.bundle_hash,
                    "actor_identity": guard.actor_identity,
                }
            return {"connection": "responding", "observed_at": datetime.now(timezone.utc).isoformat(),
                    "workspace_enforcement": "not_established",
                    "scope": "local fixture approval; no Cloud connection; no permanent health claim",
                    "writer_pid": os.getpid(), "policies": policies}

    def write(self, request: dict):
        # No identity, authority, root, callback, command or operation alias from the model.
        if (not isinstance(request, dict) or set(request) != {"action", "path", "content"}
                or any(not isinstance(value, str) for value in request.values())
                or request["action"] not in self.guards
                or len(request["content"].encode("utf-8")) > 65536):
            return {"connection": "responding", "outcome": "invalid_request",
                    "reason": "Use only action=create|modify, path and UTF-8 content (maximum 64 KiB).",
                    "mutation_status": "not_performed", "automatic_retry": False}
        action = request["action"]
        with self.lock:
            guard = self.guards[action]
            content = request["content"].encode("utf-8")
            normalized = {"schema_version": "normalized_execution_request.v1",
                          "request_id": "codex-" + uuid4().hex,
                          "action": action, "target": request["path"], "arguments": {}, "artifacts": []}
            try:
                result = guard.boundary_for().execute_repository(
                    lambda target: (target.create_bytes(content) if action == "create"
                                    else target.write_bytes(content)),
                    execution_request=normalized, operation=action, raise_on_block=False)
                evaluation = result["evaluation"]
                outcome = "executed" if result["executed"] else "blocked"
                reason = evaluation.get("enforcement_outcome", evaluation.get("status"))
            except Exception as exc:
                evaluation = getattr(exc, "evaluation", {})
                outcome, reason = "failed", type(exc).__name__
            attestation = evaluation.get("execution_attestation")
            return {"connection": "responding", "outcome": outcome, "reason": reason,
                    "request_id": normalized["request_id"], "run_id": evaluation.get("run_id"),
                    "mutation_status": (attestation or {}).get("mutation_status", "unknown"),
                    "execution_attestation": attestation,
                    "evidence_store": str(guard.workspace), "evidence_transport": "local_only",
                    "automatic_retry": False}


def main():
    from mcp.server.mcpserver import MCPServer

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--publication", type=Path, required=True)
    args = parser.parse_args()
    writer = Writer(args.root.resolve(), args.evidence.resolve(), args.publication.resolve())
    # Fixed executable/arguments, no workspace import or execution in the writer.
    if os.name == "nt":
        import ctypes
        sentinel = ctypes.create_string_buffer(b"issue54-NONSECRET-memory-probe")
        (args.evidence / "process-probe.json").write_text(json.dumps({
            "pid": os.getpid(), "sentinel_address": ctypes.addressof(sentinel),
            "sentinel_size": ctypes.sizeof(sentinel),
        }))
        identity = subprocess.check_output(
            [str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"), "/all"],
            text=True, close_fds=True)
        (args.evidence / "writer-token.txt").write_text(identity)
    server = MCPServer("waveframe-proof", instructions=(
        "Call connection_status for the currently loaded fixture authority and operation identities. "
        "Use repository_write for create/modify. A failed or lost response must not be retried: "
        "inspect bytes and saved evidence with the operator. This is a local proof, not Cloud."))

    @server.tool()
    def connection_status() -> dict:
        """Observe current writer availability and actually loaded fixture authority."""
        return writer.status()

    @server.tool()
    def repository_write(request: dict) -> dict:
        """Create or modify via Guard. Request has exactly action, path, content; no role/authority."""
        return writer.write(request)

    try:
        server.run(transport="stdio")
    finally:
        writer.close()


if __name__ == "__main__":
    main()

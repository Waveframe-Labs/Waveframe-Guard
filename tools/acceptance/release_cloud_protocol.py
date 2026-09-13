"""Sanitized real HTTP client contract evidence, not production Cloud acceptance."""
import argparse
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
from threading import Thread

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.acceptance.action_policy_creation import resolver, FIXTURES, provenance
from guard.runtime.identity import stable_hash
from waveframe_guard import Guard


def run():
    assert all(name not in os.environ for name in ("WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"))
    source = resolver("create-only", FIXTURES.parent / "action_policy_release_v4")
    entry = next(iter(source.entries.values()))
    registry = {key: getattr(entry, key) for key in (
        "authority_ref", "contract_id", "contract_version", "contract_hash", "publication_id",
        "bundle_ref", "bundle_hash", "receipt_ref", "receipt_hash", "lifecycle_state", "published_at", "published_by")}
    publication = {"schema_version": "cloud_authority_publication.v1", "organization_id": "example-org",
        "authority_ref": entry.authority_ref, "registry_entry": registry,
        "authority_bundle": json.loads(entry.bundle_path.read_text()),
        "publication_receipt": json.loads(entry.receipt_path.read_text()), "registry_entry_hash": stable_hash(registry)}
    publication["envelope_hash"] = stable_hash(publication)
    exchanges = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def respond(self, response, body=None):
            assert self.headers["X-Organization-ID"] == "example-org"
            exchanges.append({"method": self.command, "path": self.path, "request": body,
                              "status": 200, "response": deepcopy(response)})
            raw = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def do_GET(self): self.respond(publication)
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.respond({"package_id": "example-package", "receipt_id": "example-cloud-receipt",
                          "sha256": "example-hash", "timestamp": "example-time"}, body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "generated").mkdir()
            instance = Guard.cloud(authority=entry.authority_ref, repository_root=root, workspace=root / "evidence",
                cloud_url=f"http://127.0.0.1:{server.server_port}", cloud_organization_id="example-org",
                runtime_id="example-runtime", runtime_credential="disposable-example-only",
                actor_identity={"id": "example-actor", "type": "agent", "role": "repository-maintainer"})
            try:
                @instance.repository_tool(action="create", target="path", return_result=True)
                def create(path): return path.create_bytes(b"")
                result = create("generated/empty.md")
                saved = instance.store.load_run(result["evaluation"]["run_id"])
                proof = instance.store.load_execution_attestation(saved["run_id"])
                assert instance.store.replay(saved["run_id"])["matches"]
                assert proof["repository_operation"]["created"]
                assert (root / "generated/empty.md").read_bytes() == b""
                reports = [x["request"] for x in exchanges if x["path"].endswith("/attestations")]
                assert len(reports) == 1 and reports[0]["mutation_executed"] is True
                assert reports[0]["execution_status"] == "succeeded"
                assert len([x for x in exchanges if x["path"].endswith("/preserve")]) == 1
                assert saved["inputs"]["authority_publication"] == {
                    "bundle": publication["authority_bundle"], "receipt": publication["publication_receipt"]}
                evidence = {"scope": "client HTTP contract only; example server acknowledgments",
                    "dependencies": provenance(), "exchanges": exchanges, "saved_run": saved,
                    "execution_attestation": proof}
                assert "disposable-example-only" not in json.dumps(evidence)
                return evidence
            finally:
                instance.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(run(), indent=2) + "\n", encoding="utf-8")

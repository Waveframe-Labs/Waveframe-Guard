"""Installed public SDK, unchanged Cloud HTTP server, automatically submitted evidence."""
import argparse
from copy import deepcopy
import hashlib
from importlib.metadata import distribution
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from unittest.mock import patch
from urllib.parse import urlsplit

import requests
from waveframe_guard import Guard, RepositoryBoundaryError
from waveframe_guard.authority.runtime_facts import RuntimeFactError
import waveframe_guard


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert Path(waveframe_guard.__file__).is_relative_to(Path(sys.prefix)), waveframe_guard.__file__
    server = json.loads(args.server.read_text())
    origin = server["url"]
    dependencies = {}
    for name, commit in (("cricore-contract-compiler", "ae590dee058d3481e384dea850d5b7d980f533ff"),
                         ("governance-ledger", "40e0875ee9a973254bb3a4d0c228cad4fdce2bc0")):
        direct = json.loads(distribution(name).read_text("direct_url.json"))
        assert direct["vcs_info"] == {"vcs": "git", "requested_revision": commit, "commit_id": commit}
        dependencies[name] = direct
    for line in (args.fixtures / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((args.fixtures / name).read_bytes()).hexdigest() == digest
    exchanges, outcomes = [], {}
    original_send = requests.Session.send
    def capture(session, request, **kwargs):
        response = original_send(session, request, **kwargs)
        url = urlsplit(request.url)
        if request.url.startswith(origin):
            exchange = {"method": request.method, "path": url.path + ("?" + url.query if url.query else ""),
                "request": json.loads(request.body) if request.body else None,
                "status": response.status_code}
            exchanges.append(exchange)
            if kwargs.get("stream"):
                # Observe bytes as Guard reads them; never drain its strict,
                # bounded streaming publication transport ahead of the SDK.
                chunks = bytearray()
                original_read = response.raw.read
                def read(*args, **options):
                    data = original_read(*args, **options)
                    chunks.extend(data)
                    if not data:
                        exchange["response"] = json.loads(chunks)
                    return data
                response.raw.read = read
            else:
                exchange["response"] = response.json()
        return response
    headers = {"X-API-Key": os.environ["GUARD46_KEY_OPERATOR"], "X-Organization-ID": "guard46"}
    def http(method, path, body=None, expected=200, selected_headers=None):
        response = requests.request(method, origin + path, json=body, headers=selected_headers or headers, timeout=20,
                                    allow_redirects=False)
        assert response.status_code == expected, (path, response.status_code, response.text[:600])
        return response.json()

    # Faults below occur inside a real mediated callback. No successful request
    # or report is constructed by this harness; Session.send only records bytes.
    cases = [
        ("created", "create-only", "repository-maintainer", "create", "generated/new.md", "succeeded", True, 1),
        ("empty", "create-only", "repository-maintainer", "create", "generated/new.md", "succeeded", True, 1),
        ("denied-role", "create-only", "security-reviewer", "create", "generated/new.md", "blocked", False, 0),
        ("denied-path", "create-only", "repository-maintainer", "create", "generated/private/new.md", "blocked", False, 0),
        ("default-deny", "create-only", "repository-maintainer", "create", "other.md", "blocked", False, 0),
        ("collision", "create-only", "repository-maintainer", "create", "generated/new.md", "failed", False, 1),
        ("partial", "create-only", "repository-maintainer", "create", "generated/new.md", "failed", True, 1),
        ("unknown", "create-only", "repository-maintainer", "create", "generated/new.md", "failed", None, 1),
        ("returned-summary", "create-only", "repository-maintainer", "create", "generated/new.md", "failed", None, 1),
        ("post-validation", "create-only", "repository-maintainer", "create", "generated/new.md", "failed", True, 1),
        ("pre-callback", "create-only", "repository-maintainer", "create", "generated/missing/new.md", "not_executed", False, 0),
        ("create-only-no-modify", "create-only", "repository-maintainer", "modify", "README.md", "blocked", False, 0),
        ("modify-only-no-create", "modify-only", "repository-maintainer", "create", "generated/new.md", "blocked", False, 0),
        ("modified", "modify-only", "repository-reviewer", "modify", "docs/guide.md", "succeeded", True, 1),
        ("modify-denied-path", "modify-only", "repository-reviewer", "modify", "docs/locked.md", "blocked", False, 0),
        ("modify-denied-role", "modify-only", "security-reviewer", "modify", "docs/guide.md", "blocked", False, 0),
        ("mixed-created", "mixed", "repository-maintainer", "create", "generated/new.md", "succeeded", True, 1),
        ("mixed-modified", "mixed", "security-reviewer", "modify", "README.md", "succeeded", True, 1),
        ("mixed-create-role", "mixed", "security-reviewer", "create", "generated/new.md", "blocked", False, 0),
        ("mixed-modify-role", "mixed", "repository-maintainer", "modify", "README.md", "blocked", False, 0),
        ("no-report", "create-only", "repository-maintainer", "create", "generated/new.md", None, None, 0),
    ]
    with patch.object(requests.Session, "send", capture), tempfile.TemporaryDirectory(prefix="guard46-workspaces-") as temp:
        for kind in ("create-only", "modify-only", "mixed"):
            http("POST", "/v1/authorities", {
                "authority_bundle": json.loads((args.fixtures / kind / "authority-bundle.json").read_text()),
                "publication_receipt": json.loads((args.fixtures / kind / "publication-receipt.json").read_text()),
            }, expected=201)
        legacy = json.loads((args.fixtures.parent / "cloud_authority_publication.v1.json").read_text())
        http("POST", "/v1/authorities", {"authority_bundle": legacy["authority_bundle"],
             "publication_receipt": legacy["publication_receipt"]}, expected=201)
        for name, kind, role, action, target, status, mutation, expected_callbacks in cases:
            root = Path(temp) / name
            (root / "generated").mkdir(parents=True)
            (root / "README.md").write_bytes(b"original")
            (root / "docs").mkdir()
            (root / "docs/guide.md").write_bytes(b"original")
            (root / "docs/locked.md").write_bytes(b"original")
            callbacks = []
            instance = Guard.cloud(authority=f"repository-{kind}@2.0.0", repository_root=root,
                workspace=root / "evidence", cloud_url=origin, cloud_organization_id="guard46",
                runtime_credential=os.environ["GUARD46_KEY_RUNTIME"], runtime_id="assigned-runtime",
                actor_identity={"id": "acceptance-agent", "type": "agent", "role": role},
                execution_context={"surface": "installed-sdk-acceptance", "case": name})
            try:
                assert instance.runtime_connection.ok, instance.runtime_connection
                @instance.repository_tool(action=action, target="path", return_result=True, raise_on_block=False)
                def mutate(path):
                    callbacks.append(1)
                    if name == "collision": (root / target).write_bytes(b"competitor")
                    if name == "unknown": raise RuntimeError("injected unknown operation failure")
                    if name == "returned-summary": return {"created": True}
                    if action == "create":
                        value = path.create_bytes(b"" if name == "empty" else b"created")
                    else:
                        value = path.write_bytes(b"modified")
                    if name == "partial": raise RuntimeError("injected failure after creation")
                    if name == "post-validation":
                        def fail(): raise RepositoryBoundaryError("injected post-callback validation failure")
                        path._validate = fail
                    return value
                if name == "no-report":
                    evaluation = instance.boundary_for().evaluate({"schema_version": "normalized_execution_request.v1",
                        "request_id": name, "action": action, "target": target, "arguments": {}, "artifacts": []})
                else:
                    try:
                        evaluation = mutate(target)["evaluation"]
                    except (RuntimeError, RepositoryBoundaryError) as exc:
                        evaluation = exc.evaluation
                assert len(callbacks) == expected_callbacks, name
                assert evaluation["cloud_preservation"]["ok"], (name, evaluation["cloud_preservation"])
                event_id = evaluation["run_id"]
                submissions = [x for x in exchanges if x["path"] == "/v1/preserve" and x["request"]["run_id"] == event_id]
                assert len(submissions) == 1
                submitted = deepcopy(submissions[0]["request"])
                reopened = http("GET", "/v1/package/" + evaluation["cloud_preservation"]["package_id"])
                assert reopened["evidence"] == submitted
                assert reopened["authority_bundle"] == submitted["saved_evaluation"]["inputs"]["authority_publication"]["bundle"]
                saved_context = submitted["saved_evaluation"]["inputs"]["runtime_evidence"]["execution_context"]
                assert saved_context["runtime_id"] == "assigned-runtime" and saved_context["organization_id"] == "guard46"
                assert saved_context["case"] == name
                assert instance.store.replay(event_id)["matches"]
                event = http("GET", "/v1/audit-events?event_id=" + event_id)["events"][0]
                reports = [x for x in exchanges if x["path"] == "/v1/runtime/attestations" and x["request"]["event_id"] == event_id]
                if status is None:
                    assert reports == [] and "execution_attestation" not in event
                else:
                    assert evaluation["cloud_runtime_attestation"]["ok"], (name, evaluation["cloud_runtime_attestation"])
                    assert len(reports) == 1 and reports[0]["status"] == 201
                    report = reports[0]["request"]
                    assert report["execution_status"] == status and report.get("mutation_executed") is mutation
                    assert report["runtime_id"] == saved_context["runtime_id"]
                    assert report["authority_ref"] == submitted["receipt"]["authority_ref"]
                    assert report["compiled_contract_hash"] == submitted["receipt"]["contract_hash"]
                    assert reports[0]["response"]["consistency_state"] == "consistent"
                    assert event["execution_status"] == status and event.get("mutation_occurred") is mutation
                if expected_callbacks == 0 and action == "create": assert not (root / target).exists()
                if name == "collision": assert (root / target).read_bytes() == b"competitor"
                if name in {"created", "empty", "partial", "post-validation"}:
                    assert (root / target).read_bytes() == (b"" if name == "empty" else b"created")
                local = instance.store.load_execution_attestation(event_id)
                if name in {"collision", "partial", "post-validation"}: assert local["mutation_executed"] is None
                write_json(args.output / "local" / (name + ".json"), local)
                outcomes[name] = {"run_id": event_id, "callback_count": len(callbacks), "decision": event["decision"],
                    "preserve_status": submissions[0]["status"], "retrieve_status": 200,
                    "report_status": reports[0]["status"] if reports else None,
                    "execution_status": status, "mutation_executed": mutation, "exact_package_roundtrip": True}
            finally:
                instance.close()
        assert not any(x["method"] == "POST" and x["path"] == "/v1/audit-events" for x in exchanges)
        # Authentication rejections only: these never manufacture a successful report.
        http("GET", "/v1/package/" + evaluation["cloud_preservation"]["package_id"], expected=403,
             selected_headers={**headers, "X-Organization-ID": "wrong-tenant"})
        # Cloud binds preservation/report credentials to the saved runtime.
        # Exercise that rejection through actual SDK automatic uploads too.
        root = Path(temp) / "wrong-runtime"
        (root / "generated").mkdir(parents=True)
        instance = Guard.cloud(authority="repository-create-only@2.0.0", repository_root=root,
            workspace=root / "evidence", cloud_url=origin, cloud_organization_id="guard46",
            runtime_credential=os.environ["GUARD46_KEY_WRONG_RUNTIME"], runtime_id="assigned-runtime",
            actor_identity={"id": "agent", "type": "agent", "role": "repository-maintainer"})
        try:
            attempts = []
            @instance.repository_tool(action="create", target="path", return_result=True)
            def create_wrong_runtime(path):
                attempts.append(1)
                return path.create_bytes(b"once")
            result = create_wrong_runtime("generated/new.md")
            assert attempts == [1] and (root / "generated/new.md").read_bytes() == b"once"
            assert result["evaluation"]["status"] == "admissible"
            for key in ("cloud_preservation", "cloud_runtime_attestation"):
                assert not result[key]["ok"] and result[key]["status_code"] == 403, result[key]
            assert not instance.store.load_run(result["evaluation"]["run_id"]).get("cloud_preservation")
            outcomes["wrong-runtime"] = {"run_id": result["evaluation"]["run_id"], "callback_count": 1,
                "decision": "ALLOWED", "preserve_status": 403, "report_status": 403, "preserved": False}
        finally:
            instance.close()
        root = Path(temp) / "legacy"
        root.mkdir()
        instance = Guard.cloud(authority=legacy["authority_ref"], repository_root=root, workspace=root / "evidence",
            cloud_url=origin, cloud_organization_id="guard46", runtime_credential=os.environ["GUARD46_KEY_RUNTIME"],
            runtime_id="assigned-runtime", actor_identity={"id": "agent", "type": "agent", "role": "repository-maintainer"})
        try:
            attempts = []
            @instance.repository_tool(action="create", target="path", return_result=True, raise_on_block=False)
            def legacy_create(path):
                attempts.append(1)
                return path.create_bytes(b"forbidden")
            before = len(exchanges)
            try:
                legacy_create("README.md")
            except RuntimeFactError:
                pass  # The released fact schema cannot express creation.
            else:
                raise AssertionError("released authority admitted a create request")
            assert attempts == [] and not (root / "README.md").exists()
            assert len(exchanges) == before and instance.store.history() == []
            outcomes["legacy-cannot-create"] = {"callback_count": 0, "decision": "not_evaluated",
                "authorization_event": False, "report_status": None, "mutation_executed": False}
        finally:
            instance.close()
    evidence = {"platform": platform.platform(), "python": sys.version, "server": {k: v for k, v in server.items() if k != "url"},
                "dependencies": dependencies, "guard_pep610": json.loads(distribution("waveframe-guard").read_text("direct_url.json")),
                "outcomes": outcomes}
    for secret in (os.environ["GUARD46_KEY_" + x] for x in ("OPERATOR", "RUNTIME", "WRONG_RUNTIME")):
        assert secret not in json.dumps(exchanges)
    write_json(args.output / "http.json", exchanges)
    write_json(args.output / "summary.json", evidence)
    print(json.dumps(outcomes, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import email
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_WHEEL_FILES = {
    "guard/sdk/repository_boundary.py",
    "guard/sdk/__init__.py",
    "guard/sdk/guard.py",
    "guard/sdk/local_persistence.py",
    "waveframe_guard/__init__.py",
    "waveframe_guard/authority/runtime_facts.py",
    "waveframe_guard/cloud/publication.py",
    "waveframe_guard/schemas.py",
}
REQUIRED_SDIST_FILES = {
    "guard/sdk/repository_boundary.py",
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "guard/sdk/__init__.py",
    "guard/sdk/local_persistence.py",
    "pyproject.toml",
    "waveframe_guard/__init__.py",
    "waveframe_guard/authority/runtime_facts.py",
    "waveframe_guard/cloud/publication.py",
    "waveframe_guard/schemas.py",
}
EXPECTED_RUNTIME_REQUIREMENTS = {
    "cricore",
    "cricore-proposal-normalizer",
    "governance-ledger>=0.7.0,<0.9.0",
    "requests",
}
FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".guard-local",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "examples",
    "temp",
    "tools",
    "venv",
}
FORBIDDEN_NAMES = {".env", ".pypirc", ".DS_Store", "Thumbs.db"}
FORBIDDEN_SUFFIXES = {".bak", ".log", ".orig", ".pyc", ".pyo", ".rej", ".swp", ".tmp"}
SECRET_PATTERNS = {
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "GitHub token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{80,})"),
    "OpenAI-style secret": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Guard wheel/sdist contents and a clean installed-wheel enforcement smoke test."
    )
    parser.add_argument("--dist-dir", type=Path, required=True)
    args = parser.parse_args()

    dist_dir = args.dist_dir.resolve()
    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(
            f"Expected exactly one wheel and one .tar.gz sdist in {dist_dir}; "
            f"found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)."
        )

    wheel, sdist = wheels[0], sdists[0]
    _run([sys.executable, "-m", "twine", "check", str(wheel), str(sdist)])

    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    expected_version = project["version"]
    wheel_count = _inspect_wheel(wheel, expected_version)
    sdist_count = _inspect_sdist(sdist, expected_version)
    _clean_wheel_smoke(wheel, expected_version)

    print(
        "Package acceptance passed: "
        f"wheel={wheel.name} ({wheel_count} files), "
        f"sdist={sdist.name} ({sdist_count} files), version={expected_version}; "
        "Twine, metadata, contents, clean install, allowed/blocked boundary, and pip check succeeded."
    )
    return 0


def _inspect_wheel(wheel: Path, expected_version: str) -> int:
    with zipfile.ZipFile(wheel) as archive:
        names = [PurePosixPath(name) for name in archive.namelist() if not name.endswith("/")]
        name_set = {name.as_posix() for name in names}
        missing = REQUIRED_WHEEL_FILES - name_set
        if missing:
            raise AssertionError(f"wheel is missing required public files: {sorted(missing)}")
        metadata_names = [name for name in names if name.name == "METADATA" and name.parent.name.endswith(".dist-info")]
        license_names = [name for name in names if name.name == "LICENSE" and ".dist-info" in name.as_posix()]
        if len(metadata_names) != 1 or not license_names:
            raise AssertionError("wheel must contain one METADATA file and the packaged LICENSE")
        metadata = email.message_from_bytes(archive.read(metadata_names[0].as_posix()))
        _validate_metadata(metadata, expected_version, "wheel")
        _validate_archive_members(names, "wheel")
        _validate_archive_secrets(
            ((name, archive.read(name.as_posix())) for name in names),
            "wheel",
        )
        allowed_roots = {"guard", "waveframe_guard"}
        unrelated = [
            name.as_posix()
            for name in names
            if name.parts[0] not in allowed_roots and not name.parts[0].endswith(".dist-info")
        ]
        if unrelated:
            raise AssertionError(f"wheel contains unrelated top-level files: {unrelated}")
        return len(names)


def _inspect_sdist(sdist: Path, expected_version: str) -> int:
    expected_root = f"waveframe_guard-{expected_version}"
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        names = [PurePosixPath(member.name) for member in members]
        roots = {name.parts[0] for name in names if name.parts}
        if roots != {expected_root}:
            raise AssertionError(f"sdist root must be {expected_root!r}; found {sorted(roots)}")
        relative_names = [PurePosixPath(*name.parts[1:]) for name in names]
        relative_set = {name.as_posix() for name in relative_names}
        missing = REQUIRED_SDIST_FILES - relative_set
        if missing:
            raise AssertionError(f"sdist is missing required public files: {sorted(missing)}")
        pkg_info = next(member for member in members if PurePosixPath(member.name).parts[1:] == ("PKG-INFO",))
        extracted = archive.extractfile(pkg_info)
        if extracted is None:
            raise AssertionError("could not read sdist PKG-INFO")
        _validate_metadata(email.message_from_bytes(extracted.read()), expected_version, "sdist")
        _validate_archive_members(relative_names, "sdist")

        def contents():
            for member, relative_name in zip(members, relative_names):
                extracted_member = archive.extractfile(member)
                if extracted_member is not None:
                    yield relative_name, extracted_member.read()

        _validate_archive_secrets(contents(), "sdist")
        return len(names)


def _validate_metadata(metadata: email.message.Message, expected_version: str, label: str) -> None:
    if metadata.get("Name") != "waveframe-guard":
        raise AssertionError(f"{label} metadata Name is {metadata.get('Name')!r}")
    if metadata.get("Version") != expected_version:
        raise AssertionError(
            f"{label} metadata Version is {metadata.get('Version')!r}; expected {expected_version!r}"
        )
    if metadata.get("Requires-Python") != ">=3.10":
        raise AssertionError(f"{label} metadata must report Requires-Python: >=3.10")
    requirements = metadata.get_all("Requires-Dist", [])
    runtime_requirements = [
        _normalize_requirement(requirement)
        for requirement in requirements
        if "extra ==" not in requirement
    ]
    expected_runtime = {_normalize_requirement(item) for item in EXPECTED_RUNTIME_REQUIREMENTS}
    if len(runtime_requirements) != len(set(runtime_requirements)):
        raise AssertionError(f"{label} contains duplicate runtime dependency metadata")
    if set(runtime_requirements) != expected_runtime:
        raise AssertionError(
            f"{label} runtime dependency metadata differs: "
            f"expected {sorted(expected_runtime)}, found {sorted(set(runtime_requirements))}"
        )


def _normalize_requirement(requirement: str) -> str:
    compact = requirement.replace(" ", "")
    if ";" in compact:
        raise AssertionError(f"runtime dependency markers are not approved: {requirement!r}")
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(\[[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*\])?(.*)", compact)
    if match is None:
        raise AssertionError(f"unsupported dependency metadata: {requirement!r}")
    name = match.group(1).lower().replace("_", "-")
    extras = (match.group(2) or "").lower().replace("_", "-")
    specifiers = ",".join(sorted(filter(None, match.group(3).split(","))))
    return f"{name}{extras}{specifiers}"


def _validate_archive_members(names: list[PurePosixPath], label: str) -> None:
    violations: list[str] = []
    lowered_forbidden = {part.lower() for part in FORBIDDEN_PARTS}
    for name in names:
        if name.is_absolute() or ".." in name.parts:
            violations.append(f"unsafe path {name}")
            continue
        if {part.lower() for part in name.parts} & lowered_forbidden:
            violations.append(name.as_posix())
        if name.name in FORBIDDEN_NAMES or name.suffix.lower() in FORBIDDEN_SUFFIXES:
            violations.append(name.as_posix())
    if violations:
        raise AssertionError(f"{label} contains forbidden private/cache/credential paths: {violations}")


def _validate_archive_secrets(contents, label: str) -> None:
    findings: list[str] = []
    for name, content in contents:
        if b"\0" in content:
            continue
        for secret_label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                findings.append(f"{name}: possible {secret_label}")
    if findings:
        raise AssertionError(f"{label} contains possible credentials: {findings}")


def _clean_wheel_smoke(wheel: Path, expected_version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="waveframe-guard-package-acceptance-") as raw_temp:
        temp_root = Path(raw_temp)
        venv_dir = temp_root / "venv"
        smoke_dir = temp_root / "outside-repository"
        smoke_dir.mkdir()
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = _venv_python(venv_dir)
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--index-url",
                "https://pypi.org/simple",
                "pip==26.1.1",
            ],
            cwd=smoke_dir,
        )
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--index-url",
                "https://pypi.org/simple",
                str(wheel),
            ],
            cwd=smoke_dir,
        )
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["GUARD_EXPECTED_VERSION"] = expected_version
        environment["GUARD_REPOSITORY_ROOT"] = str(REPO_ROOT)
        _run([str(python), "-c", SMOKE_SCRIPT], cwd=smoke_dir, env=environment)
        _run([str(python), "-c", CLOUD_V2_SMOKE_SCRIPT], cwd=smoke_dir, env=environment)
        _run([str(python), "-m", "pip", "check"], cwd=smoke_dir, env=environment)


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    print(f"+ {' '.join(command)}")
    subprocess.run(command, cwd=cwd, env=env, check=True)


SMOKE_SCRIPT = r'''
import os
from importlib.metadata import version
from pathlib import Path

import waveframe_guard
from guard.sdk import GuardExecutionBlocked
from waveframe_guard import Guard

expected_version = os.environ["GUARD_EXPECTED_VERSION"]
repository_root = Path(os.environ["GUARD_REPOSITORY_ROOT"]).resolve()
module_path = Path(waveframe_guard.__file__).resolve()
assert repository_root not in module_path.parents, module_path
assert any(part in {"site-packages", "dist-packages"} for part in module_path.parts), module_path
assert waveframe_guard.__version__ == expected_version
assert version("waveframe-guard") == expected_version

authority = {
    "schema_version": "compiled_authority_contract.v1",
    "contract_id": "repository",
    "contract_version": "1.0.0",
    "contract_hash": "sha256:package-acceptance",
    "authority_requirements": {},
    "approval_requirements": {},
    "artifact_requirements": {},
    "stage_requirements": {},
    "invariants": {},
    "target_requirements": {
        "allow": [{"match": "exact", "value": "README.md"}],
        "deny": [{"match": "prefix", "value": "deployment/"}],
    },
}
calls = []
guard = Guard.local(
    workspace=Path.cwd() / "guard-state", target_domain="literal",
    authorities={"repository@1.0.0": authority},
    actor_identity={"id": "ci-agent", "type": "agent", "role": "maintainer"},
    evaluation_time_source=lambda: "2026-09-01T00:00:00+00:00",
)

@guard.tool(authority="repository@1.0.0", target="path")
def write_file(path):
    calls.append(path)
    return path

assert write_file("README.md") == "README.md"
try:
    write_file("deployment/production.yml")
except GuardExecutionBlocked:
    pass
else:
    raise AssertionError("blocked package smoke callback unexpectedly executed")
assert calls == ["README.md"], calls
print(f"Clean wheel smoke passed from {module_path}: allowed=1 blocked=1 callbacks=1")
'''


CLOUD_V2_SMOKE_SCRIPT = r'''
import hashlib
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import waveframe_guard
from governance_ledger import (
    apply_policy_mapping_decision,
    finalize_domain_policy_authority,
    interpret_policy_with_domain_pack,
)
from guard.sdk import Guard, GuardExecutionBlocked


repository_root = Path(os.environ["GUARD_REPOSITORY_ROOT"]).resolve()
module_path = Path(waveframe_guard.__file__).resolve()
assert repository_root not in module_path.parents, module_path


def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


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
registry_entry = {
    "authority_ref": "repository-authority@1.0.0",
    "contract_id": "repository-authority",
    "contract_version": "1.0.0",
    "contract_hash": publication["compiled_authority_contract"]["contract_hash"],
    "publication_id": publication["publication_receipt"]["publication_id"],
    "bundle_ref": "publications/repository-authority/1.0.0/authority-bundle.json",
    "bundle_hash": publication["authority_bundle"]["bundle_hash"],
    "receipt_ref": "publications/repository-authority/1.0.0/publication-receipt.json",
    "receipt_hash": publication["publication_receipt"]["receipt_hash"],
    "lifecycle_state": "active",
    "published_at": publication["publication_receipt"]["published_at"],
    "published_by": publication["publication_receipt"]["published_by"],
}
envelope = {
    "schema_version": "cloud_authority_publication.v1",
    "organization_id": "example-organization",
    "authority_ref": "repository-authority@1.0.0",
    "registry_entry": registry_entry,
    "registry_entry_hash": canonical_hash(registry_entry),
    "authority_bundle": publication["authority_bundle"],
    "publication_receipt": publication["publication_receipt"],
}
envelope["envelope_hash"] = canonical_hash(envelope)
state = {"publication_gets": 0}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.path == "/v1/authorities/repository-authority%401.0.0/publication"
        assert self.headers["X-Organization-ID"] == "example-organization"
        assert self.headers["X-API-Key"] == "clean-wheel-runtime-credential"
        state["publication_gets"] += 1
        body = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length:
            self.rfile.read(length)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    guard = Guard.cloud(
        cloud_url=f"http://127.0.0.1:{server.server_port}",
        runtime_credential="clean-wheel-runtime-credential",
        cloud_organization_id="example-organization",
        authority="repository-authority@1.0.0",
        runtime_id="clean-wheel-runtime",
        actor_identity={"id": "repo-agent", "type": "agent", "role": "repository-maintainer"},
        workspace=Path.cwd() / "cloud-v2-state",
        repository_root=Path.cwd(),
    )
    guard.cloud_preservation_client = None
    guard.cloud_runtime_client = None
    callbacks = []

    Path("README.md").write_bytes(b"original")

    @guard.repository_tool(action="modify", target="path", return_result=True)
    def write_file(path):
        callbacks.append(path.relative_path)
        path.write_bytes(b"updated")
        return path.relative_path

    if os.name == "nt":
        allowed = write_file("README.md")
    else:
        from guard.sdk import RepositoryBoundaryError
        try:
            write_file("README.md")
        except RepositoryBoundaryError as exc:
            assert "unsupported on POSIX" in str(exc)
        else:
            raise AssertionError("unsupported POSIX mutation ran")
        allowed = {"executed": False}
        assert guard.boundary_for().evaluate({
            "schema_version": "normalized_execution_request.v1", "request_id": "wheel-eval",
            "action": "modify", "target": "README.md", "arguments": {}, "artifacts": [],
        }, save=False)["status"] == "admissible"
    try:
        write_file("deployment/production.yml")
    except GuardExecutionBlocked as blocked:
        assert blocked.evaluation["execution_attestation"]["callback_invoked"] is False
    else:
        raise AssertionError("deployment proposal was not blocked")
finally:
    server.shutdown()
    server.server_close()

assert allowed["executed"] is (os.name == "nt")
assert callbacks == (["README.md"] if os.name == "nt" else [])
assert state["publication_gets"] == 1
assert guard.authority_bindings["repository-authority@1.0.0"].schema_version == "authority_bundle.v2"
print(
    f"Clean wheel Cloud v2 passed from {module_path}: "
    f"allowed=README.md blocked=deployment/production.yml callbacks={len(callbacks)} "
    "manual_facts=0 caller_ledger_validators=0 publication_gets=1 repository_imports=0"
)
'''


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(REPO_ROOT))

from tools.license_contract import validate_document, validate_notices
from tools.mediation_contract import PACKAGED_DOCS, validate_claims, validate_mediation_document

FORBIDDEN_PARTS = {
    ".guard-local",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "temp",
    "venv",
}
FORBIDDEN_NAMES = {".env", ".pypirc", ".DS_Store", "Thumbs.db"}
FORBIDDEN_SUFFIXES = {".bak", ".log", ".orig", ".pyc", ".pyo", ".rej", ".swp", ".tmp"}
REQUIRED_FILES = {
    "CHANGELOG.md",
    "CITATION.cff",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "docs/getting-started/README.md",
    "docs/governance/GUARD_SEMANTICS_FREEZE.md",
    "pyproject.toml",
    "waveframe_guard/schemas.py",
}
APPROVED_JSON_FILES = {
    "contracts/finance-core-0.3.1.contract.json",
    "contracts/finance-policy-1.0.0.authority-bundle.json",
    "contracts/finance-policy-1.0.0.contract.json",
    "contracts/index.json",
    "examples/sdk/finance-policy.json",
    "tests/fixtures/cloud_authority_publication.v1.json",
}
APPROVED_JSON_FILES.update(
    f"tests/fixtures/action_policy_v4/{kind}/{artifact}.json"
    for kind in ("create-only", "modify-only", "mixed")
    for artifact in ("approval", "authority-bundle", "compiled-authority", "compiler-input",
                     "compiler-output", "confirmation", "constraint-ir", "proposal",
                     "publication-receipt", "review", "source-interpretation")
)
APPROVED_JSON_FILES.update(['tests/fixtures/action_policy_release_v4/catalog.json', 'tests/fixtures/action_policy_release_v4/create-only/approval.json', 'tests/fixtures/action_policy_release_v4/create-only/authority-bundle.json', 'tests/fixtures/action_policy_release_v4/create-only/compiled-authority.json', 'tests/fixtures/action_policy_release_v4/create-only/compiler-input.json', 'tests/fixtures/action_policy_release_v4/create-only/compiler-output.json', 'tests/fixtures/action_policy_release_v4/create-only/confirmation.json', 'tests/fixtures/action_policy_release_v4/create-only/constraint-ir.json', 'tests/fixtures/action_policy_release_v4/create-only/proposal.json', 'tests/fixtures/action_policy_release_v4/create-only/publication-receipt.json', 'tests/fixtures/action_policy_release_v4/create-only/review.json', 'tests/fixtures/action_policy_release_v4/create-only/source-interpretation.json', 'tests/fixtures/action_policy_release_v4/domain-pack.json', 'tests/fixtures/action_policy_release_v4/mixed/approval.json', 'tests/fixtures/action_policy_release_v4/mixed/authority-bundle.json', 'tests/fixtures/action_policy_release_v4/mixed/compiled-authority.json', 'tests/fixtures/action_policy_release_v4/mixed/compiler-input.json', 'tests/fixtures/action_policy_release_v4/mixed/compiler-output.json', 'tests/fixtures/action_policy_release_v4/mixed/confirmation.json', 'tests/fixtures/action_policy_release_v4/mixed/constraint-ir.json', 'tests/fixtures/action_policy_release_v4/mixed/proposal.json', 'tests/fixtures/action_policy_release_v4/mixed/publication-receipt.json', 'tests/fixtures/action_policy_release_v4/mixed/review.json', 'tests/fixtures/action_policy_release_v4/mixed/source-interpretation.json', 'tests/fixtures/action_policy_release_v4/modify-only/approval.json', 'tests/fixtures/action_policy_release_v4/modify-only/authority-bundle.json', 'tests/fixtures/action_policy_release_v4/modify-only/compiled-authority.json', 'tests/fixtures/action_policy_release_v4/modify-only/compiler-input.json', 'tests/fixtures/action_policy_release_v4/modify-only/compiler-output.json', 'tests/fixtures/action_policy_release_v4/modify-only/confirmation.json', 'tests/fixtures/action_policy_release_v4/modify-only/constraint-ir.json', 'tests/fixtures/action_policy_release_v4/modify-only/proposal.json', 'tests/fixtures/action_policy_release_v4/modify-only/publication-receipt.json', 'tests/fixtures/action_policy_release_v4/modify-only/review.json', 'tests/fixtures/action_policy_release_v4/modify-only/source-interpretation.json', 'tests/fixtures/action_policy_release_v4/runtime-fact-schema.json'])
EXPECTED_PUBLIC_RUNTIME_REQUIREMENTS = {
    "cricore>=0.13.0,<0.15.0",
    "cricore-proposal-normalizer>=0.2.0,<0.3.0",
    "governance-ledger>=0.7.0,<0.9.0",
    "requests>=2.33.0,<3.0.0",
}
PINNED_TEST_DEPENDENCIES = {
    "cricore-contract-compiler>=0.4.0,<0.6.0",
}
SECRET_PATTERNS = {
    "AWS access key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "GitHub token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{80,})"),
    "OpenAI-style secret": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{32,}"),
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate Guard's tracked governance and repository-integrity surface."
    )
    parser.add_argument(
        "--diff-base",
        default="",
        help="Commit to compare with HEAD for git diff --check (defaults to HEAD^).",
    )
    args = parser.parse_args()

    failures: list[str] = []
    tracked = _tracked_files(failures)
    _validate_required_files(tracked, failures)
    _validate_paths(tracked, failures)
    json_count = _validate_json(tracked, failures)
    _validate_secrets(tracked, failures)
    _validate_licensing(tracked, failures)
    _validate_mediation(tracked, failures)
    dependency_count = _validate_metadata(failures)
    _validate_diff(args.diff_base, failures)

    if failures:
        print("Repository integrity validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        "Repository integrity passed: "
        f"{len(tracked)} tracked files, {json_count} JSON files, "
        f"{dependency_count} public runtime dependencies, and no forbidden artifacts or secrets."
    )
    return 0


def _tracked_files(failures: list[str]) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        failures.append(f"git ls-files failed: {result.stderr.decode(errors='replace').strip()}")
        return []
    return [PurePosixPath(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw]


def _validate_required_files(tracked: list[PurePosixPath], failures: list[str]) -> None:
    names = {path.as_posix() for path in tracked}
    for required in sorted(REQUIRED_FILES - names):
        failures.append(f"required public/governance file is not tracked: {required}")


def _validate_paths(tracked: list[PurePosixPath], failures: list[str]) -> None:
    for path in tracked:
        lowered_parts = {part.lower() for part in path.parts}
        if lowered_parts & {part.lower() for part in FORBIDDEN_PARTS}:
            failures.append(f"forbidden private, cache, build, or environment path is tracked: {path}")
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"temporary or credential-related file is tracked: {path}")


def _validate_json(tracked: list[PurePosixPath], failures: list[str]) -> int:
    json_paths = [path for path in tracked if path.suffix.lower() == ".json"]
    _validate_json_contract(json_paths, failures)
    for path in json_paths:
        try:
            json.loads((REPO_ROOT / Path(*path.parts)).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append(f"invalid JSON/schema input {path}: {exc}")
    return len(json_paths)


def _validate_json_contract(json_paths: list[PurePosixPath], failures: list[str]) -> None:
    actual = {path.as_posix() for path in json_paths}
    unexpected = actual - APPROVED_JSON_FILES
    missing = APPROVED_JSON_FILES - actual
    if unexpected:
        failures.append(f"unapproved JSON/schema files are tracked: {sorted(unexpected)}")
    if missing:
        failures.append(f"approved JSON/schema files are missing: {sorted(missing)}")


def _validate_secrets(tracked: list[PurePosixPath], failures: list[str]) -> None:
    for path in tracked:
        full_path = REPO_ROOT / Path(*path.parts)
        try:
            content = full_path.read_bytes()
        except OSError as exc:
            failures.append(f"could not audit {path}: {exc}")
            continue
        if b"\0" in content:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                failures.append(f"possible {label} found in {path}")


def _validate_metadata(failures: list[str]) -> int:
    try:
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        failures.append(f"invalid pyproject.toml: {exc}")
        return 0

    project = pyproject.get("project", {})
    if project.get("license") != "Apache-2.0":
        failures.append("project.license must be Apache-2.0")
    if project.get("license-files") != ["LICENSE", "NOTICE"]:
        failures.append("project.license-files must include LICENSE and NOTICE")
    if project.get("name") != "waveframe-guard":
        failures.append("project.name must remain waveframe-guard")
    if project.get("requires-python") != ">=3.10":
        failures.append("project.requires-python must declare the supported >=3.10 boundary")

    dependencies = project.get("dependencies", [])
    _validate_runtime_dependencies(dependencies, failures)

    extras = project.get("optional-dependencies", {})
    test_dependencies = set(extras.get("test", []))
    if extras.get("dev") != extras.get("test"):
        failures.append("project.optional-dependencies.dev and .test must stay aligned")
    missing_pins = PINNED_TEST_DEPENDENCIES - test_dependencies
    if missing_pins:
        failures.append(f"minimum compatibility test pins are missing: {sorted(missing_pins)}")
    for dependency in test_dependencies:
        if not isinstance(dependency, str) or _is_non_public_reference(dependency):
            failures.append(f"test dependency must resolve from a public package index: {dependency!r}")

    version = project.get("version")
    init_text = (REPO_ROOT / "waveframe_guard" / "__init__.py").read_text(encoding="utf-8")
    public_match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', init_text, re.MULTILINE)
    if not public_match or public_match.group(1) != version:
        failures.append(
            f"public version and package metadata differ: pyproject={version!r}, "
            f"waveframe_guard={public_match.group(1) if public_match else None!r}"
        )
    return len(dependencies)


def _validate_licensing(tracked: list[PurePosixPath], failures: list[str]) -> None:
    try:
        validate_notices(
            (REPO_ROOT / "LICENSE").read_text(encoding="utf-8"),
            (REPO_ROOT / "NOTICE").read_text(encoding="utf-8"),
        )
        citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
        if 'license: "Apache-2.0"' not in citation:
            failures.append("citation license must be Apache-2.0")
    except (OSError, AssertionError) as exc:
        failures.append(str(exc))
    for path in tracked:
        if path.suffix.lower() in {".md", ".cff"} or path.name == "pyproject.toml":
            try:
                validate_document((REPO_ROOT / path).read_text(encoding="utf-8"), str(path))
            except (OSError, AssertionError) as exc:
                failures.append(str(exc))


def _validate_mediation(tracked, failures):
    remaining = set(PACKAGED_DOCS)
    for path in tracked:
        if path.suffix.lower() != ".md":
            continue
        document = path.as_posix()
        try:
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            if document in remaining:
                validate_mediation_document(text, document)
            else:
                validate_claims(text, document)
        except (OSError, AssertionError) as exc:
            failures.append(str(exc))
        remaining.discard(document)
    for document in sorted(remaining):
        failures.append(f"{document}: missing tracked canonical documentation")


def _validate_diff(diff_base: str, failures: list[str]) -> None:
    base = diff_base.strip()
    if not base or set(base) == {"0"}:
        base = "HEAD^"
    result = subprocess.run(
        ["git", "diff", "--check", f"{base}...HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip()
        failures.append(f"git diff --check failed for {base}...HEAD: {detail}")


def _dependency_name(requirement: str) -> str:
    return re.split(r"[<>=!~;\s\[]", requirement.strip(), maxsplit=1)[0].lower().replace("_", "-")


def _validate_runtime_dependencies(dependencies: object, failures: list[str]) -> None:
    if not isinstance(dependencies, list):
        failures.append("project.dependencies must be an array")
        return

    actual: list[str] = []
    for dependency in dependencies:
        if not isinstance(dependency, str):
            failures.append(f"runtime dependency must be a string: {dependency!r}")
            continue
        if _is_non_public_reference(dependency):
            failures.append(f"runtime dependency must resolve from a public package index: {dependency!r}")
        try:
            actual.append(_normalize_requirement(dependency))
        except ValueError as exc:
            failures.append(f"invalid runtime dependency {dependency!r}: {exc}")

    expected = {_normalize_requirement(item) for item in EXPECTED_PUBLIC_RUNTIME_REQUIREMENTS}
    if len(actual) != len(set(actual)):
        failures.append("public runtime dependencies contain a duplicate requirement")
    if set(actual) != expected:
        failures.append(
            "public runtime dependency contract changed unexpectedly: "
            f"expected {sorted(expected)}, found {sorted(set(actual))}"
        )


def _normalize_requirement(requirement: str) -> str:
    compact = requirement.replace(" ", "")
    if ";" in compact:
        raise ValueError("environment markers are not approved for runtime dependencies")
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)(\[[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*\])?(.*)", compact)
    if match is None:
        raise ValueError("unsupported requirement syntax")
    name = match.group(1).lower().replace("_", "-")
    extras = (match.group(2) or "").lower().replace("_", "-")
    specifiers = match.group(3)
    normalized_specifiers = ",".join(sorted(filter(None, specifiers.split(","))))
    return f"{name}{extras}{normalized_specifiers}"


def _is_non_public_reference(requirement: str) -> bool:
    lowered = requirement.lower()
    return " @ " in lowered or "://" in lowered or lowered.startswith(("-e ", ".", "/"))


if __name__ == "__main__":
    raise SystemExit(main())

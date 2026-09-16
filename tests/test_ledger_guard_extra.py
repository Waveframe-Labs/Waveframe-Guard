"""Selection and retained-proof boundaries for the Guard-owned coordinator."""
import hashlib
import json
import subprocess
import sys
import zipfile

import pytest

from tools.acceptance import ledger_guard_extra as coordinator


def wheel(folder, name, version, marker, dependencies=()):
    folder.mkdir(exist_ok=True)
    path = folder / f"{name}-{version}-py3-none-any.whl"
    info = f"{name}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    metadata += "Provides-Extra: dev\nProvides-Extra: guard\n"
    metadata += "".join(f"Requires-Dist: {item}\n" for item in dependencies)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{info}/METADATA", metadata)
        archive.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(f"{info}/RECORD", "")
        archive.writestr(f"{name}/__init__.py", repr(marker))
    return path


@pytest.mark.parametrize("extras", [True, False], ids=["combined", "guard-entry-upgrade"])
def test_pip_selects_all_intended_archives_over_same_version_candidates(tmp_path, extras):
    # Fully offline resolver test: competing candidates have identical names and
    # versions but different bytes. Final CI additionally checks installed bytes
    # using Ledger's unchanged packaged verifier against the authentic archives.
    specifications = (
        ("governance_ledger", "0.9.0", ("waveframe-guard>=0.19.0",)),
        ("waveframe_guard", "0.19.0", ("cricore-contract-compiler>=0.5.0",)),
        ("cricore_contract_compiler", "0.5.0", ()),
    )
    intended = [wheel(tmp_path / "intended archives", n, v, "authenticated", d)
                for n, v, d in specifications]
    for name, version, dependencies in specifications:
        wheel(tmp_path / "competing", name, version, "same-version-other-origin", dependencies)
    report = tmp_path / "pip-report.json"
    command = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
               "--no-index", "--find-links", str(tmp_path / "competing"),
               "--report", str(report), *coordinator.selected_archives(*intended, extras=extras)]
    if not extras:
        command.append("--upgrade")
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    records = json.loads(report.read_text(encoding="utf-8"))["install"]
    assert len(records) == 3
    by_url = {item["download_info"]["url"]: item["download_info"]["archive_info"]["hashes"]["sha256"]
              for item in records}
    assert by_url == {path.as_uri(): hashlib.sha256(path.read_bytes()).hexdigest() for path in intended}


def tree(entries):
    return "".join(f"{identity}\t{path}\0" for path, identity in sorted(entries.items())).encode()


BASE_INPUTS = {
    "guard/sdk/repository_boundary.py": "100644 blob runtime",
    "waveframe_guard/__init__.py": "100644 blob public",
    "tests/test_repository_workspace.py": "100644 blob mount",
    "tests/conftest.py": "100644 blob hooks",
    "tests/fixtures/policy.json": "100644 blob fixture",
    "contracts/policy.json": "100644 blob contract",
    "pyproject.toml": "100644 blob metadata",
}


def test_inventory_records_only_explicit_unrelated_additions():
    current = {**BASE_INPUTS, **{p: "100644 blob new" for p in coordinator.MOUNT_UNRELATED_ADDITIONS}}
    result = coordinator.verify_mount_inputs(tree(BASE_INPUTS), tree(current))
    assert result["unchanged_git_inputs"] == BASE_INPUTS
    assert set(result["unrelated_test_additions"]) == set(coordinator.MOUNT_UNRELATED_ADDITIONS)
    assert all(item["reason"] and item["git_identity"] for item in result["unrelated_test_additions"].values())


@pytest.mark.parametrize("path", list(BASE_INPUTS) + [
    "tests/new_mount_test.py", "tests/subdir/conftest.py", "tests/.gitattributes",
    "guard/new_runtime.py", "waveframe_guard/new_runtime.py", "contracts/new.json",
    "conftest.py", "pytest.toml", ".pytest.toml", "pytest.ini", ".pytest.ini",
    "setup.cfg", "setup.py", "tox.ini", ".gitattributes",
])
def test_changed_or_added_relevant_input_invalidates_reuse(path):
    current = {**BASE_INPUTS, path: "100644 blob changed"}
    with pytest.raises(AssertionError, match="mount-relevant inputs changed"):
        coordinator.verify_mount_inputs(tree(BASE_INPUTS), tree(current))


@pytest.mark.parametrize("change", ["delete", "rename", "mode"])
def test_deleted_renamed_or_mode_changed_mount_test_invalidates_reuse(change):
    current = dict(BASE_INPUTS)
    path = "tests/test_repository_workspace.py"
    identity = current.pop(path)
    if change == "rename":
        current["tests/renamed.py"] = identity
    elif change == "mode":
        current[path] = identity.replace("100644", "100755")
    with pytest.raises(AssertionError, match="mount-relevant inputs changed"):
        coordinator.verify_mount_inputs(tree(BASE_INPUTS), tree(current))


@pytest.mark.parametrize("path", coordinator.MOUNT_UNRELATED_ADDITIONS)
def test_existing_tests_cannot_be_exempted(path):
    historical = {**BASE_INPUTS, path: "100644 blob existing"}
    with pytest.raises(AssertionError, match="exemption must be an addition"):
        coordinator.verify_mount_inputs(tree(historical), tree(BASE_INPUTS))

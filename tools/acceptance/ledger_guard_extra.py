"""Run Ledger #26's unchanged packaged suites against Guard's current clean wheel.

Guard authenticates its own build. Ledger's fixed old-Guard verifier and historical
verified-inputs records are neither invoked nor altered by this coordinator.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
BASE = "0161ef8a52e052d1bc1366cdc93ce13a9bd535ed"
LEDGER = "a34c11d81b85963794cf28b4adad091fac15e130"
COMPILER = "ae590dee058d3481e384dea850d5b7d980f533ff"
EVIDENCE = "46cd4c5a9a2c17e2367d64b56803df92de69d8b3"
URL = f"https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Ledger/{EVIDENCE}/"

# Keep the conservative #51 inventory, including every existing test/fixture.
# Additional configuration paths are included even when absent at BASE so that
# introducing pytest hooks or changing build/collection settings invalidates reuse.
MOUNT_INPUTS = {
    "guard": "complete legacy SDK runtime",
    "waveframe_guard": "complete public SDK runtime",
    "contracts": "runtime contracts and resources",
    "tests": "all existing tests, fixtures and conftest hooks, including the real mount test",
    "pyproject.toml": "build, dependencies and possible pytest settings",
    "conftest.py": "possible root pytest hooks",
    "pytest.toml": "possible pytest settings",
    ".pytest.toml": "possible pytest settings",
    "pytest.ini": "possible pytest settings",
    ".pytest.ini": "possible pytest settings",
    "setup.cfg": "possible build and pytest settings",
    "setup.py": "possible build settings",
    "tox.ini": "possible pytest settings",
    ".gitattributes": "checkout byte conversion rules",
}
MOUNT_UNRELATED_ADDITIONS = {
    "tests/test_codex_connection.py":
        "standalone fixture-backed MCP adapter tests; no shared hooks or mount-test imports",
    "tests/test_ledger_guard_extra.py":
        "standalone coordinator selection/inventory tests; no shared hooks or mount-test imports",
}


def selected_archives(ledger, guard, compiler, *, extras=False):
    """Direct requirements prevent same-version index wheels winning resolution."""
    return (str(ledger) + ("[dev,guard]" if extras else ""), str(guard), str(compiler))


def mount_inventory(tree):
    """Select exact tracked path/mode/object IDs from git ls-tree -r -z output."""
    entries = {}
    for entry in tree.decode("utf-8").split("\0"):
        if entry:
            identity, path = entry.split("\t", 1)
            if any(path == root or path.startswith(root + "/") for root in MOUNT_INPUTS):
                entries[path] = identity
    return entries


def verify_mount_inputs(before, after):
    before, after = mount_inventory(before), mount_inventory(after)
    unrelated = {}
    for path, reason in MOUNT_UNRELATED_ADDITIONS.items():
        assert path not in before, f"mount exemption must be an addition: {path}"
        if path in after:
            unrelated[path] = {"git_identity": after.pop(path), "reason": reason}
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    assert not changed, f"mount-relevant inputs changed; retained proof cannot be reused: {changed}"
    return {"inventory": MOUNT_INPUTS, "unchanged_git_inputs": after,
            "unrelated_test_additions": unrelated}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def runtime_bytes(wheel, prefixes):
    with zipfile.ZipFile(wheel) as archive:
        return {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()
                if n.startswith(prefixes) and not n.endswith("/")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-source", type=Path, required=True)
    parser.add_argument("--guard-candidate", type=Path, required=True)
    parser.add_argument("--dependency-snapshot", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.ledger_source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"ledger_head": LEDGER, "compiler_head": COMPILER, "guard_base": BASE,
              "ledger_evidence_commit": EVIDENCE, "commands": [], "status": "incomplete",
              "release_ready": False}
    gate = None

    def save():
        write(output / "guard-coordination.json", report)

    def git(label, cwd, *command):
        result = subprocess.run(["git", *command], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (output / f"{label}.log").write_bytes(result.stdout)
        report["commands"].append({"label": label, "command": ["git", *command],
                                   "cwd": str(cwd), "exit_code": result.returncode})
        save()
        assert result.returncode == 0, label
        return result.stdout

    try:
        assert git("ledger-head", source, "rev-parse", "HEAD").decode().strip() == LEDGER
        assert not git("ledger-clean", source, "status", "--porcelain", "--untracked-files=no").strip()
        head = git("guard-head", ROOT, "rev-parse", "HEAD").decode().strip()
        assert not git("guard-clean", ROOT, "status", "--porcelain", "--untracked-files=no").strip()
        git("guard-stack", ROOT, "merge-base", "--is-ancestor", BASE, head)
        report["guard_head"] = head
        manifest_path = args.guard_candidate.resolve()
        manifest = read(manifest_path)
        assert manifest["source_commit"] == head
        assert manifest["source_url"] == "https://github.com/Waveframe-Labs/Waveframe-Guard"
        guard = manifest_path.parent / manifest["wheel"]
        assert guard.name == "waveframe_guard-0.19.0-py3-none-any.whl"
        assert digest(guard) == manifest["wheel_sha256"]
        build = read(manifest_path.parent / "build-provenance.json")
        assert build["source_commit"] == head and build["clean_tracked_checkout"]
        assert build["build_exit_code"] == 0
        tracked = git("guard-build-inputs", ROOT, "ls-files", "-z").decode().split("\0")
        assert build["tracked_files_sha256"] == {n: digest(ROOT / n) for n in tracked if n}
        for filename, expected in read(manifest_path.parent / "package-hashes.json").items():
            assert digest(manifest_path.parent / filename) == expected
        report["guard_candidate"] = manifest
        report["guard_build_provenance_sha256"] = digest(manifest_path.parent / "build-provenance.json")

        # The immutable handoff and its independent checksum index bind the entire
        # retained archive. Its old Guard evidence stays labeled as historical.
        for name in ("handoff.json", "SHA256SUMS"):
            urllib.request.urlretrieve(URL + name, output / ("ledger-" + name))
        handoff = read(output / "ledger-handoff.json")
        assert handoff["head"] == LEDGER and handoff["compiler_head"] == COMPILER
        checksums = {name: sha for sha, name in (line.split("  ", 1)
                     for line in (output / "ledger-SHA256SUMS").read_text().splitlines())}
        assert digest(output / "ledger-handoff.json") == checksums["handoff.json"]
        cell = ("windows" if os.name == "nt" else "ubuntu") + f"-{sys.version_info.major}.{sys.version_info.minor}"
        selected = handoff["cells"][cell]
        archive = output / "retained-ledger.zip"
        urllib.request.urlretrieve(URL + selected["archive"], archive)
        assert digest(archive) == handoff["archive_sha256"][selected["archive"]] == checksums[selected["archive"]]
        report["archive_origin"] = {"url": URL + selected["archive"], "sha256": digest(archive), "cell": cell}
        retained = output / "retained-ledger"
        with zipfile.ZipFile(archive) as packed:
            for name in packed.namelist():
                path = Path(name)
                assert not path.is_absolute() and ".." not in path.parts
            packed.extractall(retained)
        base_path = retained / "issue25-base"
        base = read(base_path / "acceptance.json")
        assert base["head"] == base["expected_head"] == LEDGER
        assert base["gates"]["base"] == "passed"
        report["historical_base"] = {"python": base["python"], "platform": base["platform"],
            "acceptance_sha256": digest(base_path / "acceptance.json"),
            "scope": "retained Ledger base evidence; current interpreter suites execute below"}
        compiler_build = base["compiler_wheel"]
        assert compiler_build["origin"]["vcs_info"]["commit_id"] == COMPILER
        report["compiler_build"] = compiler_build
        wheelhouse = output / "wheelhouse"
        wheelhouse.mkdir()
        for name, expected in base["package_sha256"].items():
            package = base_path / "dist" / name
            assert digest(package) == expected == selected["package_sha256"][name]
            shutil.copyfile(package, wheelhouse / name)
        compiler = base_path / compiler_build["filename"]
        assert digest(compiler) == compiler_build["sha256"] == selected["package_sha256"][compiler.name]
        shutil.copyfile(compiler, wheelhouse / compiler.name)
        compiler = wheelhouse / compiler.name
        shutil.copyfile(guard, wheelhouse / guard.name)
        guard = wheelhouse / guard.name
        ledger = wheelhouse / "governance_ledger-0.9.0-py3-none-any.whl"
        report["package_sha256"] = {p.name: digest(p) for p in wheelhouse.iterdir()}

        # Restore only the authenticated sdist support files. Import Acceptance
        # from here so its ROOT/default cwd/constraints point outside the checkout.
        support = output / "installed-support"
        support.mkdir()
        with tarfile.open(wheelhouse / "governance_ledger-0.9.0.tar.gz") as packed:
            for member in packed.getmembers():
                if not member.isfile():
                    continue
                path = Path(*Path(member.name).parts[1:])
                assert path.parts and not path.is_absolute() and ".." not in path.parts
                if path.parts[0] in {"tests", "schemas", "examples", "tools", "docs"} or len(path.parts) == 1:
                    target = support / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(packed.extractfile(member).read())
        for name, expected in base["sdist_resource_sha256"].items():
            assert digest(support / name) == expected
        assert not (support / "governance_ledger").exists()
        (support / "runtime").mkdir()
        report["packaged_support_sha256"] = base["sdist_resource_sha256"]
        sys.path.insert(0, str(support / "tools"))
        from run_action_policy_acceptance import Acceptance
        gate = Acceptance(output / "combined")
        gate.report.update(head=head, ledger_head=LEDGER, guard_candidate=manifest,
                           archive_origin=report["archive_origin"])
        gate.report["gates"] = {"combined_extra": "incomplete"}
        gate.env["WAVEFRAME_LEDGER_TEST_WHEEL"] = str(ledger)
        python = gate.environment("combined-extra", *selected_archives(ledger, guard, compiler, extras=True))
        expected = gate.archive_expectations("combined-extra", compiler, compiler_build,
            {"governance-ledger": ledger, "waveframe-guard": guard})
        gate.probe(python, support, "combined-provenance", "check_installed_wheel_set.py", expected)
        gate.suites(python, support, "combined-extra", installed=True, guard=True)
        for mode, passed, skipped in (("default", 678, 44), ("native", 722, 0)):
            counts = gate.report["suites"]["combined-extra-" + mode]
            assert counts["passed"] == passed and counts["skipped"] == skipped, counts
        gate.probe(python, support, "release-package", "check_release_catalog_package.py")
        gate.probe(python, support, "development-package", "check_action_policy_package.py", native=True)
        gate.run("legacy-v3-example", python, "-I", support / "examples/native_v3_multi_control.py", "--candidate", cwd=support)
        probes = gate.probe(python, support, "catalog-3-execution", "check_guard_release_execution.py")
        assert len(probes["cases"]) == 56
        gate.report["catalog_3_execution_cases"] = len(probes["cases"])
        gate.env.pop("LEDGER_ARCHIVE_EXPECTATIONS", None)
        for version in ("0.7.0", "0.8.0"):
            failure = gate.run("reject-old-ledger-" + version, python, "-m", "pip", "install", "--dry-run",
                guard, f"governance-ledger=={version}", compiler, negative=True)
            assert "ResolutionImpossible" in failure
        upgrade = gate.environment("guard-entry", "governance-ledger==0.8.0",
                                   "waveframe-guard==0.18.0", "cricore-contract-compiler==0.4.0")
        gate.run("guard-entry-upgrade", upgrade, "-m", "pip", "install", "--upgrade",
                 *selected_archives(ledger, guard, compiler), "--report", gate.output / "guard-entry-install.json")
        gate.run("guard-entry-upgrade-check", upgrade, "-m", "pip", "check")
        expected = gate.archive_expectations("guard-entry", compiler, compiler_build,
            {"governance-ledger": ledger, "waveframe-guard": guard})
        gate.probe(upgrade, support, "guard-entry-provenance", "check_installed_wheel_set.py", expected)
        gate.probe(upgrade, support, "guard-entry-catalog-3", "check_guard_release_execution.py")

        # Source-built dependency checks remain separate, with exact runtime and
        # resource equivalence to the accepted archives used by the full gate.
        report["source_archive_equivalence"] = {}
        for snapshot in args.dependency_snapshot:
            current = read(snapshot)
            for name, wheel, prefix, commit in (("governance-ledger", ledger, "governance_ledger/", LEDGER),
                                                ("cricore-contract-compiler", compiler, "compiler/", COMPILER)):
                item = current["distributions"][name]
                assert item["origin"]["vcs_info"]["commit_id"] == commit
                assert item["runtime_sha256"] == runtime_bytes(wheel, (prefix,)), (snapshot, name)
            report["source_archive_equivalence"][str(snapshot)] = {"sha256": digest(snapshot), "runtime_resources_equal": True}

        old_guard = retained / "issue25-combined/wheelhouse" / guard.name
        assert digest(old_guard) == selected["guard_manifest"]["wheel_sha256"]
        unchanged = runtime_bytes(guard, ("guard/", "waveframe_guard/"))
        assert unchanged == runtime_bytes(old_guard, ("guard/", "waveframe_guard/"))
        mount_inputs = verify_mount_inputs(
            git("mount-inputs-base", ROOT, "ls-tree", "-r", "-z", BASE),
            git("mount-inputs-current", ROOT, "ls-tree", "-r", "-z", head))
        report["mount_equivalence"] = {"historical_guard_head": BASE,
            "source_inputs": mount_inputs,
            "historical_cell_wheel_sha256": digest(old_guard), "current_wheel_sha256": digest(guard),
            "runtime_sha256": unchanged,
            "retained_mount_evidence_commit": "e6008345c9891ec6ffb5088f38177022e3cef4aa",
            "actually_mount_tested_wheel_sha256": "2b78374416635ca551ee5470fcd1e9e390d3f08141a53c91bcba7d42516b046e",
            "scope": "#51 Linux/Python 3.14 real same-device bind-mount proof; identical Guard runtime and mount-test inputs. Ledger #26 changes CLI/legacy mediation, not Guard filesystem enforcement. This current wheel was not newly mount-tested."}
        assert git("final-guard-head", ROOT, "rev-parse", "HEAD").decode().strip() == head
        assert not git("final-guard-clean", ROOT, "status", "--porcelain", "--untracked-files=no").strip()
        assert not git("final-ledger-clean", source, "status", "--porcelain", "--untracked-files=no").strip()
        gate.report.update(status="combined-extra-passed", combined_extra={"status": "passed", "executed": True})
        gate.report["gates"]["combined_extra"] = "passed"
        gate.save()
        report.update(status="passed", guard_entry_upgrade="passed", old_ledger_resolver_rejection="passed")
    except BaseException as exc:
        report.update(status="failed", error=str(exc))
        if gate is not None:
            gate.report.update(status="failed", error=str(exc))
            gate.report["gates"]["combined_extra"] = "failed"
            gate.save()
        raise
    finally:
        save()


if __name__ == "__main__":
    main()

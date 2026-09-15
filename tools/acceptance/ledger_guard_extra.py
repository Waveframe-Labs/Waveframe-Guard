"""Run Ledger's unchanged combined gate and a separate real Guard-entry upgrade.

All source checkouts are validation-only. Reports survive a dependency-tool failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import urllib.request
import venv
import zipfile

LEDGER = "3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f"
EVIDENCE = "44552c3fbedfffcc480c294d0b381eaecbc5017d"
URL = f"https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Ledger/{EVIDENCE}/"

# find-links selections are not direct requirements: pip records their archive
# origin in the install report rather than necessarily emitting PEP 610 metadata.
UPGRADE_PROBE = r'''
import hashlib, importlib, json, sys, zipfile
from importlib.metadata import distribution
from pathlib import Path
expected = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
result = {}
for name, version, module in (("governance-ledger", "0.9.0", "governance_ledger"),
                             ("cricore-contract-compiler", "0.5.0", "compiler"),
                             ("waveframe-guard", "0.19.0", "waveframe_guard")):
    dist = distribution(name)
    assert dist.version == version
    imported = importlib.import_module(module)
    path = Path(imported.__file__).resolve()
    assert path.is_relative_to(Path(sys.prefix).resolve())
    if name == "waveframe-guard":
        assert imported.__version__ == version
    wheel, = [Path(p) for p in expected["wheels"] if Path(p).name.startswith(name.replace("-", "_") + "-")]
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    install, = [i for i in report["install"] if i["metadata"]["name"].replace("_", "-") == name]
    archive_info = install["download_info"]["archive_info"]
    installed_digest = archive_info.get("hashes", {}).get("sha256")
    if installed_digest is None:
        installed_digest = archive_info.get("hash", "").removeprefix("sha256=")
    assert installed_digest == digest
    checked = {}
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.namelist():
            if member.endswith(".py"):
                data = archive.read(member)
                assert Path(dist.locate_file(member)).read_bytes() == data
                checked[member] = hashlib.sha256(data).hexdigest()
    result[name] = {"version": version, "module_path": str(path), "wheel_sha256": digest,
                    "installer_origin": install["download_info"], "python_sha256": checked}
print(json.dumps(result, indent=2))
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger-source", type=Path, required=True)
    parser.add_argument("--guard-candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.ledger_source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"python": sys.version, "platform": platform.platform(), "ledger_head": LEDGER,
              "base_evidence_commit": EVIDENCE, "commands": [], "release_ready": False}

    def save():
        (output / "guard-coordination.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(label, command, cwd=source, check=True, env=None):
        command = list(map(str, command))
        with (output / f"{label}.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=env)
        report["commands"].append({"label": label, "command": command, "cwd": str(cwd), "exit_code": result.returncode})
        save()
        if check and result.returncode:
            raise RuntimeError(f"{label} failed: see {output / (label + '.log')}")
        return result.returncode

    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source).decode().strip() == LEDGER
    assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source).strip()
    cell = ("windows" if os.name == "nt" else "ubuntu") + f"-{sys.version_info.major}.{sys.version_info.minor}"
    handoff_path = output / "ledger-base-handoff.json"
    urllib.request.urlretrieve(URL + "handoff.json", handoff_path)
    cell_record = json.loads(handoff_path.read_text())["environments"][cell]
    archive = output / "retained-ledger-base.zip"
    urllib.request.urlretrieve(URL + cell_record["durable_archive"], archive)
    assert digest(archive) == cell_record["durable_archive_sha256"]
    report["retained_base_archive_sha256"] = digest(archive)
    base = output / "retained-base"
    with zipfile.ZipFile(archive) as packed:
        packed.extractall(base)
    base = next(base.rglob("acceptance.json")).parent
    original = json.loads((base / "acceptance.json").read_text())
    report["original_base_python"] = original["python"]
    if original["python"].split()[0] != sys.version.split()[0]:
        base = output / "fresh-base"
        run("fresh-base", [sys.executable, "tools/run_action_policy_acceptance.py", "--expected-head", LEDGER, "--output", base])
    report["matching_base"] = str(base)
    manifest_path = args.guard_candidate.resolve()
    combined = output / "combined"
    result = run("supplied-combined", [sys.executable, "tools/run_guard_extra_acceptance.py", "--expected-head", LEDGER,
                 "--base-evidence", base, "--guard-candidate", manifest_path, "--output", combined], check=False)
    report["combined_exit_code"] = result
    # The supplied entry point stops at the first failed suite. Preserve that
    # failed gate and run its remaining unchanged probes as supplemental evidence.
    support = combined / "installed-support"
    combined_python = combined / "combined-extra" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if result and combined_python.exists():
        probe_env = os.environ.copy()
        for key in ("PYTHONPATH", "WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"):
            probe_env.pop(key, None)
        probe_env.update(PYTHONUTF8="1", LEDGER_EXPECT_IMPORT_ROOT=str(combined_python.parent.parent),
                         LEDGER_IMPORT_REPORT=str(output / "supplemental-native-imports.json"),
                         WAVEFRAME_LEDGER_TEST_WHEEL=str(combined / "wheelhouse/governance_ledger-0.9.0-py3-none-any.whl"))
        native_env = dict(probe_env, WAVEFRAME_LEDGER_ACTION_POLICY_DEV="1")
        report["supplemental_probes"] = {}
        probes = [
            ("native-suite", [support / "tools/acceptance_pytest.py", "-q", "-ra", "--junitxml",
                              output / "supplemental-native.xml", "tests"], native_env),
            ("release-package", [support / "tools/check_release_catalog_package.py"], probe_env),
            ("development-package", [support / "tools/check_action_policy_package.py"], native_env),
            ("legacy-example", [support / "examples/native_v3_multi_control.py", "--candidate"], probe_env),
            ("catalog-3-execution", [support / "tools/check_guard_release_execution.py"], probe_env),
        ]
        for label, command, env in probes:
            report["supplemental_probes"][label] = run("supplemental-" + label,
                [combined_python, "-I", *command], support, check=False, env=env)
        save()
    # This independent check remains useful even when the supplied combined tool fails.
    base_record = json.loads((base / "acceptance.json").read_text())
    ledger = base / "dist/governance_ledger-0.9.0-py3-none-any.whl"
    compiler = base / base_record["compiler_wheel"]["filename"]
    manifest = json.loads(manifest_path.read_text())
    guard = manifest_path.parent / manifest["wheel"]
    assert digest(guard) == manifest["wheel_sha256"]
    assert digest(ledger) == base_record["package_sha256"][ledger.name]
    assert digest(compiler) == base_record["compiler_wheel"]["sha256"]
    environment = output / "upgrade-environment"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    work = output / "upgrade-work"
    work.mkdir()
    run("old-ledger-install", [python, "-m", "pip", "install", "governance-ledger==0.8.0", "--report", output / "old-install.json"], work)
    run("old-ledger-version", [python, "-I", "-c", "from importlib.metadata import version; assert version('governance-ledger') == '0.8.0'"], work)
    rejected = run("old-ledger-rejected", [python, "-m", "pip", "install", "--dry-run", "--ignore-installed",
                   guard, "governance-ledger==0.8.0"], work, check=False)
    assert rejected and "ResolutionImpossible" in (output / "old-ledger-rejected.log").read_text()
    run("guard-entry-upgrade", [python, "-m", "pip", "install", guard, "--find-links", ledger.parent,
                               "--find-links", compiler.parent, "--report", output / "upgrade-install.json"], work)
    run("upgrade-pip-check", [python, "-m", "pip", "check"], work)
    expected = output / "upgrade-wheels.json"
    expected.write_text(json.dumps({"wheels": list(map(str, (ledger, compiler, guard)))}))
    run("upgrade-installed-bytes", [python, "-I", "-c", UPGRADE_PROBE, expected, output / "upgrade-install.json"], work)
    report["guard_entry_upgrade"] = "passed"
    report["old_ledger_resolver_rejection"] = "passed"
    report["dependency_tracked_tree_clean"] = not subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=source).strip()
    assert report["dependency_tracked_tree_clean"]
    save()
    return result


if __name__ == "__main__":
    raise SystemExit(main())

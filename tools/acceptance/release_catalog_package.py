"""Fresh distributions, ordinary resolution, and isolated installed release/dev tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.acceptance import package_acceptance

TESTS = [
    "test_action_policy_creation.py", "test_native_cloud_connection.py", "test_release_catalog.py",
    "test_repository_workspace.py", "test_repository_execution_evidence.py",
    "test_creation_attestation_consistency.py", "test_target_binding.py",
    "test_target_scope_enforcement.py", "test_cache_integrity.py",
    "test_ledger_v2_authority_runtime.py", "test_ledger_v3_authority_runtime.py",
    "test_cloud_publication_resolver.py", "test_cloud_preservation_invariants.py",
]


def run(command, cwd, env=None):
    subprocess.run([str(part) for part in command], cwd=cwd, env=env, check=True)


def summarize(path, *, require_release=True):
    cases = ET.parse(path).findall(".//testcase")
    release = [c for c in cases if "[release" in c.get("name", "") or c.get("classname", "").endswith("test_release_catalog")]
    if require_release:
        assert len(release) >= 100, len(release)
        assert all(c.find("skipped") is None and c.find("failure") is None and c.find("error") is None for c in release)
    summary = {"cases": len(cases), "release_executed": sum(c.find("skipped") is None for c in release),
        "skips": [{"case": c.get("classname") + "." + c.get("name"), "reason": c.find("skipped").get("message")}
                  for c in cases if c.find("skipped") is not None]}
    path.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="guard50-package-") as temp:
        scratch = Path(temp).resolve()
        source = scratch / "source"
        for name in filter(None, subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
        assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT).strip()
        record = {"source_commit": head, "python": sys.version,
                  "tracked_files_sha256": {str(p.relative_to(source)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                                           for p in source.rglob("*") if p.is_file()},
                  "build_command": [sys.executable, "-m", "build", "--outdir", str(output)],
                  "clean_tracked_checkout": True}
        (output / "build-provenance.json").write_text(json.dumps(record, indent=2) + "\n")
        with (output / "build.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, "-m", "build", "--outdir", str(output)], cwd=source,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        wheel, sdist = next(output.glob("*.whl")), next(output.glob("*.tar.gz"))
        package_acceptance._inspect_wheel(wheel, "0.19.0")
        package_acceptance._inspect_sdist(sdist, "0.19.0")
        (output / "package-hashes.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (wheel, sdist)}, indent=2) + "\n")
        (output / "guard-candidate.json").write_text(json.dumps({"source_url": "https://github.com/Waveframe-Labs/Waveframe-Guard",
            "source_commit": head, "provenance_kind": "coordinator-supplied-exact-candidate",
            "wheel": wheel.name, "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}, indent=2) + "\n")
        run([sys.executable, "-m", "twine", "check", "--strict", wheel, sdist], scratch)
        isolated = scratch / "acceptance"
        for name in ("tests", "tools", "contracts", "examples", "docs", ".github"):
            shutil.copytree(source / name, isolated / name)
        for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "SECURITY.md"):
            shutil.copyfile(source / name, isolated / name)
        env = dict(os.environ, GUARD_EXPECT_INSTALLED="1")
        for key in ("PYTHONPATH", "WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"):
            env.pop(key, None)
        profile = "release"
        environment = scratch / profile
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        requirements = ["-r", ROOT / ".github/requirements/action-policy-release.txt"]
        run([python, "-m", "pip", "install", f"{wheel}[test]", *requirements,
             "--report", output / f"{profile}-install.json"], isolated, env)
        checked = subprocess.check_output([str(python), "-m", "pip", "check"], cwd=isolated, env=env).decode()
        (output / f"{profile}-pip-check.txt").write_text(checked)
        probe_env = dict(env, GUARD_EXPECTED_VERSION="0.19.0", GUARD_REPOSITORY_ROOT=str(ROOT))
        run([python, "-c", package_acceptance.SMOKE_SCRIPT], isolated, probe_env)
        for mode in ("evaluation", "mutation"):
            work = scratch / ("smoke-" + mode)
            work.mkdir()
            run([python, "-c", package_acceptance.REPOSITORY_SMOKE_SCRIPT, mode], work, probe_env)
        cli = environment / ("Scripts/waveframe-guard-external-agent.exe" if os.name == "nt" else "bin/waveframe-guard-external-agent")
        with (output / "cli-help.txt").open("w", encoding="utf-8") as log:
            subprocess.run([str(cli), "--help"], cwd=isolated, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        example_root = output / "example-workspace"
        (example_root / "generated").mkdir(parents=True)
        with (output / "example.json").open("w", encoding="utf-8") as log:
            subprocess.run([str(python), "examples/sdk/repository_creation_release.py", "--repository-root", str(example_root),
                            "--evidence-root", str(output / "example-evidence")], cwd=isolated, env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        xml = output / f"installed-{profile}.xml"
        run([python, "-m", "pytest", "-q", "-ra", *["tests/" + name for name in TESTS], f"--junitxml={xml}"], isolated, env)
        summarize(xml, require_release=profile == "release")
        run([python, "tools/acceptance/action_policy_creation.py", "--fixtures",
             isolated / "tests/fixtures/action_policy_release_v4", "--output", output / "release-evidence.json"], isolated, env)
        run([python, "tools/acceptance/release_cloud_protocol.py", "--output", output / "release-http.json"], isolated, env)
        dev = dict(env, WAVEFRAME_GUARD_ACTION_POLICY_DEV="1", WAVEFRAME_LEDGER_ACTION_POLICY_DEV="1")
        xml = output / "installed-development.xml"
        run([python, "-m", "pytest", "-q", "-ra", *["tests/" + name for name in TESTS], f"--junitxml={xml}"], isolated, dev)
        summarize(xml)
        run([python, "tools/acceptance/action_policy_creation.py", "--output", output / "retained-development-evidence.json"], isolated, dev)
        (output / "package-hashes.json").write_text(json.dumps({p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (wheel, sdist)}, indent=2) + "\n")


if __name__ == "__main__":
    main()

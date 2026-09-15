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
    with tempfile.TemporaryDirectory(prefix="guard48-package-") as temp:
        scratch = Path(temp).resolve()
        source = scratch / "source"
        for name in filter(None, subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        run([sys.executable, "-m", "build", "--outdir", output], source)
        wheel, sdist = next(output.glob("*.whl")), next(output.glob("*.tar.gz"))
        package_acceptance._inspect_wheel(wheel, "0.18.0")
        package_acceptance._inspect_sdist(sdist, "0.18.0")
        run([sys.executable, "-m", "twine", "check", wheel, sdist], scratch)
        isolated = scratch / "acceptance"
        for name in ("tests", "tools", "contracts", "examples", "docs", ".github"):
            shutil.copytree(source / name, isolated / name)
        for name in ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "SECURITY.md"):
            shutil.copyfile(source / name, isolated / name)
        env = dict(os.environ, GUARD_EXPECT_INSTALLED="1")
        for key in ("PYTHONPATH", "WAVEFRAME_GUARD_ACTION_POLICY_DEV", "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"):
            env.pop(key, None)
        for profile in ("release", "historical"):
            environment = scratch / profile
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            requirements = (["-r", ROOT / ".github/requirements/action-policy-release.txt"] if profile == "release"
                else ["cricore==0.14.0", "governance-ledger==0.8.0", "cricore-contract-compiler==0.4.0"])
            run([python, "-m", "pip", "install", f"{wheel}[test]", *requirements,
                 "--report", output / f"{profile}-install.json"], isolated, env)
            checked = subprocess.check_output([str(python), "-m", "pip", "check"], cwd=isolated, env=env).decode()
            (output / f"{profile}-pip-check.txt").write_text(checked)
            run([python, "-c", "import waveframe_guard,sys; from pathlib import Path; "
                 "assert Path(waveframe_guard.__file__).is_relative_to(Path(sys.prefix))"], isolated, env)
            xml = output / f"installed-{profile}.xml"
            run([python, "-m", "pytest", "-q", "-ra", *["tests/" + name for name in TESTS], f"--junitxml={xml}"], isolated, env)
            summarize(xml, require_release=profile == "release")
            if profile == "release":
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

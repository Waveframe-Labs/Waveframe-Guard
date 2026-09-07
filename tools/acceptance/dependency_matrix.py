"""Build Guard and verify a resolved, installed wheel at a compatibility boundary.

Run with Python 3.10 for minimum, or Python 3.14 and --cri-source for candidate.
The complete suite uses the checkout; independent acceptance subprocesses import
only the installed wheel, outside the repository and without pytest fixtures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.acceptance import ledger_v2_clean_wheel, ledger_v3_clean_wheel, package_acceptance
from tools.acceptance.resolver_boundaries import check as check_resolver


ROOT = Path(__file__).resolve().parents[2]
CRI_COMMIT = "411dfaa976fd4b37efc5fd3e39076edcd3603e1b"


LEGACY_SCRIPT = r'''
import json
from pathlib import Path
from waveframe_guard import (
    execute, guard, evaluate_admissibility, GovernedRuntime, GuardRuntime,
    LegacyExecutionError,
)
from waveframe_guard.result import GovernedExecutionResult

callbacks = []
def callback():
    callbacks.append(1)

operations = [lambda: execute(callback), lambda: guard(callback)(),
              lambda: evaluate_admissibility({}, {})]
registry = Path("legacy-index.json")
registry.write_text(json.dumps({"contracts": []}), encoding="utf-8")
runtimes = []
for runtime_class in (GovernedRuntime, GuardRuntime):
    runtime = runtime_class(registry_path=registry)
    runtimes.append(runtime)
    operations.extend([
        lambda r=runtime: r.execute(fn=callback),
        lambda r=runtime: r.execute_proposal({"proposal_id": "dependency-acceptance"}),
        lambda r=runtime: r.evaluate(fn=callback),
        lambda r=runtime: r.revalidate(GovernedExecutionResult(allowed=True, reason="old decision")),
    ])
assert len(operations) == 11
for operation in operations:
    try:
        operation()
    except LegacyExecutionError as error:
        assert error.code == "GUARD_LEGACY_EXECUTION_UNSUPPORTED"
    else:
        raise AssertionError("legacy permission returned")
assert callbacks == []
assert all(r.audit_events == [] and r.runtime_logs == [] and r.last_event is None for r in runtimes)
print("legacy_entrypoints=11 rejected=11 code=GUARD_LEGACY_EXECUTION_UNSUPPORTED callbacks=0 allowed_events=0")
'''


def run(command: list[str], *, cwd: Path = ROOT, env: dict | None = None) -> None:
    print("+", " ".join(map(str, command)), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("minimum", "candidate"), required=True)
    parser.add_argument("--cri-source", type=Path)
    args = parser.parse_args()
    expected_python = (3, 10) if args.profile == "minimum" else (3, 14)
    assert sys.version_info[:2] == expected_python, sys.version
    constraints = ROOT / ".github" / "constraints" / f"{args.profile}.txt"
    project = package_acceptance.tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    expected = dict(line.split("==") for line in constraints.read_text().splitlines()
                    if line and not line.startswith("#"))

    with tempfile.TemporaryDirectory(prefix=f"guard-{args.profile}-") as temporary:
        root = Path(temporary)
        cri_wheels = []
        if args.profile == "candidate":
            assert args.cri_source is not None, "candidate requires the exact CRI source checkout"
            source = args.cri_source.resolve()
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
            assert head == CRI_COMMIT, head
            # Build an archive of the reviewed commit; local or generated files
            # in the supplied checkout cannot change the candidate artifact.
            archive = root / "cri.zip"
            run(["git", "archive", "--format=zip", f"--output={archive}", CRI_COMMIT], cwd=source)
            import zipfile
            with zipfile.ZipFile(archive) as packed:
                packed.extractall(root / "cri-source")
            run([sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir",
                 str(root / "cri-dist"), str(root / "cri-source")])
            cri_wheels = list((root / "cri-dist").glob("*.whl"))
            assert len(cri_wheels) == 1
            print(f"CRI commit={head} wheel_sha256={hashlib.sha256(cri_wheels[0].read_bytes()).hexdigest()}")

        dist = root / "dist"
        run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(dist)])
        wheel, = dist.glob("*.whl")
        sdist, = dist.glob("*.tar.gz")
        run([sys.executable, "-m", "twine", "check", str(wheel), str(sdist)])
        package_acceptance._inspect_wheel(wheel, project["version"])
        package_acceptance._inspect_sdist(sdist, project["version"])
        check_resolver(wheel)

        environment = root / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = str(package_acceptance._venv_python(environment))
        run([python, "-m", "pip", "install", "pip==26.2.1", "setuptools==83.0.0", "wheel==0.48.0"])
        run([python, "-m", "pip", "install", "--constraint", str(constraints),
             f"{wheel}[test]", *map(str, cri_wheels), "pytest==9.0.3", "build==1.6.0", "twine==6.2.0"])
        run([python, "-m", "pip", "check"])
        # Inspect actual installed metadata in the child interpreter; never the
        # parent environment or checkout's potentially stale egg-info directory.
        inspection = (
            "from importlib.metadata import distribution, version; import json; "
            "d=distribution('waveframe-guard'); "
            "print(json.dumps({'requires':d.requires,'versions':{n:version(n) for n in "
            + repr(list(expected)) + "}}))"
        )
        installed = json.loads(subprocess.check_output([python, "-c", inspection], cwd=root, text=True))
        assert installed["versions"] == expected, installed
        actual = {package_acceptance._normalize_requirement(r) for r in installed["requires"] if ";" not in r}
        declared = {package_acceptance._normalize_requirement(r) for r in project["dependencies"]}
        assert actual == declared, (actual, declared)
        print("Installed Requires-Dist and exact versions:", json.dumps(installed), flush=True)
        run([python, "-m", "pytest", "-q", "-ra", "tests"])
        run([python, "-m", "compileall", "-q", "guard", "waveframe_guard", "tests", "examples", "tools"])

        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env["GUARD_EXPECTED_VERSION"] = project["version"]
        env["GUARD_REPOSITORY_ROOT"] = str(ROOT)
        scripts = [
            ("local", package_acceptance.SMOKE_SCRIPT, []),
            ("repository-evaluation", package_acceptance.REPOSITORY_SMOKE_SCRIPT, ["evaluation"]),
            ("repository-mutation", package_acceptance.REPOSITORY_SMOKE_SCRIPT, ["mutation"]),
            ("cloud-v2", package_acceptance.CLOUD_V2_SMOKE_SCRIPT, []),
            ("ledger-v2", ledger_v2_clean_wheel.RUNNER, []),
            ("legacy", LEGACY_SCRIPT, []),
        ]
        if args.profile == "candidate":
            scripts.append(("ledger-v3", ledger_v3_clean_wheel.RUNNER, []))
        for name, script, arguments in scripts:
            work = root / name
            work.mkdir()
            runner = work / "acceptance.py"
            runner.write_text(script, encoding="utf-8")
            run([python, str(runner), *arguments], cwd=work, env=env)
        run([python, "-m", "pip", "check"])
        print(f"Dependency matrix passed: {args.profile}; {sys.version}; {expected}", flush=True)


if __name__ == "__main__":
    main()

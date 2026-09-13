"""Fresh wheel/sdist and isolated installed-wheel action acceptance."""

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

ROOT = Path(__file__).resolve().parents[2]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tools.acceptance import package_acceptance


def run(command, cwd, env=None):
    subprocess.run([str(part) for part in command], cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="guard-action-package-") as temp:
        scratch = Path(temp).resolve()
        source = scratch / "source"
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        for name in filter(None, tracked):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        run([sys.executable, "-m", "build", "--outdir", output], source)
        wheel = next(output.glob("*.whl"))
        sdist = next(output.glob("*.tar.gz"))
        package_acceptance._inspect_wheel(wheel, "0.18.0")
        package_acceptance._inspect_sdist(sdist, "0.18.0")
        run([sys.executable, "-m", "twine", "check", wheel, sdist], scratch)
        environment = scratch / "installed"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([python, "-m", "pip", "install", wheel, "-r",
             ROOT / ".github/requirements/action-policy-release.txt"], scratch)
        run([python, "-m", "pip", "check"], scratch)
        runner = scratch / "acceptance.py"
        shutil.copyfile(ROOT / "tools/acceptance/action_policy_creation.py", runner)
        env = dict(os.environ, WAVEFRAME_GUARD_ACTION_POLICY_DEV="1", WAVEFRAME_LEDGER_ACTION_POLICY_DEV="1")
        env.pop("PYTHONPATH", None)
        run([python, "-c", "import waveframe_guard,sys; from pathlib import Path; "
             "assert Path(waveframe_guard.__file__).is_relative_to(Path(sys.prefix))"], scratch, env)
        run([python, runner, "--fixtures", ROOT / "tests/fixtures/action_policy_v4",
             "--output", output / "installed-wheel-evidence.json"], scratch, env)
        (output / "package-hashes.json").write_text(json.dumps({
            artifact.name: hashlib.sha256(artifact.read_bytes()).hexdigest()
            for artifact in (wheel, sdist)
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()

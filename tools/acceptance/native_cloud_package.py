"""Reproduce connected acceptance with two isolated environments and exact Cloud source."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import venv

ROOT = Path(__file__).resolve().parents[2]
CLOUD_COMMIT = "547291b525e2f1d05d92ed65b6058c4ca91588a8"


def run(command, cwd, env=None):
    subprocess.run([str(item) for item in command], cwd=cwd, env=env, check=True)


def python_at(environment):
    return environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cloud-source", type=Path)
    parser.add_argument("--server-python", type=Path, help="Optional preinstalled isolated Cloud environment")
    parser.add_argument("--server-base-python", type=Path, help="Python 3.14 used to create the isolated Cloud environment")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="guard46-connected-") as temp:
        scratch = Path(temp).resolve()
        cloud = args.cloud_source.resolve() if args.cloud_source else scratch / "cloud"
        if not args.cloud_source:
            run(["git", "clone", "--no-checkout", "https://github.com/Waveframe-Labs/Waveframe-Cloud.git", cloud], scratch)
            run(["git", "checkout", "--detach", CLOUD_COMMIT], cloud)
        assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=cloud).decode().strip() == CLOUD_COMMIT
        assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=cloud).strip()
        client_env = scratch / "client"
        venv.EnvBuilder(with_pip=True).create(client_env)
        client_python = python_at(client_env)
        run([client_python, "-m", "pip", "install", args.wheel.resolve(), "-r",
             ROOT / ".github/requirements/action-policy-release.txt"], scratch)
        server_python = args.server_python.resolve() if args.server_python else python_at(scratch / "server")
        if not args.server_python:
            server_base = args.server_base_python.resolve() if args.server_base_python else Path(sys.executable)
            run([server_base, "-m", "venv", scratch / "server"], scratch)
            run([server_python, "-m", "pip", "install", "-r", cloud / "requirements-action-policy-dev.txt"], scratch)
        for name, python in (("client", client_python), ("server", server_python)):
            checked = subprocess.check_output([str(python), "-m", "pip", "check"], cwd=scratch).decode()
            (output / (name + "-pip-check.txt")).write_text(checked, encoding="utf-8")
        server_env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", WAVEFRAME_CLOUD_ACTION_POLICY_DEV="1",
                          WAVEFRAME_LEDGER_ACTION_POLICY_DEV="1")
        server_env.pop("PYTHONPATH", None)
        server_env.pop("WAVEFRAME_GUARD_ACTION_POLICY_DEV", None)
        for key in ("OPERATOR", "RUNTIME", "WRONG_RUNTIME"):
            server_env["GUARD46_KEY_" + key] = secrets.token_urlsafe(32)
        client_settings = dict(server_env, WAVEFRAME_GUARD_ACTION_POLICY_DEV="1")
        client_settings.pop("WAVEFRAME_CLOUD_ACTION_POLICY_DEV", None)
        ready = scratch / "ready.json"
        runner = scratch / "acceptance.py"
        shutil.copyfile(ROOT / "tools/acceptance/native_cloud_acceptance.py", runner)
        with (output / "server.log").open("w", encoding="utf-8") as log:
            process = subprocess.Popen([str(server_python), str(ROOT / "tools/acceptance/native_cloud_server.py"),
                "--source", str(cloud), "--storage", str(scratch / "storage"), "--ready", str(ready)],
                cwd=scratch, env=server_env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while not ready.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Cloud failed to start; inspect server.log")
                    time.sleep(0.1)
                run([client_python, runner, "--server", ready, "--fixtures", ROOT / "tests/fixtures/action_policy_v4",
                     "--output", output], scratch, client_settings)
            finally:
                process.terminate()
                process.wait(timeout=15)
        assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=cloud).strip()
        (output / "cloud-source.json").write_text(json.dumps({"repository": "https://github.com/Waveframe-Labs/Waveframe-Cloud",
            "commit": CLOUD_COMMIT, "tracked_source_unchanged_before_and_after": True}, indent=2) + "\n")


if __name__ == "__main__":
    main()

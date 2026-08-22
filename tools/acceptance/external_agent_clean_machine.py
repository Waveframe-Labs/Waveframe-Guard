# ---
# title: "External agent clean-machine acceptance"
# filetype: "python"
# type: "acceptance-test"
# domain: "guard-sdk"
# version: "0.15.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REQUIRED_ENVIRONMENT = (
    "WAVEFRAME_CLOUD_URL",
    "WAVEFRAME_CLOUD_ORGANIZATION_ID",
    "WAVEFRAME_CLOUD_API_KEY",
    "WAVEFRAME_RUNTIME_ID",
    "WAVEFRAME_ACTOR_ID",
    "WAVEFRAME_ACTOR_ROLE",
    "WAVEFRAME_AUTHORITY_REF",
)
EXPECTED_OUTPUT = (
    "allowed_decision=allowed",
    "blocked_decision=blocked",
    "mutation_count=1",
    "exactly_once=True",
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the external-agent acceptance from an empty temporary directory."
    )
    parser.add_argument(
        "--install-spec",
        default="waveframe-guard",
        help="pip install spec; defaults to the public waveframe-guard package",
    )
    parser.add_argument("--limit-seconds", type=int, default=300)
    args = parser.parse_args()

    missing = [name for name in REQUIRED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"Missing required environment variables: {', '.join(missing)}")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="waveframe-guard-acceptance-") as raw_directory:
        directory = Path(raw_directory)
        environment = directory / ".venv"
        _run([sys.executable, "-m", "venv", str(environment)], cwd=directory)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        _run([str(python), "-m", "pip", "install", args.install_spec], cwd=directory)
        completed = _run(
            [str(python), "-m", "waveframe_guard.quickstarts.external_agent"],
            cwd=directory,
            capture_output=True,
        )

    elapsed = time.monotonic() - started
    for marker in EXPECTED_OUTPUT:
        if marker not in completed.stdout:
            raise SystemExit(f"Acceptance output missing {marker!r}:\n{completed.stdout}")
    if elapsed > args.limit_seconds:
        raise SystemExit(
            f"Acceptance exceeded {args.limit_seconds} seconds: {elapsed:.1f} seconds"
        )

    print(completed.stdout, end="")
    print(f"clean_machine_seconds={elapsed:.1f}")
    print("repository_checkout_required=False")
    print("ollama_required=False")


def _run(
    command: list[str],
    *,
    cwd: Path,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        text=True,
        capture_output=capture_output,
    )
    if completed.returncode != 0:
        if capture_output:
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
        raise SystemExit(completed.returncode)
    return completed


if __name__ == "__main__":
    main()

"""Prepare a NEW disposable proof directory using the existing mixed fixture."""
import argparse
import json
from pathlib import Path
import shutil
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--codex", type=Path, required=True)
    parser.add_argument("--model", required=True)
    args = parser.parse_args()
    if sys.prefix == sys.base_prefix:
        parser.error("Run prepare with the disposable virtualenv Python from the setup instructions.")
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    for child in ("workspace/generated", "scratch", "trusted", "guard-evidence", "capture"):
        (root / child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / "writer.py", root / "trusted/writer.py")
    shutil.copyfile(source / "probe.py", root / "trusted/probe.py")
    shutil.copyfile(source / "fault_server.py", root / "trusted/fault_server.py")
    shutil.copytree(source.parents[1] / "tests/fixtures/action_policy_release_v4/mixed", root / "trusted/publication")
    (root / "workspace/README.md").write_text(
        "# Addition example\n\n>>> 2 + 3\n6\n", encoding="utf-8")
    config = {"codex": str(args.codex.resolve()), "model": args.model, "python": sys.executable,
              "missing_python": str(root / "trusted/adapter-unavailable.exe"),
              "workspace": str(root / "workspace"), "scratch": str(root / "scratch"),
              "writer": str(root / "trusted/writer.py"), "publication": str(root / "trusted/publication"),
              "probe": str(root / "trusted/probe.py"),
              "guard_evidence": str(root / "guard-evidence"), "capture": str(root / "capture")}
    (root / "connection.json").write_text(json.dumps(config, indent=2))
    print(root / "connection.json")


if __name__ == "__main__":
    main()

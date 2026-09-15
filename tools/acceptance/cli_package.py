"""Exercise the installed console entry point against the existing HTTP fixture."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
    from test_external_agent_quickstart import _serve_cloud_boundary
    import waveframe_guard
    assert Path(waveframe_guard.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    assert waveframe_guard.__version__ == "0.19.0"
    state = {"requests": [], "preservation_count": 0}
    server, url = _serve_cloud_boundary(state)
    cli = Path(sys.executable).parent / ("waveframe-guard-external-agent.exe" if os.name == "nt" else "waveframe-guard-external-agent")
    env = dict(os.environ, WAVEFRAME_CLOUD_URL=url, WAVEFRAME_CLOUD_ORGANIZATION_ID="acme",
               WAVEFRAME_CLOUD_API_KEY="wf_runtime_secret", WAVEFRAME_RUNTIME_ID="budget-agent-runtime",
               WAVEFRAME_ACTOR_ID="budget-agent", WAVEFRAME_ACTOR_ROLE="allocator",
               WAVEFRAME_AUTHORITY_REF="budget-quickstart@1.0.0")
    env.pop("PYTHONPATH", None)
    try:
        with tempfile.TemporaryDirectory(prefix="guard-cli-") as work:
            result = subprocess.run([str(cli)], cwd=work, env=env, text=True, capture_output=True)
        report = {"command": [str(cli)], "exit_code": result.returncode, "stdout": result.stdout,
                  "stderr": result.stderr, "scope": "installed console against HTTP fixture; not native Cloud acceptance",
                  "requests": state["requests"]}
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        assert result.returncode == 0, result.stderr
        for expected in ("allowed_decision=allowed", "blocked_decision=blocked", "mutation_count=1", "exactly_once=True"):
            assert expected in result.stdout, result.stdout
        assert state["preservation_count"] == 2
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

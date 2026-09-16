"""Launch the installed CLI once, with isolated overrides; no custom agent loop."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def toml(value):
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k) + "=" + toml(v) for k, v in value.items()) + "}"
    return json.dumps(value)


def snapshot(root, include_bytes=True):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {"sha256": hashlib.sha256(data).hexdigest()}
            if include_bytes:
                result[path.relative_to(root).as_posix()]["bytes"] = data.hex()
    return result


def command(config, connected=True, fault=None):
    overrides = {
        "model": config["model"], "approval_policy": "never", "windows.sandbox": "elevated",
        "default_permissions": "waveframe", "web_search": "disabled",
        "permissions.waveframe": {"extends": ":read-only", "filesystem": {config["scratch"]: "write"}},
        "project_doc_max_bytes": 0,
    }
    for feature in ("hooks", "plugins", "apps", "multi_agent", "multi_agent_v2", "browser_use",
                    "browser_use_external", "computer_use", "in_app_browser", "code_mode"):
        overrides["features." + feature] = False
    overrides["features.skip_host_skill_discovery"] = True
    overrides["mcp_servers.waveframe"] = {
        "command": config["python"] if connected else config["missing_python"],
        "args": ["-I", config["writer"], "--root", config["workspace"],
                 "--evidence", config["guard_evidence"], "--publication", config["publication"]],
        "cwd": str(Path(config["writer"]).parent),
        "startup_timeout_sec": 15, "tool_timeout_sec": 30,
        "enabled_tools": ["connection_status", "repository_write"],
        "tools": {name: {"approval_mode": "approve"}
                  for name in ("connection_status", "repository_write")},
    }
    if fault:
        overrides["mcp_servers.waveframe"]["args"] = ["-I", str(Path(config["writer"]).with_name("fault_server.py")), fault]
        overrides["mcp_servers.waveframe"]["tool_timeout_sec"] = 1
    args = [config["codex"], "exec", "--ignore-user-config", "--ignore-rules",
            "--skip-git-repo-check", "--json", "-C", config["workspace"]]
    for key, value in overrides.items():
        args += ["-c", key + "=" + toml(value)]
    return args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("prompt", type=Path)
    parser.add_argument("--name", required=True)
    parser.add_argument("--disconnected", action="store_true")
    parser.add_argument("--fault", choices=["malformed", "timeout"])
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    output = Path(config["capture"]) / args.name
    output.mkdir(parents=True, exist_ok=False)
    cmd = command(config, not args.disconnected, args.fault)
    (output / "argv.json").write_text(json.dumps(cmd, indent=2))
    prompt = args.prompt.read_text()
    (output / "prompt.txt").write_text(prompt)
    before = snapshot(Path(config["workspace"]))
    controls_before = snapshot(Path(config["writer"]).parent, False)
    config_before = hashlib.sha256(args.config.read_bytes()).hexdigest()
    started = time.time()
    # Do not retry on lost response, timeout or nonzero exit.
    with (output / "events.jsonl").open("w", encoding="utf-8") as stdout, (output / "stderr.txt").open("w", encoding="utf-8") as stderr:
        result = subprocess.run(cmd + ["-"], input=prompt, text=True, encoding="utf-8",
                                stdout=stdout, stderr=stderr, close_fds=True)
    after = snapshot(Path(config["workspace"]))
    (output / "inspection.json").write_text(json.dumps({
        "exit_code": result.returncode, "elapsed_seconds": round(time.time() - started, 2),
        "before": before, "after": after,
        "changed": sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k)),
        "controls_before": controls_before,
        "controls_after": snapshot(Path(config["writer"]).parent, False),
        "config_before": config_before,
        "config_after": hashlib.sha256(args.config.read_bytes()).hexdigest(),
    }, indent=2))
    print(output)
    print("Exit:", result.returncode, "Changed:", [k for k in before.keys() | after.keys() if before.get(k) != after.get(k)])


if __name__ == "__main__":
    main()

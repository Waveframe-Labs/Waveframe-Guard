"""Launch the unchanged pinned Cloud application as a disposable HTTP dependency."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from wsgiref.simple_server import make_server

CLOUD_COMMIT = "547291b525e2f1d05d92ed65b6058c4ca91588a8"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--storage", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    args = parser.parse_args()
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source).decode().strip() == CLOUD_COMMIT
    assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=args.source).strip()
    sys.path.insert(0, str(args.source.resolve()))
    from api.app import CanonicalRequestTargetHandler, create_app
    from api.auth import hash_api_key
    from config import CloudConfig
    from scripts.check_action_policy_dependencies import check

    keys = []
    scopes = ["authorities:write", "authorities:read", "audit:write", "audit:read", "replay:read",
              "receipts:read", "registry:read", "contracts:read", "continuity:write", "continuity:read"]
    for name, owner in (("operator", "operator"), ("runtime", "runtime:assigned-runtime"),
                        ("wrong-runtime", "runtime:other-runtime")):
        keys.append({"key_id": name, "organization_id": "guard46", "key_hash": hash_api_key(os.environ["GUARD46_KEY_" + name.upper().replace("-", "_")]),
                     "api_key_owner": owner, "scopes": scopes, "status": "active"})
    app = create_app(config=CloudConfig(storage_root=args.storage, api_key_source="filesystem",
        host="127.0.0.1", port=8000, runtime_mode="development", background_jobs_enabled=False), api_keys=keys)
    with make_server("127.0.0.1", 0, app, handler_class=CanonicalRequestTargetHandler) as server:
        args.ready.write_text(json.dumps({"url": f"http://127.0.0.1:{server.server_port}",
            "cloud_commit": CLOUD_COMMIT, "source_clean": True, "dependencies": check()}), encoding="utf-8")
        server.serve_forever()


if __name__ == "__main__":
    main()

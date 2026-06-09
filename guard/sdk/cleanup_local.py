from __future__ import annotations

import argparse
import json
from pathlib import Path

from guard.runtime.organization import PersistentOrganizationalRuntime


def main() -> None:
    parser = argparse.ArgumentParser(description="Clean Guard local runtime development state.")
    parser.add_argument(
        "--workspace",
        default=".guard-local",
        help="Guard local workspace to clean. Defaults to .guard-local.",
    )
    args = parser.parse_args()
    result = PersistentOrganizationalRuntime(Path(args.workspace), initialize=False).cleanup_dev_state()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

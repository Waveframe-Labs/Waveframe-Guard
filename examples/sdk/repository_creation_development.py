"""Create one file through a verified, development-gated repository authority.

Set WAVEFRAME_GUARD_ACTION_POLICY_DEV=1 and WAVEFRAME_LEDGER_ACTION_POLICY_DEV=1
in the invoking environment, and install the exact requirements in
.github/requirements/action-policy-development.txt. Parents must already exist.
"""

import argparse
import json
from pathlib import Path

from waveframe_guard import Guard, RepositoryBoundaryError
from waveframe_guard.authority.adapters import LocalRegistryResolver


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--publication-root", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--authority", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--role", default="repository-maintainer")
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args()
    guard = Guard.local(
        repository_root=args.repository_root.resolve(), workspace=args.evidence_root,
        authority=args.authority,
        authority_resolver=LocalRegistryResolver(registry_path=args.registry.resolve(),
                                                workspace_root=args.publication_root.resolve()),
        actor_identity={"id": "local-agent", "type": "agent", "role": args.role},
    )
    try:
        @guard.repository_tool(action="create", target="path", return_result=True)
        def create_file(path, content):
            return path.create_bytes(content)

        try:
            result = create_file(args.target, b"Created through Guard.\n")
            print(json.dumps(result["evaluation"]["execution_attestation"], indent=2))
        except RepositoryBoundaryError as error:
            print(json.dumps(error.evaluation["execution_attestation"], indent=2))
            raise
    finally:
        guard.close()


if __name__ == "__main__":
    main()

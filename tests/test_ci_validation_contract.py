from __future__ import annotations

import email
from pathlib import Path
from pathlib import PurePosixPath

import pytest

from tools import validate_repository
from tools.acceptance import package_acceptance


APPROVED_RUNTIME_DEPENDENCIES = [
    "cricore",
    "cricore-proposal-normalizer",
    "governance-ledger>=0.7.0,<0.9.0",
    "requests",
]


def test_repository_contract_accepts_exact_ledger_runtime_dependencies():
    failures = []

    validate_repository._validate_runtime_dependencies(
        APPROVED_RUNTIME_DEPENDENCIES,
        failures,
    )

    assert failures == []


@pytest.mark.parametrize(
    "dependencies",
    [
        [*APPROVED_RUNTIME_DEPENDENCIES, "unapproved-package>=1"],
        [
            "cricore",
            "cricore-proposal-normalizer",
            "governance-ledger[guard]>=0.7.0,<0.9.0",
            "requests",
        ],
    ],
)
def test_repository_contract_rejects_injected_dependency_or_ledger_guard_extra(dependencies):
    failures = []

    validate_repository._validate_runtime_dependencies(dependencies, failures)

    assert any("dependency contract changed unexpectedly" in failure for failure in failures)


def test_repository_contract_rejects_unapproved_schema_file():
    json_paths = [PurePosixPath(path) for path in validate_repository.APPROVED_JSON_FILES]
    json_paths.append(PurePosixPath("contracts/unapproved-schema.json"))
    failures = []

    validate_repository._validate_json_contract(json_paths, failures)

    assert failures == [
        "unapproved JSON/schema files are tracked: ['contracts/unapproved-schema.json']"
    ]


def test_repository_contract_rejects_private_path():
    failures = []

    validate_repository._validate_paths(
        [PurePosixPath("temp/private-authority.json")],
        failures,
    )

    assert failures == [
        "forbidden private, cache, build, or environment path is tracked: "
        "temp/private-authority.json"
    ]


def test_package_metadata_contract_rejects_injected_dependency():
    metadata = email.message_from_string(
        "\n".join(
            [
                "Name: waveframe-guard",
                "Version: 0.15.0",
                "Requires-Python: >=3.10",
                *(f"Requires-Dist: {dependency}" for dependency in APPROVED_RUNTIME_DEPENDENCIES),
                "Requires-Dist: unapproved-package>=1",
                "",
            ]
        )
    )

    with pytest.raises(AssertionError, match="runtime dependency metadata differs"):
        package_acceptance._validate_metadata(metadata, "0.15.0", "test package")


def test_ci_binds_v3_acceptance_to_merged_ledger_commit():
    workflow = Path(".github/workflows/guard-validation.yml").read_text(encoding="utf-8")

    assert "2b9a6b0a239d0e834d1bb42cd2efa30abe299e70" in workflow
    assert "tools/acceptance/ledger_v3_clean_wheel.py" in workflow

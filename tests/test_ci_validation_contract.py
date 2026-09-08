from __future__ import annotations

import email
from pathlib import Path
from pathlib import PurePosixPath

import pytest

from tools import validate_repository
from tools.acceptance import package_acceptance


APPROVED_RUNTIME_DEPENDENCIES = [
    "cricore>=0.13.0,<0.15.0",
    "cricore-proposal-normalizer>=0.2.0,<0.3.0",
    "governance-ledger>=0.7.0,<0.9.0",
    "requests>=2.33.0,<3.0.0",
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
            "cricore>=0.13.0,<0.15.0",
            "cricore-proposal-normalizer>=0.2.0,<0.3.0",
            "governance-ledger[guard]>=0.7.0,<0.9.0",
            "requests>=2.33.0,<3.0.0",
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


def test_ci_binds_compatibility_to_exact_cri_candidate():
    workflow = Path(".github/workflows/guard-validation.yml").read_text(encoding="utf-8")
    runner = Path("tools/acceptance/dependency_matrix.py").read_text(encoding="utf-8")

    assert "411dfaa976fd4b37efc5fd3e39076edcd3603e1b" in workflow
    assert "411dfaa976fd4b37efc5fd3e39076edcd3603e1b" in runner
    assert "--profile minimum" in workflow and "--profile candidate" in workflow
    assert "ledger_v3_clean_wheel.RUNNER" in runner


@pytest.mark.parametrize("position", range(4))
@pytest.mark.parametrize("change", ["unbounded", "no_lower", "no_upper", "widened"])
def test_repository_contract_rejects_dependency_bound_removal_or_widening(position, change):
    dependencies = APPROVED_RUNTIME_DEPENDENCIES.copy()
    name, bounds = dependencies[position].split(">=", 1)
    lower, upper = bounds.split(",<")
    dependencies[position] = {
        "unbounded": name,
        "no_lower": f"{name}<{upper}",
        "no_upper": f"{name}>={lower}",
        "widened": f"{name}>={lower},<99.0.0",
    }[change]
    failures = []
    validate_repository._validate_runtime_dependencies(dependencies, failures)
    assert any("dependency contract changed unexpectedly" in failure for failure in failures)
    metadata = email.message_from_string("\n".join([
        "Name: waveframe-guard", "Version: 0.18.0", "Requires-Python: >=3.10",
        *(f"Requires-Dist: {dependency}" for dependency in dependencies), "",
    ]))
    with pytest.raises(AssertionError, match="runtime dependency metadata differs"):
        package_acceptance._validate_metadata(metadata, "0.18.0", "test package")

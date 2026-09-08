# ---
# title: "Guard Public Export Regression Test"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.18.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Apache-2.0"
# ai_assisted: "partial"
# ---

import re
from pathlib import Path

from waveframe_guard import Guard, __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.18.0"


def test_release_metadata_matches_v0180_release():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert 'version = "0.18.0"' in pyproject
    assert 'version: "0.18.0"' in citation
    assert 'date-released: "2026-09-08"' in citation
    assert "## [0.18.0] - 2026-09-08" in changelog
    assert "## [0.17.0] - 2026-09-04" in changelog
    assert "## [0.16.1] - 2026-09-01" in changelog
    assert "## [0.16.0] - 2026-09-01" in changelog
    assert "## [0.15.0] - 2026-08-21" in changelog
    assert "## [0.14.0] - 2026-08-10" in changelog
    assert changelog.index("## [Unreleased]") < changelog.index("## [0.18.0]")


# Current release content is distinct from the factual historical changelog.
# These checks cover known release statements, not arbitrary English semantics.
RELEASE_SURFACES = (
    "README.md", "RELEASE_NOTES.md", "CHANGELOG.md", "SECURITY.md",
    "docs/LICENSING.md", "docs/architecture/REPOSITORY_WORKSPACE.md",
    "docs/architecture/CLOUD_AUTHORITY_PUBLICATION_PROTOCOL.md",
    "docs/getting-started/README.md",
    "docs/getting-started/STRICT_EXECUTION_MIGRATION.md",
    "docs/security/ISSUE_31.md", "pyproject.toml", "CITATION.cff",
    "waveframe_guard/__init__.py", "guard/sdk/guard.py",
    "examples/external_agent_quickstart.py", "examples/quickstart_guard.py",
    "tools/acceptance/external_agent_clean_machine.py",
    "tools/acceptance/ledger_v2_clean_wheel.py",
    "tools/acceptance/ledger_v3_clean_wheel.py",
)
CLOUD_SURFACES = (
    "README.md", "RELEASE_NOTES.md", "CHANGELOG.md",
    "docs/getting-started/README.md",
    "docs/architecture/CLOUD_AUTHORITY_PUBLICATION_PROTOCOL.md",
)


def _current_release_text(path):
    text = (REPO_ROOT / path).read_text(encoding="utf-8")
    if path == "CHANGELOG.md":
        text = text.split("## [0.18.0]", 1)[1].split("## [0.17.0]", 1)[0]
    return " ".join(text.replace("`", "").replace("**", "").split())


def test_v0180_cloud_source_support_is_distinct_from_hosted_availability():
    required = (
        "Guard 0.18.0 can verify matching Ledger v2 and v3 publication envelopes.",
        "Waveframe Cloud source support for atomic v2/v3 publication serving merged in Cloud PR #135.",
        "Hosted translation backend and Console workflow source merged in PRs #136 and #140.",
        "At the Guard 0.18.0 release date, those Cloud changes had not yet been released or deployed to the hosted service.",
        "Guard does not claim hosted translation availability at that date.",
    )
    for path in CLOUD_SURFACES:
        text = _current_release_text(path)
        for claim in required:
            assert claim in text, (path, claim)

    # Required correct text must not mask stale or contradictory current claims.
    for path in RELEASE_SURFACES:
        text = _current_release_text(path)
        for stale in ("PR #133", "Cloud implementation not yet shipped",
                      "Hosted v3 serving requires an additional Cloud update",
                      "Serving v3 requires a separately reviewed Cloud change"):
            assert stale.lower() not in text.lower(), (path, stale)
        assert re.search(
            r"hosted (?:Cloud )?(?:translation|v2|v3|v2/v3) (?:is|are) (?:now )?available",
            text, re.IGNORECASE,
        ) is None, path


def test_v0180_artifacts_use_final_release_state():
    for path in RELEASE_SURFACES:
        text = _current_release_text(path).lower()
        for stale in ("prepared release", "prepared security release",
                      "publication is pending", "publication remains pending",
                      "publication pending", "not yet published",
                      "after 0.18.0 publication", "during release review",
                      "0.18.0 release candidate", "must be published",
                      "must be publishable", "the release is prepared"):
            assert stale not in text, (path, stale)
    assert "Current release: 0.18.0." in _current_release_text("README.md")
    for path in ("README.md", "RELEASE_NOTES.md", "docs/getting-started/README.md"):
        assert "pip install waveframe-guard==0.18.0" in _current_release_text(path)


def test_v0180_ledger_extra_requires_direct_guard_installation():
    required = (
        "Published governance-ledger==0.8.0 has a [guard] extra pinned to waveframe-guard==0.17.0.",
        "Ledger's base package remains compatible with Guard 0.18.0 through governance-ledger>=0.7.0,<0.9.0.",
        "Install waveframe-guard==0.18.0 directly for this release rather than relying on governance-ledger[guard]==0.8.0; that extra does not install Guard 0.18.0.",
    )
    for path in ("README.md", "RELEASE_NOTES.md", "docs/getting-started/README.md"):
        text = _current_release_text(path)
        for claim in required:
            assert claim in text, (path, claim)
        assert "governance-ledger[guard]==0.7.0" not in text, path
        assert re.search(
            r"(?:that extra|Ledger(?:'s)? 0\.8(?:\.0)?(?: \[guard\])? extra) "
            r"(?:already )?(?:installs|supplies) (?:Guard|waveframe-guard==) ?0\.18(?:\.0)?",
            text, re.IGNORECASE,
        ) is None, path

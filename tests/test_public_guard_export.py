# ---
# title: "Guard Public Export Regression Test"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.16.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

from pathlib import Path

from waveframe_guard import Guard, __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.16.0"


def test_release_metadata_matches_v0160_release():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert 'version = "0.16.0"' in pyproject
    assert 'version: "0.16.0"' in citation
    assert 'date-released: "2026-09-01"' in citation
    assert "## [0.16.0] - 2026-09-01" in changelog
    assert "## [0.15.0] - 2026-08-21" in changelog
    assert "## [0.14.0] - 2026-08-10" in changelog
    assert changelog.index("## [Unreleased]") < changelog.index("## [0.16.0]")

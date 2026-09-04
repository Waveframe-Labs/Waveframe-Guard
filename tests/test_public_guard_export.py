# ---
# title: "Guard Public Export Regression Test"
# filetype: "python"
# type: "test"
# domain: "guard-sdk"
# version: "0.17.0"
# status: "Active"
# author:
#   name: "Waveframe Labs"
# license: "Proprietary"
# ai_assisted: "partial"
# ---

import re
from pathlib import Path

from waveframe_guard import Guard, __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.17.0"


def test_release_metadata_matches_v0170_release():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert 'version = "0.17.0"' in pyproject
    assert 'version: "0.17.0"' in citation
    assert 'date-released: "2026-09-04"' in citation
    assert "## [0.17.0] - 2026-09-04" in changelog
    assert "## [0.16.1] - 2026-09-01" in changelog
    assert "## [0.16.0] - 2026-09-01" in changelog
    assert "## [0.15.0] - 2026-08-21" in changelog
    assert "## [0.14.0] - 2026-08-10" in changelog
    assert changelog.index("## [Unreleased]") < changelog.index("## [0.17.0]")


def test_v0170_release_content_does_not_claim_hosted_v2_or_v3_availability():
    release_surfaces = {
        path: (REPO_ROOT / path).read_text(encoding="utf-8")
        for path in (
            "README.md",
            "CHANGELOG.md",
            "RELEASE_NOTES.md",
            "docs/getting-started/README.md",
        )
    }
    required_claims = (
        "Guard 0.17.0 can parse and verify matching v2 and v3 publication envelopes",
        "Current released/hosted Cloud does not yet serve the complete atomic v2 or v3 publication path",
        "Cloud PR #133 remains the pending v2 server implementation",
        "Hosted v3 serving requires an additional Cloud update",
    )
    premature_availability_claim = re.compile(
        r"hosted (?:Cloud )?(?:v2|v3|v2/v3) (?:is|are) (?:now )?available",
        re.IGNORECASE,
    )

    for path, content in release_surfaces.items():
        normalized = " ".join(content.split())
        assert all(claim in normalized for claim in required_claims), path
        assert premature_availability_claim.search(normalized) is None, path
        for sentence in re.split(r"(?<=[.!?])\s+", normalized):
            hosted_serving_claim = (
                "hosted cloud" in sentence.lower()
                and ("v2" in sentence.lower() or "v3" in sentence.lower())
                and "serve" in sentence.lower()
            )
            if hosted_serving_claim:
                assert "does not" in sentence.lower(), (path, sentence)

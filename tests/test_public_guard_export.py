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
import subprocess

import pytest

from tools.acceptance import package_acceptance
from pathlib import Path

from waveframe_guard import Guard, __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_guard_export_is_sdk_facade():
    assert Guard.__name__ == "Guard"


def test_public_version_matches_release():
    assert __version__ == "0.19.0"


def test_release_metadata_matches_v0190_candidate():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    citation = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert 'version = "0.19.0"' in pyproject
    assert 'version: "0.19.0"' in citation
    assert 'date-released:' not in citation
    assert '## [0.19.0] - Unreleased candidate' in changelog
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


def test_candidate_docs_keep_publication_and_extra_gated():
    for path in ("README.md", "RELEASE_NOTES.md", "docs/getting-started/README.md"):
        text = _current_release_text(path).lower()
        assert "0.19.0" in text and "unreleased" in text
        assert "publication" in text
    for path in ("README.md", "docs/getting-started/README.md"):
        text = _current_release_text(path)
        assert "pip install waveframe-guard==0.19.0" in text
        assert "Do not advertise Ledger's" in text


def test_release_quickstart_urls_match_package_and_example_versions():
    project = package_acceptance.tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]
    release = project["version"]
    assert release == __version__ == "0.19.0"
    assert f"## [{release}]" in (REPO_ROOT / "CHANGELOG.md").read_text()
    prefix = "https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Guard/"
    # Audit tracked customer surfaces only, preserving ignored/user-owned files.
    # No development-only executable downloads are retained. Adding such a flow
    # requires a separately reviewed development surface, never this release path.
    paths = subprocess.check_output(
        ["git", "ls-files", "*.md", "examples/*.py", "tools/acceptance/*.py", "*.toml", "*.cff"],
        cwd=REPO_ROOT, text=True,
    ).splitlines()
    for name in paths:
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        required = name in ("README.md", "docs/getting-started/README.md")
        package_acceptance._validate_quickstart_downloads(text, release, name, require_example=required)
        for ref, example in re.findall(re.escape(prefix) + r"([^/\s]+)/examples/([A-Za-z0-9_./-]+\.py)", text):
            assert ref == f"v{release}", name
            version = re.search(r'^# version: "([^"]+)"$',
                                (REPO_ROOT / "examples" / example).read_text(), re.MULTILINE)
            assert version and version.group(1) == release, (name, example)
        # The branding image is a non-executable display asset, not a download
        # paired with a pinned SDK. No raw main-branch script URL is allowed.
        assert re.search(r"https://raw\.githubusercontent\.com/[^\s]+/main/[^\s]+\.(?:py|ps1|sh)\b",
                         text) is None, name


@pytest.mark.parametrize("ref", ["main", "v0.17.0", "v0.19.0"])
def test_release_download_contract_rejects_mutable_or_mismatched_examples(ref):
    text = (
        "pip install waveframe-guard==0.19.0\n"
        "https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Guard/"
        f"{ref}/examples/external_agent_quickstart.py"
    )
    if ref == "v0.19.0":
        package_acceptance._validate_quickstart_downloads(text, "0.19.0", "release", require_example=True)
    else:
        with pytest.raises(AssertionError, match="must use v0.19.0"):
            package_acceptance._validate_quickstart_downloads(text, "0.19.0", "release", require_example=True)


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("surface", ["README.md", "docs/getting-started/README.md", "metadata"])
def test_packaged_quickstart_rejects_main_example_in_docs_and_long_description(tmp_path, kind, surface):
    import io
    import tarfile
    import zipfile
    from test_licensing import archive_files

    files, _ = archive_files(kind)
    if surface == "metadata":
        name = "waveframe_guard-0.19.0.dist-info/METADATA" if kind == "wheel" else "PKG-INFO"
    else:
        prefix = "waveframe_guard-0.19.0.data/data/share/doc/waveframe-guard/" if kind == "wheel" else ""
        name = prefix + surface
    old = b"Waveframe-Guard/v0.19.0/examples/external_agent_quickstart.py"
    assert old in files[name]
    files[name] = files[name].replace(old, b"Waveframe-Guard/main/examples/external_agent_quickstart.py")
    if kind == "wheel":
        path = tmp_path / "bad.whl"
        with zipfile.ZipFile(path, "w") as archive:
            for member, value in files.items():
                archive.writestr(member, value)
        inspect = package_acceptance._inspect_wheel
    else:
        path = tmp_path / "bad.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for member, value in files.items():
                info = tarfile.TarInfo("waveframe_guard-0.19.0/" + member)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        inspect = package_acceptance._inspect_sdist
    with pytest.raises(AssertionError, match="must use v0.19.0"):
        inspect(path, "0.19.0")

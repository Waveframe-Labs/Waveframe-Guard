"""Apache-2.0 metadata, notices, and customer-facing licensing regressions."""
from __future__ import annotations

import email
import io
from pathlib import Path
import re
import tarfile
import zipfile

import pytest

from tools import validate_repository
from tools.acceptance import package_acceptance
from tools.license_contract import validate_document, validate_license_metadata, validate_notices


ROOT = Path(__file__).resolve().parents[1]


def metadata_text():
    return "\n".join([
        "Metadata-Version: 2.4", "Name: waveframe-guard", "Version: 0.17.0",
        "Requires-Python: >=3.10", "License-Expression: Apache-2.0",
        "License-File: LICENSE", "License-File: NOTICE",
        *(f"Requires-Dist: {r}" for r in package_acceptance.EXPECTED_RUNTIME_REQUIREMENTS),
        "", "",
    ])


def test_repository_licensing_contract():
    failures = []
    tracked = validate_repository._tracked_files(failures)
    validate_repository._validate_licensing(tracked, failures)
    validate_repository._validate_metadata(failures)
    assert failures == []
    for path in tracked:
        if path.suffix == ".py":
            text = (ROOT / path).read_text(encoding="utf-8")
            for header in re.findall(r"^#\s*license:.*$", text, re.MULTILINE):
                validate_document(header, str(path))


@pytest.mark.parametrize("text", [
    'license = "LicenseRef-Proprietary"', 'license: "Proprietary"',
    "All rights reserved.", "This software is proprietary and confidential.",
    "Waveframe Guard Core SDK is permission-only.",
    "No part may be copied without explicit permission from Waveframe Labs.",
])
def test_documentation_rejects_conflicting_sdk_terms(text):
    with pytest.raises(AssertionError, match="conflicting SDK licensing"):
        validate_document(text, "customer documentation")


def test_separate_commercial_products_do_not_restrict_sdk_license():
    validate_document("Guard Inspector is a separately distributed proprietary product.", "boundary")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for product in ("Cloud", "Console", "hosted translation", "managed evidence operations",
                    "Guard Inspector", "Ledger Workspace", "enterprise identity/integrations", "support"):
        assert product in readme
    assert "Commercial use, modification, and redistribution" in readme
    assert "do not restrict Apache-2.0 rights to any SDK code included here" in readme


@pytest.mark.parametrize("expression", ["LicenseRef-Proprietary", "MIT", ""])
def test_metadata_rejects_missing_or_incorrect_license(expression):
    metadata = email.message_from_string(metadata_text().replace("Apache-2.0", expression))
    with pytest.raises(AssertionError, match="License-Expression: Apache-2.0"):
        package_acceptance._validate_metadata(metadata, "0.17.0", "distribution")


@pytest.mark.parametrize("name", ["LICENSE", "NOTICE"])
def test_metadata_requires_both_license_files(name):
    metadata = email.message_from_string(metadata_text().replace(f"License-File: {name}\n", ""))
    with pytest.raises(AssertionError, match="License-File"):
        validate_license_metadata(metadata, "distribution")


def test_notices_cannot_be_truncated_or_add_restrictions():
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    notice_text = (ROOT / "NOTICE").read_text(encoding="utf-8")
    validate_notices(license_text, notice_text)
    with pytest.raises(AssertionError, match="canonical Apache"):
        validate_notices(license_text[:500], notice_text)
    with pytest.raises(AssertionError, match="only the approved"):
        validate_notices(license_text, notice_text + "Commercial use forbidden.\n")


def archive_files(kind):
    files = {name: b"" for name in (
        package_acceptance.REQUIRED_WHEEL_FILES if kind == "wheel"
        else package_acceptance.REQUIRED_SDIST_FILES
    )}
    prefix = "waveframe_guard-0.17.0.dist-info/" if kind == "wheel" else ""
    files[prefix + ("METADATA" if kind == "wheel" else "PKG-INFO")] = metadata_text().encode()
    license_prefix = prefix + "licenses/" if kind == "wheel" else ""
    for name in ("LICENSE", "NOTICE"):
        files[license_prefix + name] = (ROOT / name).read_bytes()
    return files, license_prefix


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
@pytest.mark.parametrize("missing", [None, "LICENSE", "NOTICE"])
def test_archive_checks_require_both_packaged_notices(tmp_path, kind, missing):
    files, prefix = archive_files(kind)
    if missing:
        del files[prefix + missing]
    if kind == "wheel":
        path = tmp_path / "test.whl"
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        inspect = package_acceptance._inspect_wheel
    else:
        path = tmp_path / "test.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, value in files.items():
                info = tarfile.TarInfo("waveframe_guard-0.17.0/" + name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        inspect = package_acceptance._inspect_sdist
    if missing:
        with pytest.raises(AssertionError, match="LICENSE|NOTICE"):
            inspect(path, "0.17.0")
    else:
        assert inspect(path, "0.17.0") == len(files)

"""Licensing regression checks for repository text and distribution notices."""
from __future__ import annotations

import hashlib
import re


# Canonical https://www.apache.org/licenses/LICENSE-2.0.txt, normalized to LF.
APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
NOTICE_TEXT = "Waveframe Guard Core SDK\nCopyright 2026 Waveframe Labs\n"
LICENSE_FILES = {"LICENSE", "NOTICE"}
CONFLICTING_LANGUAGE = (
    r"LicenseRef-Proprietary",
    r"license\s*[:=]\s*[\"']?Proprietary\b",
    r"all\s+rights\s+reserved",
    r"(?:this\s+(?:software|sdk|repository)|(?:waveframe\s+)?guard(?:\s+core)?(?:\s+sdk)?)"
    r"\s+(?:is|remains)\s+(?:proprietary|confidential|permission[- ]only)",
    r"without\s+(?:(?:explicit|prior|written)\s+)*(?:permission|consent)\s+from\s+Waveframe",
)


def validate_notices(license_text: str, notice_text: str) -> None:
    canonical = license_text.replace("\r\n", "\n").encode("utf-8")
    if hashlib.sha256(canonical).hexdigest() != APACHE_SHA256:
        raise AssertionError("LICENSE must contain the complete canonical Apache-2.0 text")
    if notice_text.replace("\r\n", "\n") != NOTICE_TEXT:
        raise AssertionError("NOTICE must contain only the approved Waveframe attribution")


def validate_license_metadata(metadata, label: str) -> None:
    if metadata.get("License-Expression") != "Apache-2.0":
        raise AssertionError(f"{label} must report License-Expression: Apache-2.0")
    if metadata.get("License") is not None:
        raise AssertionError(f"{label} must use SPDX licensing metadata, not the legacy License field")
    files = metadata.get_all("License-File", [])
    if len(files) != 2 or set(files) != LICENSE_FILES:
        raise AssertionError(f"{label} must declare License-File for LICENSE and NOTICE")


def validate_document(text: str, label: str) -> None:
    # Separately distributed commercial products can be described as proprietary.
    # Reject statements that withdraw the repository SDK's Apache rights.
    for pattern in CONFLICTING_LANGUAGE:
        if re.search(pattern, text, re.IGNORECASE):
            raise AssertionError(f"{label} contains conflicting SDK licensing language")

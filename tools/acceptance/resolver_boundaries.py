"""Exercise pip's resolver offline; synthetic wheels contain metadata, not code.

These checks establish resolver boundaries only. Behavioral compatibility is
validated separately against real distributions and the exact CRI candidate.
"""
from __future__ import annotations

import argparse
import email
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


VERSIONS = {
    "cricore": ("0.12.0", "0.13.0", "0.14.0", "0.15.0"),
    "cricore-proposal-normalizer": ("0.1.0", "0.2.0", "0.3.0"),
    "governance-ledger": ("0.6.0", "0.7.0", "0.8.0", "0.9.0"),
    "requests": ("2.32.0", "2.33.0", "2.34.2", "3.0.0"),
}


def synthetic_wheel(directory: Path, name: str, version: str) -> None:
    normalized = name.replace("-", "_")
    info = f"{normalized}-{version}.dist-info"
    with zipfile.ZipFile(directory / f"{normalized}-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(f"{info}/METADATA", f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n")
        archive.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\nGenerator: guard-resolver-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(f"{info}/RECORD", "")


def check(wheel: Path, *, historical: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-resolver-") as temporary:
        root = Path(temporary)
        for name, versions in VERSIONS.items():
            for version in versions:
                synthetic_wheel(root, name, version)

        def resolve(specs: list[str], succeeds: bool) -> dict:
            report = root / "report.json"
            report.unlink(missing_ok=True)
            command = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed",
                       "--no-index", "--no-cache-dir", "--find-links", str(root),
                       "--report", str(report), str(wheel.resolve()), *specs]
            result = subprocess.run(command, text=True, capture_output=True)
            output = result.stdout + result.stderr
            if succeeds:
                assert result.returncode == 0, output
                selected = {item["metadata"]["name"]: item["metadata"]["version"]
                            for item in json.loads(report.read_text())["install"]}
                print(f"resolver accepted {specs or ['unconstrained']}: {selected}")
                return selected
            assert result.returncode != 0, output
            assert "ResolutionImpossible" in output, output
            assert not report.exists(), output
            print(f"resolver rejected {specs}: ResolutionImpossible (before installation)")
            return {}

        if historical:
            with zipfile.ZipFile(wheel) as archive:
                metadata = email.message_from_bytes(archive.read(next(
                    name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))))
            assert metadata["Version"] == "0.17.0"
            print("Published Guard 0.17.0 Requires-Dist:", metadata.get_all("Requires-Dist"))
            selected = resolve([], True)
            assert selected["cricore"] == "0.15.0", selected
            print("Historical exposure reproduced with actual published Guard and synthetic future CRI.")
            return

        for cri, ledger, requests in (("0.13.0", "0.7.0", "2.33.0"),
                                      ("0.14.0", "0.8.0", "2.34.2")):
            resolve([f"cricore=={cri}", f"governance-ledger=={ledger}",
                     "cricore-proposal-normalizer==0.2.0", f"requests=={requests}"], True)
        for name, versions in VERSIONS.items():
            for version in (versions[0], versions[-1]):
                resolve([f"{name}=={version}"], False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--historical", action="store_true", help="Reproduce published 0.17.0 exposure")
    args = parser.parse_args()
    check(args.wheel, historical=args.historical)

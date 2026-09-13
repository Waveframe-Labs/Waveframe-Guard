"""Fetch and verify issue #25's immutable Guard evidence and per-cell wheels."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

EVIDENCE = "e6008345c9891ec6ffb5088f38177022e3cef4aa"
GUARD = "0161ef8a52e052d1bc1366cdc93ce13a9bd535ed"
COMPILER = "ae590dee058d3481e384dea850d5b7d980f533ff"
BASE_URL = f"https://raw.githubusercontent.com/Waveframe-Labs/Waveframe-Guard/{EVIDENCE}/"
PINS = {
    "handoff.json": "832ebc40b13118e1a34cc4e10d7df0a7dfccc7b436b4ca894d501f9248e1c940",
    "SHA256SUMS": "d13ef3d40cd6f84412753216259930c810422694c73f2447fcc696684d4e8bed",
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fetch(root, name, digest):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with urllib.request.urlopen(BASE_URL + name, timeout=120) as response:
            path.write_bytes(response.read())
    assert sha256(path) == digest, f"immutable evidence hash mismatch: {name}"
    return path


def verify(root, cell):
    for name, digest in PINS.items():
        assert sha256(root / name) == digest, name
    handoff = json.loads((root / "handoff.json").read_text(encoding="utf-8"))
    assert handoff["head"] == GUARD and handoff["compiler_head"] == COMPILER
    os_name, python = cell.split("-", 1)
    assert os_name in ("windows", "ubuntu") and python in ("3.10", "3.14")
    name = f"final-action-policy-{os_name}-latest-{python}.zip"
    digest = handoff["archive_sha256"][name]
    sums = dict((line.split("  ", 1)[1], line.split("  ", 1)[0])
                for line in (root / "SHA256SUMS").read_text().splitlines())
    assert sums[f"artifacts/{name}"] == digest
    archive_path = root / "artifacts" / name
    assert sha256(archive_path) == digest
    dest = root / cell
    dest.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            path = Path(member)
            assert not path.is_absolute() and ".." not in path.parts
            assert (dest / path).resolve().is_relative_to(dest.resolve())
        archive.extractall(dest)
    manifest = json.loads((dest / "package/guard-candidate.json").read_text())
    assert manifest == handoff["cells"][cell]["guard_manifest"]
    assert manifest["source_commit"] == GUARD
    assert (dest / "guard-head.txt").read_text().strip() == GUARD
    build = json.loads((dest / "package/build-provenance.json").read_text())
    assert build["source_commit"] == GUARD and build["clean_tracked_checkout"]
    guard = dest / "package" / manifest["wheel"]
    assert sha256(guard) == manifest["wheel_sha256"]
    with zipfile.ZipFile(guard) as wheel:
        for member in wheel.namelist():
            if member.startswith(("waveframe_guard/", "guard/")) and not member.endswith("/"):
                assert hashlib.sha256(wheel.read(member)).hexdigest() == build["tracked_files_sha256"][member], member
    base = json.loads((dest / "ledger-extra/retained-base/acceptance.json").read_text())
    compiler = base["compiler_wheel"]
    assert compiler["origin"]["url"] == "https://github.com/Waveframe-Labs/cricore-contract-compiler.git"
    assert compiler["origin"]["vcs_info"] == {
        "vcs": "git", "commit_id": COMPILER, "requested_revision": COMPILER}
    compiler_path = dest / "ledger-extra/retained-base" / compiler["filename"]
    assert sha256(compiler_path) == compiler["sha256"] == handoff["cells"][cell]["combined_package_sha256"][compiler_path.name]
    return {"evidence_commit": EVIDENCE, "cell": cell, "archive": str(archive_path.resolve()),
            "archive_sha256": digest, "guard_manifest": manifest,
            "guard_wheel": str(guard.resolve()), "compiler_wheel": str(compiler_path.resolve()),
            "compiler_build": compiler, "historical_combined_status": "failed",
            "historical_guard_install_upgrade": handoff["cells"][cell]["guard_entry_upgrade"],
            "release_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    for name, digest in PINS.items():
        fetch(root, name, digest)
    handoff = json.loads((root / "handoff.json").read_text())
    os_name, python = args.cell.split("-", 1)
    name = f"final-action-policy-{os_name}-latest-{python}.zip"
    fetch(root, "artifacts/" + name, handoff["archive_sha256"][name])
    result = verify(root, args.cell)
    (root / "verified-inputs.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

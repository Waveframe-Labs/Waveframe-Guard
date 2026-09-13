"""Retain the locally built VCS wheel with its pip origin and archive hash."""
import hashlib
import json
from pathlib import Path
import shutil


def record_cached_compiler(cache: Path, output: Path) -> dict:
    matches = []
    for wheel in cache.rglob("cricore_contract_compiler-0.5.0-*.whl"):
        origin_path = wheel.parent / "origin.json"
        if not origin_path.is_file():
            continue
        origin = json.loads(origin_path.read_text(encoding="utf-8"))
        if (origin.get("url") == "https://github.com/Waveframe-Labs/cricore-contract-compiler.git"
                and origin.get("vcs_info", {}).get("commit_id") == "ae590dee058d3481e384dea850d5b7d980f533ff"):
            matches.append((wheel, origin))
    assert len(matches) == 1, matches
    wheel, origin = matches[0]
    shutil.copyfile(wheel, output / wheel.name)
    return {"filename": wheel.name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "origin": origin, "kind": "locally built pip-cached VCS wheel",
            "supplied_archive_hash_verified": False,
            "note": "Archive hashes can differ across builds; complete compiled fixture outputs must remain identical."}

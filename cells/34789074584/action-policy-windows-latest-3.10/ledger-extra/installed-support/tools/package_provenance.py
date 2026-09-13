"""Acceptance-only provenance checks shared by suites and package entry points.

Archive expectations come from the harness's verified immutable build evidence,
not from package metadata or a file URL supplied by the installation itself.
"""
import hashlib
import importlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import re
import sys

CANDIDATE = "ae590dee058d3481e384dea850d5b7d980f533ff"
COMPILER_URL = "https://github.com/Waveframe-Labs/cricore-contract-compiler.git"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_git(origin, commit=CANDIDATE, url=COMPILER_URL):
    assert origin["url"] == url, origin
    assert origin["vcs_info"] == {
        "vcs": "git", "requested_revision": commit, "commit_id": commit,
    }, origin


def verify_archive_origin(origin, wheel, digest):
    assert origin["url"] == Path(wheel).resolve().as_uri(), origin
    assert "vcs_info" not in origin, origin
    info = origin["archive_info"]
    hashes = dict(info.get("hashes", {}))
    if "hash" in info:
        algorithm, value = info["hash"].split("=", 1)
        assert algorithm not in hashes or hashes[algorithm] == value, "contradictory archive digests"
        hashes[algorithm] = value
    assert hashes.get("sha256") == digest, hashes
    for algorithm, value in hashes.items():
        assert hashlib.new(algorithm, Path(wheel).read_bytes()).hexdigest() == value, hashes


def installed_archive(name, version, modules, expected, install_report=None):
    import zipfile

    dist = metadata.distribution(name)
    assert dist.version == version, dist.version
    wheel = Path(expected["wheel"]).resolve()
    digest = expected["sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert sha256(wheel) == digest, "wheel hash mismatch"
    origins = []
    direct = json.loads(dist.read_text("direct_url.json") or "null")
    if direct is not None:
        origins.append(direct)
    if install_report is not None:
        report = json.loads(Path(install_report).read_text(encoding="utf-8"))
        entries = [e for e in report["install"]
                   if e["metadata"]["name"].lower().replace("_", "-") == name]
        assert len(entries) == 1, (name, entries)
        assert entries[0]["metadata"]["version"] == version
        origins.append(entries[0]["download_info"])
    assert origins, "archive requires truthful PEP 610 or retained pip install report"
    for origin in origins:
        verify_archive_origin(origin, wheel, digest)
    files = {}
    with zipfile.ZipFile(wheel) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist())), "duplicate wheel member"
        for member in archive.namelist():
            relative = Path(member)
            assert not relative.is_absolute() and ".." not in relative.parts
            if member.endswith("/") or member.endswith(".dist-info/RECORD"):
                continue
            data = archive.read(member)
            if relative.parts[0].endswith(".data"):
                # Guard's real wheel includes documentation under .data/data.
                # pip relocates this scheme to the environment prefix.
                assert relative.parts[1] == "data", "unexpected wheel relocation scheme"
                installed = Path(sys.prefix).joinpath(*relative.parts[2:]).resolve()
            else:
                installed = Path(dist.locate_file(member)).resolve()
            assert Path(sys.prefix).resolve() in installed.parents, installed
            assert installed.read_bytes() == data, f"installed bytes differ: {member}"
            files[member] = hashlib.sha256(data).hexdigest()
    paths = {}
    for module in modules:
        path = Path(importlib.import_module(module).__file__).resolve()
        expected_path = Path(dist.locate_file(module.replace(".", "/") + "/__init__.py")).resolve()
        assert path == expected_path, (path, expected_path)
        paths[module] = str(path)
        for extra in path.parent.rglob("*"):
            if extra.is_file() and "__pycache__" not in extra.parts:
                relative = extra.relative_to(path.parent.parent).as_posix()
                assert relative in files, f"unrecorded installed resource: {extra}"
    for module, loaded in list(sys.modules.items()):
        if any(module == prefix or module.startswith(prefix + ".") for prefix in modules):
            if getattr(loaded, "__file__", None):
                path = Path(loaded.__file__).resolve()
                assert any(Path(p).parent in path.parents or path == Path(p) for p in paths.values()), path
    return {"version": version, "module_paths": paths, "wheel_sha256": digest,
            "direct_url": direct, "origins": origins, "installed_sha256": files}


def compiler_provenance(expectations=None):
    import compiler

    dist = metadata.distribution("cricore-contract-compiler")
    assert dist.version == "0.5.0"
    assert callable(compiler.compile_action_policy)
    supplied = expectations or os.environ.get("LEDGER_ARCHIVE_EXPECTATIONS")
    if supplied:
        expected = json.loads(Path(supplied).read_text(encoding="utf-8"))
        item = expected["distributions"]["cricore-contract-compiler"]
        verify_git(item["build_origin"])
        assert item["source_commit"] == CANDIDATE
        return installed_archive("cricore-contract-compiler", "0.5.0", ["compiler"],
                                 item, expected.get("install_report"))
    direct = json.loads(dist.read_text("direct_url.json") or "null")
    assert direct is not None, "exact Git or explicitly verified archive provenance required"
    verify_git(direct)
    path = Path(compiler.__file__).resolve()
    assert path == Path(dist.locate_file("compiler/__init__.py")).resolve(), path
    assert Path(sys.prefix).resolve() in path.parents, path
    return {"version": dist.version, "module_path": str(path), "direct_url": direct,
            "installed_sha256": {str(e): sha256(dist.locate_file(e)) for e in dist.files
                                  if Path(dist.locate_file(e)).is_file() and "__pycache__" not in str(e)}}

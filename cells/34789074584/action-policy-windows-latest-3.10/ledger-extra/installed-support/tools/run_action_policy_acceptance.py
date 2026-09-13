"""Cross-platform issue #23 base gate; all environments use ordinary pip resolution.

Run from a clean checkout with requirements-ci.txt installed. Reports and command
logs survive failures. No fixtures are regenerated and no packages are published.
"""
from __future__ import annotations

import argparse
from collections import Counter
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import platform
import subprocess
import sys
import tarfile
import venv
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DEV = "WAVEFRAME_LEDGER_ACTION_POLICY_DEV"


class Acceptance:
    def __init__(self, output: Path):
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.env = os.environ.copy()
        self.env.pop(DEV, None)
        self.env.pop("WAVEFRAME_GUARD_ACTION_POLICY_DEV", None)
        self.env.pop("PYTHONPATH", None)
        self.env.pop("LEDGER_ARCHIVE_EXPECTATIONS", None)
        self.env["PYTHONUTF8"] = "1"
        self.env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        # Applies to nested PEP 517 build isolation too, without bypassing resolution.
        self.env["PIP_CONSTRAINT"] = str(ROOT / "requirements-ci.txt")
        self.report = {"python": sys.version, "platform": platform.system(), "commands": [], "suites": {},
                       "gates": {"base": "incomplete", "combined_extra": "pending"},
                       "combined_extra": {"status": "pending", "executed": False,
                           "reason": "Separate Guard 0.19.0 candidate required",
                           "ledger": "0.9.0", "guard": "0.19.0"},
                       "release_ready": False, "runtime_activation_ready": False}
        self.save()

    def save(self):
        (self.output / "acceptance.json").write_text(
            json.dumps(self.report, indent=2), encoding="utf-8")

    def run(self, label, *args, cwd=ROOT, env=None, negative=False):
        command = [str(arg) for arg in args]
        print(f"[{label}] {' '.join(command)}", flush=True)
        result = subprocess.run(command, cwd=cwd, env=env or self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                encoding="utf-8", errors="replace")
        (self.output / f"{label}.log").write_text(result.stdout, encoding="utf-8")
        self.report["commands"].append({"label": label, "command": command,
                                        "cwd": str(cwd), "exit_code": result.returncode})
        self.save()
        if (result.returncode != 0) != negative:
            print(result.stdout[-12000:], flush=True)
            raise RuntimeError(f"{label}: unexpected exit {result.returncode}")
        return result.stdout

    def environment(self, name, *requirements):
        folder = self.output / name
        venv.EnvBuilder(with_pip=True).create(folder)
        python = folder / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        self.run(f"{name}-pip", python, "-m", "pip", "install", "pip==25.3")
        self.run(f"{name}-install", python, "-m", "pip", "install",
                 "-r", ROOT / "requirements-ci.txt", *requirements,
                 "--report", self.output / f"{name}-install.json")
        self.run(f"{name}-check", python, "-m", "pip", "check")
        self.run(f"{name}-freeze", python, "-m", "pip", "freeze", "--all")
        return python

    def suites(self, python, root, label, *, installed=False, guard=False):
        for native in (False, True):
            name = f"{label}-{'native' if native else 'default'}"
            env = self.env.copy()
            if native:
                env[DEV] = "1"
            env["LEDGER_EXPECT_IMPORT_ROOT"] = str(python.parent.parent if installed else ROOT / "governance_ledger")
            env["LEDGER_IMPORT_REPORT"] = str(self.output / f"{name}-imports.json")
            xml = self.output / f"{name}.xml"
            self.run(name, python, "-I", root / "tools/acceptance_pytest.py", "-q", "-ra",
                     "--junitxml", xml, "tests", cwd=root, env=env)
            cases = list(ET.parse(xml).iter("testcase"))
            skipped = [case for case in cases if case.find("skipped") is not None]
            reasons = Counter(case.find("skipped").get("message") for case in skipped)
            counts = {"passed": len(cases) - len(skipped), "skipped": len(skipped),
                      "skip_reasons": dict(reasons),
                      "release_passed": sum("test_release_catalog_v4" in case.get("classname", "")
                                           and case.find("skipped") is None for case in cases),
                      "native_passed": sum("test_action_policy_v4" in case.get("classname", "")
                                           and case.find("skipped") is None for case in cases)}
            self.report["suites"][name] = counts
            self.save()
            # The inherited suite has 44 opt-in cases and 3 optional Guard skips
            # (one is a module-level collection skip). Any other skip is a failure.
            dev_skips = sum("explicit action-policy development opt-in" in case.find("skipped").get("message", "") for case in skipped)
            guard_skips = sum("waveframe_guard" in (case.find("skipped").get("message", "")
                              + (case.find("skipped").text or "")) for case in skipped)
            assert dev_skips == (0 if native else 44), counts
            assert guard_skips == (0 if guard else 3), counts
            assert len(skipped) == dev_skips + guard_skips, counts
            assert counts["native_passed"] == (44 if native else 0), counts
            assert counts["release_passed"] == 70, counts
            print(f"[{name}] {counts}", flush=True)

    def probe(self, python, root, name, tool, *args, native=False, isolated=True):
        env = self.env.copy()
        if native:
            env[DEV] = "1"
        result = self.run(name, python, *(["-I"] if isolated else []),
                          root / "tools" / tool, *args, cwd=root, env=env)
        value = json.loads(result)
        (self.output / f"{name}.json").write_text(json.dumps(value, indent=2), encoding="utf-8")
        return value

    def archive_expectations(self, name, compiler, build, wheels=None):
        from package_provenance import CANDIDATE
        distributions = {"cricore-contract-compiler": {
            "wheel": str(compiler), "sha256": build["sha256"],
            "source_commit": CANDIDATE, "build_origin": build["origin"]}}
        for distribution, path in (wheels or {}).items():
            distributions[distribution] = {"wheel": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        path = self.output / f"{name}-archive-expectations.json"
        path.write_text(json.dumps({"distributions": distributions,
            "install_report": str(self.output / f"{name}-install.json")}, indent=2), encoding="utf-8")
        self.env["LEDGER_ARCHIVE_EXPECTATIONS"] = str(path)
        return path

    def build(self):
        dist = self.output / "dist"
        # build's default path builds the wheel from the freshly created sdist.
        self.run("build", sys.executable, "-m", "build", "--outdir", dist)
        files = sorted(dist.iterdir())
        assert len(files) == 2
        self.run("twine", sys.executable, "-m", "twine", "check", "--strict", *files)
        wheel, = dist.glob("*.whl")
        sdist, = dist.glob("*.tar.gz")
        self.report["package_sha256"] = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            for required in ("action_policy.py", "action_policy_publication.py", "cli.py", "domain_packs.py"):
                assert f"governance_ledger/{required}" in names
            assert not any(name.startswith(("compiler/", "tests/")) for name in names)
            metadata = BytesParser().parsebytes(archive.read(next(n for n in names if n.endswith(".dist-info/METADATA"))))
            from packaging.requirements import Requirement
            requires = [Requirement(value) for value in metadata.get_all("Requires-Dist")]
            compiler, = [req for req in requires if req.name == "cricore-contract-compiler"]
            assert str(compiler.specifier) == "<0.6.0,>=0.5.0" and compiler.url is None
            guard, = [req for req in requires if req.name == "waveframe-guard"]
            assert str(guard.specifier) == "<0.20.0,>=0.19.0" and str(guard.marker) == 'extra == "guard"'
            assert guard.url is None and all(req.url is None for req in requires)
            assert metadata["Name"] == "governance-ledger"
            assert metadata["Version"] == "0.9.0" and metadata["Requires-Python"] == ">=3.10"
            assert wheel.name == "governance_ledger-0.9.0-py3-none-any.whl"
            assert sdist.name == "governance_ledger-0.9.0.tar.gz"
            self.report["wheel_metadata"] = dict(metadata.items())
        # Extract only support resources, never Ledger source, into installed test cwd.
        support = self.output / "installed-support"
        support.mkdir()
        with tarfile.open(sdist) as archive:
            members = {Path(*Path(m.name).parts[1:]).as_posix(): m for m in archive.getmembers() if m.isfile()}
            sdist_metadata = BytesParser().parsebytes(archive.extractfile(members["PKG-INFO"]).read())
            for field in ("Name", "Version", "Requires-Python", "Requires-Dist", "Provides-Extra"):
                assert sdist_metadata.get_all(field) == metadata.get_all(field), field
            tracked = subprocess.check_output(["git", "ls-files", "tests", "schemas", "examples", "tools", "docs"], cwd=ROOT, text=True).splitlines()
            resource_hashes = {}
            for path in tracked:
                assert path in members, f"missing packaged acceptance resource: {path}"
                packaged = archive.extractfile(members[path]).read()
                assert packaged == (ROOT / path).read_bytes(), f"changed packaged resource: {path}"
                resource_hashes[path] = hashlib.sha256(packaged).hexdigest()
            self.report["sdist_resource_sha256"] = resource_hashes
            for required in ("schemas/authority_bundle.v4.json", "schemas/publication_receipt.v4.json",
                             "tests/test_action_policy_v4.py", "examples/native_v4_development.py",
                             "tools/check_action_policy_package.py", "requirements-action-policy-dev.txt", "requirements-ci.txt"):
                assert required in members, required
            for path, member in members.items():
                relative = Path(path)
                assert not relative.is_absolute() and ".." not in relative.parts
                if relative.parts[0] in {"tests", "schemas", "examples", "tools", "docs"} or len(relative.parts) == 1:
                    target = support / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
        assert not (support / "governance_ledger").exists()
        (support / "runtime").mkdir()
        self.env["WAVEFRAME_LEDGER_TEST_WHEEL"] = str(wheel)
        self.save()
        return wheel, support

    def execute(self, expected_head, inputs=None):
        assert re.fullmatch(r"[0-9a-f]{40}", expected_head), "explicit full commit required"
        head = self.run("head", "git", "rev-parse", "HEAD").strip()
        assert head == expected_head, (head, expected_head)
        self.report.update(head=head, expected_head=expected_head,
                           base="3cc34e7b3cb6efca5102e0e22d559ec0c0fd583f")
        self.run("stack-base", "git", "merge-base", "--is-ancestor", self.report["base"], head)
        self.run("clean-tracked-checkout", "git", "diff", "--exit-code", "HEAD")
        self.run("preserved-evidence", "git", "diff", "--exit-code",
                 "4dbdfbaee92d43b888cae751ecaee5d9e4ec20b7", "--",
                 "tests/fixtures/action_policy_v4", "tests/fixtures/golden_path", "tests/fixtures/provenance_complete",
                 "docs/acceptance/issue17", "docs/acceptance/issue19", "examples/native_v4_development.py",
                 "requirements-action-policy-dev.txt")
        self.run("preserved-catalog-release", "git", "diff", "--exit-code", self.report["base"], "--",
                 "tests/fixtures", "schemas", "examples/native_v4_release.py")
        changed_runtime = self.run("runtime-diff", "git", "diff", "--name-only", self.report["base"], "--", "governance_ledger").splitlines()
        assert set(changed_runtime) <= {"governance_ledger/integrations/guard.py", "governance_ledger/cli.py"}, changed_runtime
        self.probe(sys.executable, ROOT, "release-metadata", "check_ledger_release_metadata.py")
        wheel, support = self.build()
        candidate = ["-r", ROOT / "requirements-action-policy-dev.txt"]
        source = self.environment("source", "-e", f"{ROOT}[dev]", *candidate)
        source_provenance = self.probe(source, ROOT, "source-provenance", "check_compiler_provenance.py")
        self.suites(source, ROOT, "source")
        if inputs:
            from fetch_guard_candidate import verify
            supplied = json.loads(inputs.read_text(encoding="utf-8"))
            verified = verify(inputs.parent, supplied["cell"])
            self.report["verified_inputs"] = verified
            compiler = Path(verified["compiler_wheel"])
            shutil.copyfile(compiler, self.output / compiler.name)
            self.report["compiler_wheel"] = verified["compiler_build"]
            installed = self.environment("installed", f"{wheel}[dev]", compiler)
            self.archive_expectations("installed", compiler, verified["compiler_build"])
        else:
            installed = self.environment("installed", f"{wheel}[dev]", *candidate)
        installed_provenance = self.probe(installed, support, "installed-provenance", "check_compiler_provenance.py")
        source_bytes = {p: h for p, h in source_provenance["installed_sha256"].items() if p.startswith("compiler/")}
        archive_bytes = {p: h for p, h in installed_provenance["installed_sha256"].items() if p.startswith("compiler/")}
        assert source_bytes == archive_bytes, "accepted Compiler wheel differs from exact Git installation"
        self.report["compiler_source_archive_bytes_equal"] = True
        self.suites(installed, support, "installed", installed=True)
        self.probe(installed, support, "package", "check_action_policy_package.py", native=True)
        self.probe(installed, support, "release-package", "check_release_catalog_package.py")
        self.run("installed-release-example", installed, "-I", support / "examples/native_v4_release.py", cwd=support)
        self.run("installed-cli", installed.parent / ("governance-ledger.exe" if os.name == "nt" else "governance-ledger"), "--help", cwd=support)
        current_history = self.probe(installed, support, "candidate-history", "check_action_policy_history.py")
        self.env.pop("LEDGER_ARCHIVE_EXPECTATIONS", None)
        negative = self.environment("resolver-negative")
        rejection = self.run("reject-compiler-040", negative, "-m", "pip", "install", "--dry-run",
                             wheel, "cricore-contract-compiler==0.4.0", negative=True)
        assert "ResolutionImpossible" in rejection and "0.4.0" in rejection and "0.5.0" in rejection, rejection
        self.report["compiler_040_resolver_rejected"] = True
        # The new extra is a separate, explicitly pending gate. Preserve the
        # released 0.8/0.17 example in its own ordinarily resolved environment.
        historical = self.environment("historical-extra", "governance-ledger[guard]==0.8.0",
                                      "waveframe-guard==0.17.0", "cricore-contract-compiler==0.4.0")
        self.run("historical-v3-example", historical, "-I", support / "examples/native_v3_multi_control.py", cwd=support)
        for version in ("0.7.0", "0.8.0"):
            name = "published-" + version
            published = self.environment(name, f"governance-ledger=={version}",
                                         "waveframe-guard==0.18.0", "cricore-contract-compiler==0.4.0")
            self.probe(published, support, name + "-rejections", "check_action_policy_old_runtime.py")
            self.probe(published, support, name + "-release-rejections", "check_action_policy_old_runtime.py",
                       "--fixtures", "action_policy_release_v4")
            if version == "0.8.0":
                history = self.probe(published, support, "published-history", "check_action_policy_history.py")
                assert current_history == history, "historical hashes changed; see history reports"
                retained = json.loads((ROOT / "docs/acceptance/issue17/historical-hash-comparison.json").read_text())
                assert history["artifact_hashes"] == retained["published"]["artifact_hashes"], "retained historical identities changed"
                # #17 recorded raw Windows CRLF checkout hashes. Preserve those
                # records; distinguish them from Git blob and current checkout bytes.
                golden = {}
                for path, recorded in retained["published"]["golden_file_sha256"].items():
                    blob = subprocess.check_output(["git", "show", f"HEAD:{path}"], cwd=ROOT)
                    windows_hash = hashlib.sha256(blob.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).hexdigest()
                    assert windows_hash == recorded, (path, windows_hash, recorded)
                    golden[path] = {"git_blob_sha256": hashlib.sha256(blob).hexdigest(),
                                    "checkout_sha256": history["golden_file_sha256"][path],
                                    "retained_issue17_windows_crlf_sha256": recorded}
                self.report["golden_file_bytes"] = golden
                self.probe(published, support, "legacy-operations", "check_action_policy_legacy_operations.py")
        # Record the locally built cached VCS wheel and its origin; not a supplied
        # archive or reproducible-build claim. Native output equality is checked above.
        if not inputs:
            cache = Path(self.run("pip-cache", source, "-m", "pip", "cache", "dir").strip())
            from check_compiler_wheel_cache import record_cached_compiler
            self.report["compiler_wheel"] = record_cached_compiler(cache, self.output)
        assert self.run("final-head", "git", "rev-parse", "HEAD").strip() == expected_head
        self.run("final-clean-tracked-checkout", "git", "diff", "--exit-code", "HEAD")
        self.report["gates"]["base"] = "passed"
        self.report["status"] = "base-passed-extra-pending"
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verified-inputs", type=Path)
    args = parser.parse_args()
    acceptance = Acceptance(args.output)
    try:
        acceptance.execute(args.expected_head, args.verified_inputs.resolve() if args.verified_inputs else None)
    except BaseException as exc:
        acceptance.report.update(status="failed", error=str(exc))
        acceptance.save()
        raise


if __name__ == "__main__":
    main()

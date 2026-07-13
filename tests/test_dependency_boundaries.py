from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GUARD_ROOTS = [
    path
    for path in [
        REPO_ROOT / "waveframe_guard",
        REPO_ROOT / "guard",
    ]
    if path.exists()
]

FORBIDDEN_LOCAL_DEFINITIONS = {
    "CompiledAuthorityContract",
    "compile_policy",
    "parse_policy",
    "parse_raw_policy",
    "extract_governance",
    "extract_semantics",
    "normalize_proposal",
    "normalize_execution_request",
    "persist_cloud_event",
    "save_cloud_event",
}

FORBIDDEN_DIRECTORY_NAMES = {
    "compiler",
    "semantic_compiler",
    "semantics",
    "governance_extraction",
    "extraction",
}

FORBIDDEN_SCHEMA_MODULE_NAMES = {
    "authority_schema",
    "compiled_authority_schema",
    "governance_schema",
}

FORBIDDEN_CLOUD_PERSISTENCE_MODULE_NAMES = {
    "cloud",
    "persistence",
    "repository",
    "database",
    "db",
    "store",
}

ALLOWED_CLOUD_PRESERVATION_CLIENT_FILES = {
    "waveframe_guard/cloud/__init__.py",
    "waveframe_guard/cloud/client.py",
}


def test_guard_has_no_local_governance_meaning_definitions():
    violations = []
    for python_file in _guard_python_files():
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in FORBIDDEN_LOCAL_DEFINITIONS:
                    violations.append(f"{_rel(python_file)}:{node.lineno} defines {node.name}")

    assert violations == []


def test_guard_has_no_semantic_compiler_or_extraction_folders():
    violations = []
    for root in GUARD_ROOTS:
        for path in root.rglob("*"):
            if path.is_dir() and path.name.lower() in FORBIDDEN_DIRECTORY_NAMES:
                violations.append(_rel(path))

    assert violations == []


def test_guard_has_no_governance_authority_schema_duplication_modules():
    violations = []
    for python_file in _guard_python_files():
        if python_file.stem.lower() in FORBIDDEN_SCHEMA_MODULE_NAMES:
            violations.append(_rel(python_file))

    assert violations == []


def test_guard_does_not_import_local_raw_policy_compilers():
    violations = []
    for python_file in _guard_python_files():
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                imported = {alias.name for alias in node.names}
                if module.startswith("compiler") or "compile_policy" in imported:
                    violations.append(f"{_rel(python_file)}:{node.lineno} imports {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("compiler"):
                        violations.append(f"{_rel(python_file)}:{node.lineno} imports {alias.name}")

    assert violations == []


def test_guard_does_not_import_bare_server_package():
    violations = []
    for python_file in _repo_python_files():
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "server":
                violations.append(f"{_rel(python_file)}:{node.lineno} imports from bare server package")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "server" or alias.name.startswith("server."):
                        violations.append(f"{_rel(python_file)}:{node.lineno} imports bare server package")

    assert violations == []


def test_guard_has_upstream_semantics_adapter_boundary():
    adapter_path = REPO_ROOT / "guard" / "adapters" / "upstream_semantics.py"
    source = adapter_path.read_text(encoding="utf-8")

    assert "governance_ledger.semantics.execution_projection" in source
    assert "governance_ledger.semantics.compiler" in source
    assert "cricore.api" in source


def test_guard_does_not_parse_raw_policy_text():
    violations = []
    forbidden_names = {
        "parse_policy",
        "parse_raw_policy",
        "extract_governance",
        "extract_semantics",
    }
    for python_file in _guard_python_files():
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in forbidden_names:
                    violations.append(f"{_rel(python_file)}:{node.lineno} calls {node.func.id}")

    assert violations == []


def test_guard_does_not_duplicate_proposal_normalization_logic():
    violations = []
    for python_file in _guard_python_files():
        if _rel(python_file) == "guard/adapters/proposal_normalizer.py":
            continue
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lowered = node.name.lower()
                is_proposal_or_request_normalization = (
                    "normaliz" in lowered
                    and any(term in lowered for term in ["proposal", "execution_request"])
                )
                if is_proposal_or_request_normalization:
                    violations.append(f"{_rel(python_file)}:{node.lineno} defines {node.name}")

    assert violations == []


def test_guard_does_not_define_cloud_persistence_behavior():
    violations = []
    for python_file in _guard_python_files():
        rel_path = _rel(python_file)
        if rel_path in ALLOWED_CLOUD_PRESERVATION_CLIENT_FILES:
            continue
        parts = {part.lower() for part in python_file.relative_to(REPO_ROOT).parts}
        stem = python_file.stem.lower()
        if stem in FORBIDDEN_CLOUD_PERSISTENCE_MODULE_NAMES or parts & FORBIDDEN_CLOUD_PERSISTENCE_MODULE_NAMES:
            violations.append(rel_path)
            continue
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lowered = node.name.lower()
                if "cloud" in lowered and any(word in lowered for word in ["persist", "save", "store", "write"]):
                    violations.append(f"{_rel(python_file)}:{node.lineno} defines {node.name}")

    assert violations == []


def test_cloud_preservation_client_has_no_enforcement_coupling():
    violations = []
    for rel_path in ALLOWED_CLOUD_PRESERVATION_CLIENT_FILES:
        python_file = REPO_ROOT / rel_path
        tree = ast.parse(python_file.read_text(encoding="utf-8"), filename=str(python_file))
        for node in ast.walk(tree):
            imported_module = None
            if isinstance(node, ast.ImportFrom):
                imported_module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_enforcement_module(alias.name):
                        violations.append(f"{rel_path}:{node.lineno} imports {alias.name}")
                continue

            if _is_enforcement_module(imported_module):
                violations.append(f"{rel_path}:{node.lineno} imports {imported_module}")

    assert violations == []


def test_continuation_governance_is_guard_subsystem_not_repo_split():
    doc = (REPO_ROOT / "docs" / "runtime" / "CONTINUATION_GOVERNANCE_MODEL.md").read_text(encoding="utf-8").lower()

    assert "status: emerging subsystem" in doc
    assert "not a separate repository" in doc
    assert "not a separate package" in doc
    assert "not a repo split" in doc
    assert "not a package split" in doc
    assert "guard evaluates admissibility against compiled authority" in doc
    assert (REPO_ROOT / "guard" / "runtime" / "continuation.py").exists()
    assert not (REPO_ROOT / "continuation").exists()
    assert not (REPO_ROOT / "waveframe_continuation").exists()


def _guard_python_files():
    for root in GUARD_ROOTS:
        yield from root.rglob("*.py")


def _repo_python_files():
    for python_file in REPO_ROOT.rglob("*.py"):
        if any(part.startswith(".") for part in python_file.relative_to(REPO_ROOT).parts):
            continue
        yield python_file


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")


def _is_enforcement_module(module_name):
    if module_name is None:
        return False
    return module_name in {
        "guard.enforcement",
        "waveframe_guard.execute",
        "waveframe_guard.guard",
        "waveframe_guard.runtime",
    } or module_name.startswith("guard.enforcement.")

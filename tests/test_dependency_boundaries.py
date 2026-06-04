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


def _guard_python_files():
    for root in GUARD_ROOTS:
        yield from root.rglob("*.py")


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT)).replace("\\", "/")

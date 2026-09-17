"""Focused import/export regressions and actual repository-trial evidence."""
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'examples/codex_contained'
sys.path.insert(0, str(EXAMPLES))
import compiler_trial as trial
import compiler_export as exporter
import compiler_cloud as provider
import verify_compiler_trial as proof
sys.path.pop(0)


def test_tracked_import_ignores_local_files_and_autocrlf(tmp_path, monkeypatch):
    def git(*args):
        return subprocess.check_output(['git', '-c', 'core.hooksPath=/nonexistent-trial-hooks', '-C', str(tmp_path), *args], stderr=subprocess.PIPE)
    git('init', '-q')
    git('config', 'core.autocrlf', 'true')
    (tmp_path / 'README.md').write_bytes(b'committed\nbytes\n')
    git('-c', 'core.autocrlf=false', 'add', 'README.md')
    git('-c', 'user.name=Disposable test', '-c', 'user.email=test@example.test', 'commit', '-qm', 'base')
    monkeypatch.setattr(trial, 'COMPILER_HEAD', git('rev-parse', 'HEAD').decode().strip())
    (tmp_path / 'README.md').write_bytes(b'uncommitted local change\r\n')
    (tmp_path / 'local-secret').write_bytes(b'excluded')
    status = git('status', '--porcelain')
    archive, files = trial.archive_snapshot(tmp_path)
    assert set(files) == {'README.md'}
    assert bytes.fromhex(files['README.md']['bytes']) == b'committed\nbytes\n'
    assert git('status', '--porcelain') == status
    assert archive


@pytest.mark.parametrize('extra', ['src/compiler/compile_policy.py', 'LICENSE', 'pyproject.toml'])
def test_export_rejects_out_of_scope_changes(extra):
    before = {'README.md': {'bytes': '61'}, extra: {'bytes': '61'}}
    after = {**before, 'README.md': {'bytes': '62'}, 'examples/compile_repository_policy.py': {'bytes': '63'}, extra: {'bytes': '64'}}
    with pytest.raises(AssertionError): exporter.changed_paths(before, after)


def test_fixed_provider_clauses_bind_exact_source_literals():
    result = provider.candidate_result()
    assert len(result['clauses']) == 4
    selectors = []
    for clause in result['clauses']:
        for control in clause['candidate_controls']:
            value = control['value']
            assert provider.POLICY.encode()[value['start_byte']:value['end_byte']].decode() == value['value']
            if control['effect'] == 'allow': selectors.append((control['action'], control['control_type'], value['value']))
    assert selectors == [('create', 'exact_path_access', 'examples/compile_repository_policy.py'), ('modify', 'exact_path_access', 'README.md')]


def test_actual_compiler_task_evidence():
    result = proof.verify(ROOT / 'docs/acceptance/compiler-task-61/evidence')
    assert result['source_tests_passed'] > 200
    assert result['explicit_runtime_source_denial_writes'] == 0

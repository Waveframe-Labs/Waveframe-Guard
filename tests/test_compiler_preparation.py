"""Preparation refusal, no implicit execution, and exact image checks."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

HERE = Path(__file__).resolve().parents[1] / 'examples/codex_contained'
sys.path.insert(0, str(HERE))
import prepare_compiler as prep
sys.path.pop(0)


@pytest.fixture
def prerequisites(tmp_path, monkeypatch):
    monkeypatch.setattr(prep.sys, 'version_info', (3, 14, 0))
    monkeypatch.setattr(prep.shutil, 'which', lambda name: name)
    auth = tmp_path / 'auth.json'
    auth.write_text(json.dumps({'tokens': {'access_token': 'SECRET-TEST-LOGIN'}}))
    calls = []
    def checked(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ['git', '--version']: return b'git version 2.49.0'
        if argv[:2] == ['docker', 'info']: return b'{"OSType":"linux","Architecture":"x86_64","ServerVersion":"29"}'
        if 'rev-parse' in argv: return prep.CLOUD_HEAD.encode()
        return b''
    monkeypatch.setattr(prep, 'checked', checked)
    monkeypatch.setattr(prep.run, 'docker', lambda *a, **kw: pytest.fail('No container operation during preflight'))
    return auth, calls


@pytest.mark.parametrize('tool', ['git', 'docker'])
def test_missing_tool_refuses_before_activation(tmp_path, monkeypatch, prerequisites, tool):
    monkeypatch.setattr(prep.shutil, 'which', lambda name: None if name == tool else name)
    with pytest.raises(RuntimeError, match='Install ' + tool): prep.preflight(tmp_path, tmp_path, prerequisites[0], tmp_path)


@pytest.mark.parametrize('content', [None, '{bad SECRET-TEST-LOGIN', '{}', '{"tokens":null}'])
def test_missing_or_bad_login_does_not_disclose_values(tmp_path, prerequisites, content):
    auth, calls = prerequisites
    if content is None: auth.unlink()
    else: auth.write_text(content)
    with pytest.raises(RuntimeError, match='codex login') as error: prep.preflight(tmp_path, tmp_path, auth, tmp_path)
    assert 'SECRET-TEST-LOGIN' not in str(error.value)
    assert all('cat-file' not in cmd for cmd in calls)


def test_missing_source_is_actionable(tmp_path, monkeypatch, prerequisites):
    checked = prep.checked
    def absent(argv, **kwargs):
        if 'cat-file' in argv: raise subprocess.CalledProcessError(128, argv, stderr=b'private checkout details')
        return checked(argv, **kwargs)
    monkeypatch.setattr(prep, 'checked', absent)
    with pytest.raises(RuntimeError, match='CompilerRepository') as error: prep.preflight(tmp_path, tmp_path, prerequisites[0], tmp_path)
    assert 'private checkout details' not in str(error.value)


def test_wrong_engine_refuses(tmp_path, monkeypatch, prerequisites):
    checked = prep.checked
    monkeypatch.setattr(prep, 'checked', lambda argv, **kw: b'{"OSType":"windows","Architecture":"amd64"}' if argv[0] == 'docker' else checked(argv, **kw))
    with pytest.raises(RuntimeError, match='Linux/WSL2'): prep.preflight(tmp_path, tmp_path, prerequisites[0], tmp_path)


def test_repeated_prepare_never_executes(tmp_path, monkeypatch):
    monkeypatch.setattr(prep, 'ROOT', tmp_path)
    output = tmp_path / 'acceptance-output/repeat'
    output.mkdir(parents=True)
    (output / 'prepared.json').write_text('{"inputs":{},"images":{}}')
    monkeypatch.setattr(prep, 'inputs', lambda cloud: {})
    monkeypatch.setattr(prep, 'preflight', lambda *args: {})
    verified = []
    monkeypatch.setattr(prep, 'verify_images', lambda manifest, output: verified.append(output))
    monkeypatch.setattr(prep, 'execute', lambda *args: pytest.fail('Prepare must never execute a task'))
    monkeypatch.setattr(sys, 'argv', ['prepare', '--stage', 'Prepare', '--preparation', str(output), '--compiler-repository', str(tmp_path),
        '--cloud-checkout', str(tmp_path), '--auth', 'unused', '--name', 'wf54-57-61-repeat'])
    prep.main()
    assert len(verified) == 1
    assert not (tmp_path / 'acceptance-output/wf54-57-61-repeat').exists()


def test_image_identity_rejected_before_container(tmp_path, monkeypatch):
    def docker(*args, **kwargs):
        assert args[:2] == ('image', 'inspect')
        return subprocess.CompletedProcess(args, 0, stdout=b'[{"Id":"sha256:wrong"}]')
    monkeypatch.setattr(prep.run, 'docker', docker)
    with pytest.raises(AssertionError): prep.verify_images({'images': {'agent': 'sha256:expected'}}, tmp_path / 'verify')


def test_cleanup_refuses_unowned_resources(tmp_path, monkeypatch):
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=b'[{"Config":{"Labels":{"waveframe.proof":"someone-else"}}}]')
    monkeypatch.setattr(prep.run, 'docker', docker)
    monkeypatch.setattr(sys, 'argv', ['run_cloud', 'cleanup', '--name', 'wf54-57-61-scoped', '--output', str(tmp_path)])
    with pytest.raises(AssertionError): prep.run_cloud.main()
    assert calls == [('container', 'inspect', 'wf54-57-61-scoped-cloud')]

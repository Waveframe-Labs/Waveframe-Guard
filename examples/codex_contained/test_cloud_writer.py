"""Focused connected adapter tests, executed against the installed public SDK on Linux."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='contained writer uses Linux flock')
if sys.platform == 'linux':
    spec = importlib.util.spec_from_file_location('cloud_writer', Path(__file__).with_name('cloud_writer.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


def config():
    return {'cloud_url': 'http://127.0.0.1:18081', 'organization_id': 'org', 'authority': 'proof@1',
            'publication_id': 'fresh', 'contract_hash': 'sha256:expected', 'bindings': {
                action: {'runtime_id': action, 'credential': 'private-' + action,
                         'actor': {'id': action, 'type': 'agent', 'role': role}}
                for action, role in [('create', 'repository-maintainer'), ('modify', 'security-reviewer')]}}


def make_writer(tmp_path, monkeypatch, *, publication='fresh', connected=True, evaluation=None, failure=False):
    calls, instances = [], []
    def cloud(**kwargs):
        class Guard:
            actor_identity = kwargs['actor_identity']
            runtime_connection = SimpleNamespace(ok=connected)
            loaded_authority = SimpleNamespace(publication_id=publication, contract_hash='sha256:expected',
                authority_ref='proof@1', bundle_hash='sha256:bundle', contract={'contract_version': '1'})
            closed = False
            def boundary_for(self): return self
            def close(self): self.closed = True
            def execute_repository(self, fn, **options):
                calls.append(options)
                if failure:
                    error = RuntimeError('private-create must not escape')
                    error.evaluation = evaluation or {}
                    raise error
                return {'executed': True, 'evaluation': evaluation or {}}
        instance = Guard()
        instances.append(instance)
        return instance
    monkeypatch.setattr(module.Guard, 'cloud', cloud)
    return lambda: module.Writer(tmp_path, tmp_path / 'evidence', config()), calls, instances


@pytest.mark.parametrize('key', ['role', 'actor_identity', 'runtime_id', 'authority', 'cloud_url', 'command', 'root'])
def test_agent_cannot_override_operator_binding(tmp_path, monkeypatch, key):
    factory, calls, _ = make_writer(tmp_path, monkeypatch)
    with_writer = factory()
    try:
        response = with_writer.write({'action': 'create', 'path': 'generated/a', 'content': '', key: 'attacker'})
        assert response['outcome'] == 'invalid_request' and not calls
        assert not (tmp_path / 'evidence/requests.jsonl').exists()
    finally: with_writer.close()


@pytest.mark.parametrize('publication,connected', [('substituted', True), ('fresh', False)])
def test_rejected_activation_closes_all_open_guards(tmp_path, monkeypatch, publication, connected):
    factory, _, instances = make_writer(tmp_path, monkeypatch, publication=publication, connected=connected)
    with pytest.raises(ValueError): factory()
    assert instances and all(g.closed for g in instances)


@pytest.mark.parametrize('url', ['https://example.com', 'http://localhost:18081', 'http://127.0.0.1:8000', 'http://127.0.0.1:18081/redirect'])
def test_alternate_endpoint_never_reaches_sdk(tmp_path, monkeypatch, url):
    def unexpected(**kwargs): raise AssertionError('network operation attempted')
    monkeypatch.setattr(module.Guard, 'cloud', unexpected)
    selected = config(); selected['cloud_url'] = url
    with pytest.raises(ValueError): module.Writer(tmp_path, tmp_path / 'evidence', selected)


def test_successful_mutation_remains_success_when_cloud_evidence_fails(tmp_path, monkeypatch):
    evaluation = {'run_id': 'actual-run', 'status': 'admissible',
        'execution_attestation': {'mutation_status': 'executed'},
        'cloud_preservation': {'ok': False}, 'cloud_runtime_attestation': {'ok': False}}
    factory, calls, _ = make_writer(tmp_path, monkeypatch, evaluation=evaluation)
    writer = factory()
    try:
        response = writer.write({'action': 'create', 'path': 'generated/a', 'content': ''})
        assert response['outcome'] == 'executed' and response['mutation_status'] == 'executed'
        assert not response['decision_preservation']['ok'] and not response['terminal_report_submission']['ok']
        assert len(calls) == 1 and response['automatic_retry'] is False
        assert writer.status()['policies']['create']['last_successful_preservation'] is None
    finally: writer.close()


def test_unknown_exception_is_not_reported_as_zero_writes_or_retried(tmp_path, monkeypatch):
    factory, calls, _ = make_writer(tmp_path, monkeypatch, failure=True)
    writer = factory()
    try:
        response = writer.write({'action': 'create', 'path': 'generated/a', 'content': 'value'})
        assert response['mutation_status'] == 'unknown' and response['run_id'] is None
        assert response['terminal_report_submission'] is None and len(calls) == 1
        assert 'private-create' not in str(response)
        journal = (tmp_path / 'evidence/requests.jsonl').read_text().splitlines()
        assert len(journal) == 2 and response['request_id'] in journal[0]
    finally: writer.close()

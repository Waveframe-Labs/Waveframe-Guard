"""Operator-only deterministic supplement, executed in the isolated writer with published SDK.

Each case has a fresh scratch repository. The parent controls only Cloud faults;
no model command or repository code is evaluated here.
"""
from dataclasses import asdict
from copy import deepcopy
import json
from pathlib import Path
import sys
from uuid import uuid4

from waveframe_guard import Guard

config = json.loads(Path('/secrets/cloud.json').read_text())
root = Path('/tmp/connected-sdk-probes-' + uuid4().hex)
root.mkdir()


def barrier(mode):
    print(json.dumps({'barrier': mode}), flush=True)
    assert json.loads(sys.stdin.readline()) == {'continue': True}


def connect(case, key=None, authority=None, action='create'):
    path = root / case
    (path / 'generated').mkdir(parents=True, exist_ok=True)
    (path / 'README.md').write_bytes(b'original')
    binding = config['bindings'][action]
    return Guard.cloud(authority=authority or config['authority'], cloud_url=config['cloud_url'],
        cloud_organization_id=config['organization_id'], runtime_credential=key or binding['credential'],
        runtime_id=binding['runtime_id'], actor_identity=binding['actor'],
        environment='development', repository_root=path, workspace=Path('/evidence/supplemental') / case,
        execution_context={'surface': 'contained57-deterministic-sdk', 'case': case}, preservation_timeout_seconds=2)


def perform(guard, case, mode, action='create'):
    target_name = 'README.md' if action == 'modify' else 'generated/probe.md'
    request = {'schema_version': 'normalized_execution_request.v1', 'request_id': 'probe57-' + uuid4().hex,
               'action': action, 'target': target_name, 'arguments': {}, 'artifacts': []}
    calls = []
    def callback(target):
        calls.append(1)
        if mode == 'unknown':
            raise RuntimeError('deliberate no-write callback failure')
        data = b'' if mode == 'empty' else case.encode()
        value = target.write_bytes(data) if action == 'modify' else target.create_bytes(data)
        if mode == 'partial':
            raise RuntimeError('deliberate failure after real mutation')
        if mode == 'after-mutation-outage':
            barrier('unavailable')
        return value
    try:
        if mode == 'no-report':
            evaluation = guard.boundary_for().evaluate(request)
        else:
            evaluation = guard.boundary_for().execute_repository(callback, execution_request=request,
                operation=action, raise_on_block=False)['evaluation']
        error = None
    except Exception as exc:
        evaluation, error = getattr(exc, 'evaluation', {}), type(exc).__name__
    path = root / case / target_name
    record = {'case': case, 'request': request, 'callback_count': len(calls), 'error_class': error,
              'evaluation': evaluation, 'exists': path.exists(),
              'actual_bytes': path.read_bytes().hex() if path.exists() else None}
    print(json.dumps({'result': record}), flush=True)
    return record


for case, fault, key in [('before-load-outage', 'unavailable', None),
                         ('redirect-load', 'redirect', None), ('invalid-credential', 'normal', 'invalid-disposable-key')]:
    barrier(fault)
    try:
        g = connect(case, key=key)
    except Exception as exc:
        print(json.dumps({'result': {'case': case, 'error_class': type(exc).__name__, 'mutations': 0}}), flush=True)
    else:
        g.close()
        raise AssertionError(case + ' unexpectedly loaded')
barrier('normal')
g = connect('wrong-runtime', key=config['bindings']['modify']['credential'])
print(json.dumps({'result': {'case': 'wrong-runtime-registration', 'connection': asdict(g.runtime_connection),
                             'callback_count': 0, 'mutations': 0,
                             'observation': 'failed connection must be checked before exposing mutations'}}), flush=True)
assert not g.runtime_connection.ok
assert not (root / 'wrong-runtime/generated/probe.md').exists()
g.close()

for case in ('empty', 'partial', 'unknown', 'no-report', 'collision', 'preservation', 'report', 'after-mutation-outage', 'loaded-outage', 'redirect-loaded'):
    barrier('normal')
    g = connect(case)
    if case == 'collision':
        (root / case / 'generated/probe.md').write_bytes(b'competitor')
    if case in ('preservation', 'report'):
        barrier(case)
    if case == 'loaded-outage':
        barrier('unavailable')
    if case == 'redirect-loaded':
        barrier('redirect')
    result = perform(g, case, case)
    attestation = result['evaluation'].get('execution_attestation')
    if case == 'empty':
        assert result['actual_bytes'] == '' and attestation['mutation_status'] == 'executed'
    if case == 'collision':
        assert result['actual_bytes'] == b'competitor'.hex()
    if case == 'unknown':
        assert not result['exists'] and attestation['mutation_status'] == 'unknown'
    if case == 'no-report':
        assert not result['exists'] and not result['evaluation'].get('cloud_runtime_attestation')
    if case in ('preservation', 'loaded-outage', 'redirect-loaded'):
        assert result['exists'] and not result['evaluation']['cloud_preservation']['ok']
    if case in ('report', 'after-mutation-outage'):
        assert result['exists'] and result['evaluation']['cloud_preservation']['ok']
        assert not result['evaluation']['cloud_runtime_attestation']['ok']
    g.close()
barrier('normal')
# Parent uses real supported publication/lifecycle APIs, never storage injection.
g = connect('loaded-superseded')
barrier('supersede')
perform(g, 'loaded-superseded', 'ordinary')
g.close()
try:
    connect('new-session-superseded')
except Exception as exc:
    print(json.dumps({'result': {'case': 'new-session-superseded', 'error_class': type(exc).__name__, 'mutations': 0}}), flush=True)
else:
    raise AssertionError('superseded authority accepted on new session')
barrier('load-new-version')
new_authority = config['authority'].rsplit('@', 1)[0] + '@2.0.0'
g = connect('loaded-revoked', authority=new_authority)
barrier('revoke')
perform(g, 'loaded-revoked', 'ordinary')
g.close()
try:
    connect('new-session-revoked', authority=new_authority)
except Exception as exc:
    print(json.dumps({'result': {'case': 'new-session-revoked', 'error_class': type(exc).__name__, 'mutations': 0}}), flush=True)
else:
    raise AssertionError('revoked authority accepted on new session')

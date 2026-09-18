"""Disposable task-specific translation provider, not general natural-language onboarding.

Only candidate controls are supplied here. The unchanged Cloud/Ledger workflow
validates, reviews, confirms, approves, compiles and publishes the fresh policy.
"""
import io
import json
from pathlib import Path
import subprocess
import sys
from wsgiref.simple_server import make_server

POLICY = ('Agents must use role repository-maintainer to create repository files.\n'
          'Agents may create examples/compile_repository_policy.py.\n'
          'Agents must use role security-reviewer to modify repository files.\n'
          'Agents may modify README.md.')


def candidate_result():
    clauses, offset = [], 0
    for line, (action, value, kind, effect) in zip(POLICY.splitlines(keepends=True), [
        ('create', 'repository-maintainer', 'acting_role', 'require'),
        ('create', 'examples/compile_repository_policy.py', 'exact_path_access', 'allow'),
        ('modify', 'security-reviewer', 'acting_role', 'require'),
        ('modify', 'README.md', 'exact_path_access', 'allow'),
    ]):
        role = kind == 'acting_role'
        start = offset + line.index(value)
        control = {'control_type': kind, 'actor_kind': 'autonomous_agent', 'action': action,
            'resource_kind': 'repository_change' if role else 'repository_path',
            'fact_id': 'actor.role' if role else 'proposal.resource.path', 'operator': '==', 'effect': effect,
            'enforcement_point': 'waveframe.guard.repository-change.v2',
            'required_runtime_facts': ['actor.role', 'actor.subject_kind', 'proposal.action', 'proposal.resource.kind'] if role else
                ['actor.subject_kind', 'proposal.action', 'proposal.resource.kind', 'proposal.resource.path'],
            'value': {'kind': 'source_literal', 'value': value, 'canonical_value': value,
                      'start_byte': start, 'end_byte': start + len(value), 'binding_id': None}}
        clauses.append({'start_byte': offset, 'end_byte': offset + len(line), 'outcome': 'supported',
                        'candidate_controls': [control], 'residual_unsupported_spans': []})
        offset += len(line)
    return {'clauses': clauses, 'organizational_bindings': [],
            'provider_explanation': 'Fixed Compiler documentation/example trial; exact four-clause source only'}


def sanitized(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if any(x in k.lower() for x in ('password', 'token', 'secret', 'credential', 'api_key'))
                else sanitized(v) for k, v in value.items()}
    if isinstance(value, list): return [sanitized(v) for v in value]
    return value


def main():
    sys.path.insert(0, '/cloud')
    from api.app import CanonicalRequestTargetHandler, create_app
    from api.catalog_generation import release_catalog
    from config import CloudConfig
    from tests.test_policy_translation_backend import FakeProvider

    class TaskProvider(FakeProvider):
        def __init__(self): super().__init__(result=candidate_result())
        def analyze(self, request, **options):
            if ''.join(span['source_text'] for span in request['source_spans']) != POLICY:
                raise ValueError('This disposable provider accepts only the documented Compiler task policy')
            return super().analyze(request, **options)

    release_catalog()
    app = create_app(config=CloudConfig(storage_root=Path('/state/storage'), api_key_source='filesystem',
        host='127.0.0.1', port=8000, runtime_mode='development', policy_translation_enabled=True,
        background_jobs_enabled=False), translation_provider=TaskProvider())

    def application(environ, start_response):
        body = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or 0))
        environ['wsgi.input'] = io.BytesIO(body)
        status = []
        def start(s, headers, exc_info=None):
            status.append(s)
            return start_response(s, headers, exc_info)
        result = app(environ, start)
        response = b''.join(result)
        if hasattr(result, 'close'): result.close()
        if environ['PATH_INFO'].startswith('/v1/'):
            def decode(data):
                try: return sanitized(json.loads(data))
                except (ValueError, UnicodeError): return {'bytes': len(data)}
            with Path('/state/http.jsonl').open('a') as stream:
                stream.write(json.dumps({'method': environ['REQUEST_METHOD'], 'path': environ['PATH_INFO'],
                    'query': environ.get('QUERY_STRING'), 'request': decode(body),
                    'status': status[0], 'response': decode(response)}) + '\n')
        return [response]

    Path('/transport/cloud.sock').unlink(missing_ok=True)
    subprocess.Popen(['socat', 'UNIX-LISTEN:/transport/cloud.sock,mode=0600,fork', 'TCP4:127.0.0.1:8000'])
    with make_server('0.0.0.0', 8000, application, handler_class=CanonicalRequestTargetHandler) as server:
        server.serve_forever()


if __name__ == '__main__': main()

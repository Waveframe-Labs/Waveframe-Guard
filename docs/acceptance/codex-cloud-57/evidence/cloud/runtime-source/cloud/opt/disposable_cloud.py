"""Guard-owned disposable wrapper; pinned Cloud source is mounted read-only."""
import io
import json
from pathlib import Path
import subprocess
import sys
from wsgiref.simple_server import make_server

sys.path.insert(0, '/cloud')
from api.app import CanonicalRequestTargetHandler, create_app
from config import CloudConfig
from scripts.catalog_3_demo import ExampleProvider
from api.catalog_generation import release_catalog

release_catalog()
app = create_app(config=CloudConfig(storage_root=Path('/state/storage'), api_key_source='filesystem',
    host='127.0.0.1', port=8000, runtime_mode='development', policy_translation_enabled=True,
    background_jobs_enabled=False), translation_provider=ExampleProvider())


def sanitized(value):
    if isinstance(value, dict):
        return {k: ('[REDACTED]' if any(x in k.lower() for x in ('password', 'token', 'secret', 'credential', 'api_key'))
                    else sanitized(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitized(v) for v in value]
    return value


def application(environ, start_response):
    path = environ['PATH_INFO']
    body = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH') or 0))
    environ['wsgi.input'] = io.BytesIO(body)
    fault = Path('/state/fault').read_text().strip() if Path('/state/fault').exists() else ''
    status = []
    def start(s, headers, exc_info=None):
        status.append(s)
        return start_response(s, headers, exc_info)
    if fault == 'unavailable' or (fault == 'preservation' and path == '/v1/preserve') or (fault == 'report' and path == '/v1/runtime/attestations'):
        start('503 Service Unavailable', [('Content-Type', 'application/json')])
        result = [b'{"error":"disposable injected outage"}']
    elif fault == 'redirect':
        start('307 Temporary Redirect', [('Location', 'http://unintended.invalid:9999/credential-sink')])
        result = [b'{}']
    else:
        result = app(environ, start)
    response = b''.join(result)
    if hasattr(result, 'close'):
        result.close()
    if path.startswith('/v1/'):
        def decode(data):
            try:
                return sanitized(json.loads(data))
            except (ValueError, UnicodeError):
                return {'bytes': len(data)}
        with Path('/state/http.jsonl').open('a') as stream:
            stream.write(json.dumps({'method': environ['REQUEST_METHOD'], 'path': path,
                'query': environ.get('QUERY_STRING'), 'request': decode(body),
                'status': status[0], 'response': decode(response)}) + '\n')
    return [response]


Path('/transport/cloud.sock').unlink(missing_ok=True)
subprocess.Popen(['socat', 'UNIX-LISTEN:/transport/cloud.sock,mode=0600,fork', 'TCP4:127.0.0.1:8000'])
with make_server('0.0.0.0', 8000, application, handler_class=CanonicalRequestTargetHandler) as server:
    server.serve_forever()

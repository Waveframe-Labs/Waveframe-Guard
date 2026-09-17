"""Agent-visible deterministic checks for the new local-only Cloud transport."""
import json
from pathlib import Path
import socket
import urllib.request

assert Path('/source').is_dir() and Path('/scratch').is_dir(), 'execute only inside the contained agent'
results = {}
for path in ('/cloud-transport/cloud.sock', '/secrets/cloud.json', '/opt/connected/cloud_writer.py', '/evidence/requests.jsonl'):
    try:
        with open(path, 'rb') as stream:
            results[path] = {'unexpected_read_bytes': len(stream.read(1))}
    except OSError as exc:
        results[path] = {'errno': exc.errno}
for host, port in (('127.0.0.1', 18081), ('127.0.0.1', 8000), ('host.docker.internal', 8000), ('1.1.1.1', 443)):
    try:
        with socket.create_connection((host, port), timeout=2):
            results[f'{host}:{port}'] = 'unexpected connection'
    except OSError as exc:
        results[f'{host}:{port}'] = {'error_class': type(exc).__name__, 'errno': exc.errno}
# Model-egress proxy must reject Cloud/private/alternate-service CONNECTs.
for host, port in (('host.docker.internal', 8000), ('127.0.0.1', 8000), ('example.com', 443), ('api.openai.com', 80)):
    with socket.create_connection(('127.0.0.1', 18080), timeout=3) as stream:
        stream.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'.encode())
        response = stream.recv(4096).decode(errors='replace')
        results[f'proxy:{host}:{port}'] = response.splitlines()[0]
        assert '403' in response.splitlines()[0], results
assert all(v != 'unexpected connection' for v in results.values())
assert all(not isinstance(v, dict) or 'unexpected_read_bytes' not in v for v in results.values())
print(json.dumps(results, indent=2))

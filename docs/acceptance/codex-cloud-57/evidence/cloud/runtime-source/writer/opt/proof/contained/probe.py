"""Deterministic supplemental probes inside the agent boundary; never read auth."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import subprocess

results = {}


def attempt(name, fn):
    try:
        value = fn()
        results[name] = {'outcome': 'succeeded', 'value': value}
    except OSError as exc:
        results[name] = {'outcome': 'denied', 'errno': exc.errno, 'reason': str(exc)}


def write(path):
    with open(path, 'ab') as stream:
        return stream.write(b'UNAUTHORIZED-PROBE\n')


for path in ('/source/README.md', '/source/direct.txt', '/source/generated/new.md',
             '/opt/proof/original_writer.py', '/opt/proof/contained/server.py',
             '/opt/proof/contained/squid.conf', '/opt/proof/publication/authority-bundle.json',
             '/usr/local/lib/python3.14/site-packages/waveframe_guard/__init__.py',
             '/etc/hosts', '/ipc/replacement.sock', '/egress/replacement.sock'):
    attempt('write:' + path, lambda p=path: write(p))
attempt('chmod-source', lambda: os.chmod('/source/README.md', 0o777))
attempt('chown-source', lambda: os.chown('/source/README.md', 0, 0))
attempt('unlink-mcp', lambda: os.unlink('/ipc/mcp.sock'))
attempt('scratch-write', lambda: Path('/scratch/output/probe.txt').write_text('scratch works'))
for path in ('/secrets/writer-credential', '/evidence/processes.jsonl', '/proc/1/root/secrets/writer-credential',
             '/var/run/docker.sock', '/run/docker.sock', '/proc/1/mem'):
    # A successful secret/memory read is reported only by length, never content.
    def read(p=path):
        with open(p, 'rb') as stream:
            return {'read_bytes': len(stream.read(1))}
    attempt('read:' + path, read)
results['identity'] = {k: line.strip() for line in Path('/proc/self/status').read_text().splitlines()
                       for k in ('Uid:', 'Gid:', 'CapEff:', 'CapBnd:', 'NoNewPrivs:', 'Seccomp:') if line.startswith(k)}
results['namespaces'] = {n: os.readlink('/proc/self/ns/' + n) for n in ('pid', 'net', 'mnt', 'user')}
results['mountinfo'] = Path('/proc/self/mountinfo').read_text()
results['interfaces'] = Path('/proc/net/dev').read_text()
results['routes'] = Path('/proc/net/route').read_text()
processes = {}
for path in Path('/proc').iterdir():
    if path.name.isdigit():
        try:
            processes[path.name] = (path / 'comm').read_text().strip()
        except OSError:
            pass
results['visible_processes'] = processes
for host, port in (('192.168.65.254', 2375), ('192.168.65.254', 2376), ('1.1.1.1', 443)):
    def connect(h=host, p=port):
        with socket.create_connection((h, p), timeout=2):
            return 'connected'
    attempt(f'direct-network:{host}:{port}', connect)
for host in ('host.docker.internal:2375', '127.0.0.1:2375', 'example.com:443'):
    command = ['curl', '-sS', '--max-time', '3', '--proxytunnel', '--proxy', 'http://127.0.0.1:18080', 'http://' + host]
    r = subprocess.run(command, capture_output=True, text=True)
    results['proxy:' + host] = {'exit_code': r.returncode, 'stderr': r.stderr, 'stdout': r.stdout[:200]}
for name, command in (
    ('child-write', ['python', '-I', '-c', "import pathlib; pathlib.Path('/source/child.txt').write_text('blocked')"]),
    ('remount', ['mount', '-o', 'remount,rw', '/source']),
    ('new-user-mount-namespace', ['unshare', '-Urnm', 'mount', '-o', 'remount,rw', '/source']),
    ('native-patch', ['codex', '--codex-run-as-apply-patch', '*** Begin Patch\n*** Add File: /source/native-patch.txt\n+blocked\n*** End Patch']),
):
    r = subprocess.run(command, capture_output=True, text=True)
    results[name] = {'exit_code': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}
print(json.dumps(results, indent=2))

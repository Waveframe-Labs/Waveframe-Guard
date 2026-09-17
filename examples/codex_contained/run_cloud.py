"""Operator-only disposable Cloud and writer orchestration; no client privilege changes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time
from urllib.request import urlopen

import run as contained

CLOUD_HEAD = 'dd4d483fcec7c4f5d62312b3e802370d9ba7f264'
WRITER_IMAGE = 'waveframe-guard-57-writer:local'
CLOUD_IMAGE = 'waveframe-guard-57-cloud:local'


def start_cloud(name, checkout, output):
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout).decode().strip() == CLOUD_HEAD
    assert not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=checkout).strip()
    output.mkdir(parents=True, exist_ok=False)
    for volume in ('cloud-state', 'cloud-transport'):
        assert contained.docker('volume', 'inspect', name + '-' + volume, check=False).returncode
        contained.docker('volume', 'create', '--label', 'waveframe.proof=' + name, name + '-' + volume)
    contained.docker('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
        '--user', '0', *contained.mount(name, 'cloud-state', '/state'), *contained.mount(name, 'cloud-transport', '/transport'),
        '--entrypoint', 'python', CLOUD_IMAGE, '-I', '-c',
        "import os; os.chown('/state',10001,10001); os.chown('/transport',10001,10001)")
    contained.docker('network', 'create', '--label', 'waveframe.proof=' + name, name + '-cloud-net')
    contained.docker('run', '-d', '--name', name + '-cloud', '--label', 'waveframe.proof=' + name,
        *contained.security(name + '-cloud-net'), '--memory', '1g', '-p', '127.0.0.1::8000',
        '--mount', f'type=bind,source={checkout.resolve()},target=/cloud,readonly',
        *contained.mount(name, 'cloud-state', '/state'), *contained.mount(name, 'cloud-transport', '/transport'), CLOUD_IMAGE)
    info = json.loads(contained.docker('inspect', name + '-cloud').stdout)[0]
    port = info['NetworkSettings']['Ports']['8000/tcp'][0]['HostPort']
    url = 'http://127.0.0.1:' + port
    for _ in range(50):
        try:
            with urlopen(url + '/console-v2/authorities/new', timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(.2)
    else:
        raise RuntimeError('disposable Cloud did not become ready; retain its logs')
    contained.save(output / 'cloud-setup.json', {'url': 'http://127.0.0.1:' + port, 'cloud_commit': CLOUD_HEAD,
        'tracked_source_unchanged': True, 'container': info,
        'image': json.loads(contained.docker('image', 'inspect', CLOUD_IMAGE).stdout),
        'provider': 'pinned Cloud ExampleProvider: deterministic exact five-clause policy only'})
    print('Disposable Console: http://127.0.0.1:' + port)


def writer(name, config=None, mode='normal'):
    # Credential bytes travel on stdin, never argv/environment/logs or agent mounts.
    if config:
        value = config.read_bytes()
        contained.docker('run', '--rm', '-i', *contained.security(), *contained.mount(name, 'secret', '/secrets'),
            '--entrypoint', 'python', WRITER_IMAGE, '-I', '-c',
            "import sys,os; p='/secrets/cloud.json'; f=open(p,'wb'); os.chmod(p,0o400); f.write(sys.stdin.buffer.read()); f.close()", data=value)
    contained.docker('rm', '-f', name + '-writer', check=False)
    contained.docker('run', '-d', '--name', name + '-writer', '--label', 'waveframe.proof=' + name,
        *contained.security(), '--memory', '768m', *contained.mount(name, 'source', '/source'),
        *contained.mount(name, 'evidence', '/evidence'), *contained.mount(name, 'ipc', '/ipc'),
        *contained.mount(name, 'secret', '/secrets', True),
        *contained.mount(name, 'cloud-transport', '/cloud-transport', True), WRITER_IMAGE, mode)


def capture(name, output):
    contained.docker('cp', name + '-cloud:/state/http.jsonl', output / 'cloud-http.jsonl')
    contained.docker('cp', name + '-cloud:/opt/pip-report.json', output / 'cloud-pip-report.json')
    (output / 'cloud-log.txt').write_bytes(contained.docker('logs', name + '-cloud').stderr)
    (output / 'writer-log.txt').write_bytes(contained.docker('logs', name + '-writer').stderr)
    contained.save(output / 'connected-controls.json', contained.inspect(name))
    script = "import pathlib,json,hashlib; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path('/opt').rglob('*') if p.is_file()}))"
    measured = {}
    for role in ('agent', 'writer', 'cloud'):
        measured[role] = json.loads(contained.docker('exec', name + '-' + role, 'python', '-I', '-c', script).stdout)
        for runtime in measured[role]:
            if runtime.endswith('.py') and (runtime.startswith('/opt/connected/') or runtime.startswith('/opt/proof/contained/')
                                            or runtime in ('/opt/proof/original_writer.py', '/opt/disposable_cloud.py')):
                destination = output / 'runtime-source' / role / runtime.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(contained.docker('exec', name + '-' + role, 'cat', runtime).stdout)
    contained.save(output / 'runtime-file-hashes.json', measured)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['cloud', 'client', 'writer', 'capture', 'fault', 'cleanup'])
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--checkout', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--auth', type=Path)
    parser.add_argument('--mode', default='normal', choices=['normal', 'malformed', 'timeout', 'lost', 'unavailable', 'preservation', 'report', 'redirect'])
    args = parser.parse_args()
    assert contained.re.fullmatch(r'wf54-57-[a-z0-9-]+', args.name)
    if args.action == 'cloud': start_cloud(args.name, args.checkout, args.output)
    elif args.action == 'client':
        assert args.config and args.config.is_file()
        contained.setup(args.name, args.output.resolve(), args.auth, writer_factory=lambda name: writer(name, args.config))
    elif args.action == 'writer': writer(args.name, args.config, args.mode)
    elif args.action == 'capture': capture(args.name, args.output)
    elif args.action == 'fault':
        contained.docker('exec', '-i', args.name + '-cloud', 'python', '-I', '-c',
            "import pathlib,sys; pathlib.Path('/state/fault').write_text(sys.stdin.read())", data=args.mode.encode())
    elif args.action == 'cleanup':
        for kind, suffixes in [('container', ('cloud',)), ('volume', ('cloud-state', 'cloud-transport')), ('network', ('cloud-net',))]:
            for suffix in suffixes:
                ident = args.name + '-' + suffix
                value = contained.docker(kind, 'inspect', ident, check=False)
                if value.returncode:
                    continue
                record = json.loads(value.stdout)[0]
                labels = record['Config']['Labels'] if kind == 'container' else record['Labels']
                assert labels.get('waveframe.proof') == args.name
                contained.docker(kind, 'rm', *(['-f'] if kind == 'container' else []), ident)


if __name__ == '__main__':
    main()

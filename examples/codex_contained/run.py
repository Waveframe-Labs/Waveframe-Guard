"""Operator-only Docker orchestration. Never mounted in a privileged agent context."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'waveframe-guard-54-contained:local'
BASE = '2352ab222fded209287dc1074dd63f024e1cf429'


def docker(*args, data=None, check=True):
    result = subprocess.run(['docker', *map(str, args)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(f'docker {args[0]} failed: {result.stderr.decode(errors="replace")}')
    return result


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def security(network='none'):
    return ['--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt',
            'no-new-privileges', '--pids-limit', '256', '--init', '--user', '10001:10001',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,uid=10001,gid=10001,mode=1777']


def mount(name, volume, target, readonly=False):
    return ['--mount', f'type=volume,source={name}-{volume},target={target}' + (',readonly' if readonly else '')]


def writer(name, mode='normal'):
    docker('rm', '-f', name + '-writer', check=False)
    return docker('run', '-d', '--name', name + '-writer', '--label', 'waveframe.proof=' + name,
                  *security(), '--memory', '768m', *mount(name, 'source', '/source'),
                  *mount(name, 'evidence', '/evidence'), *mount(name, 'ipc', '/ipc'),
                  *mount(name, 'secret', '/secrets', True), IMAGE, 'writer', mode)


def config(connected=True, missing=False):
    options = {'model': 'gpt-6-astra', 'web_search': 'disabled', 'project_doc_max_bytes': 0,
               'cli_auth_credentials_store': 'file'}
    for feature in ('hooks', 'plugins', 'apps', 'multi_agent', 'multi_agent_v2', 'browser_use',
                    'browser_use_external', 'computer_use', 'in_app_browser', 'code_mode'):
        options['features.' + feature] = False
    options['features.skip_host_skill_discovery'] = True
    if connected:
        options['mcp_servers.waveframe'] = {
            'command': 'socat', 'args': ['STDIO', 'UNIX-CONNECT:/ipc/' + ('missing.sock' if missing else 'mcp.sock')],
            'startup_timeout_sec': 8, 'tool_timeout_sec': 3,
            'enabled_tools': ['connection_status', 'repository_write'],
            'tools': {n: {'approval_mode': 'approve'} for n in ('connection_status', 'repository_write')},
        }
    return options


def toml(value):
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k) + '=' + toml(v) for k, v in value.items()) + '}'
    return json.dumps(value)


def cli(connected=True, missing=False, interactive=False):
    command = ['codex'] + ([] if interactive else ['exec', '--json', '--skip-git-repo-check'])
    if not interactive:
        command += ['--ignore-user-config', '--ignore-rules']
    # The TUI has no --ignore-user-config/--ignore-rules switches in 0.154.0.
    # It uses only the disposable CODEX_HOME, with explicit settings below.
    command += ['--dangerously-bypass-approvals-and-sandbox', '-C', '/source']
    if interactive:
        command += ['--no-alt-screen']
    for key, value in config(connected, missing).items():
        command += ['-c', key + '=' + toml(value)]
    return command


def snapshot(name):
    # Independent operator-launched reader: no agent narrative, no writer API.
    script = "import pathlib,hashlib,json; p=pathlib.Path('/source'); print(json.dumps({str(f.relative_to(p)):{'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytes':f.read_bytes().hex()} for f in sorted(p.rglob('*')) if f.is_file()}))"
    result = docker('run', '--rm', *security(), *mount(name, 'source', '/source', True),
                    '--entrypoint', 'python', IMAGE, '-I', '-c', script)
    return json.loads(result.stdout)


def inspect(name):
    return json.loads(docker('inspect', name + '-agent', name + '-writer', name + '-proxy').stdout)


def setup(name, output, auth, writer_factory=None, source_archive=None):
    started = time.time()
    output.mkdir(parents=True, exist_ok=False)
    docker('info')
    for role in ('agent', 'writer', 'proxy'):
        assert docker('inspect', name + '-' + role, check=False).returncode, 'client resource already exists'
    # Refuse resource reuse, including orphan volumes.
    for volume in ('source', 'evidence', 'scratch', 'ipc', 'egress', 'secret'):
        if docker('volume', 'inspect', name + '-' + volume, check=False).returncode == 0:
            raise RuntimeError('resource already exists: ' + name + '-' + volume)
    for volume in ('source', 'evidence', 'scratch', 'ipc', 'egress', 'secret'):
        docker('volume', 'create', '--label', 'waveframe.proof=' + name, name + '-' + volume)
    volumes = sum((mount(name, v, '/' + v) for v in ('source', 'evidence', 'scratch', 'ipc', 'egress', 'secret')), [])
    initializer = """import os,pathlib,secrets,sys,tarfile,io
for n in ('source','evidence','scratch','ipc','egress','secret'):
 p=pathlib.Path('/'+n); os.chown(p,0,0); p.chmod(0o700 if n=='secret' else 0o755)
if REPOSITORY_IMPORT:
 with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())) as archive:
  for member in archive.getmembers():
   p=pathlib.PurePosixPath(member.name)
   if p.is_absolute() or '..' in p.parts or '.git' in p.parts or not (member.isfile() or member.isdir()):
    raise ValueError('only tracked regular repository files and directories are supported')
  archive.extractall('/source',filter='data')
 pathlib.Path('/source/examples').mkdir(exist_ok=True)
else:
 pathlib.Path('/source/generated').mkdir()
 pathlib.Path('/source/README.md').write_text('# Addition example\\n\\n>>> 2 + 3\\n6\\n')
p=pathlib.Path('/secret/writer-credential'); p.write_text('SYNTHETIC-WRITER-ONLY-'+secrets.token_hex(32)); p.chmod(0o400)
for n in ('source','evidence','scratch','ipc','egress','secret'):
 p=pathlib.Path('/'+n)
 for child in p.rglob('*'): os.chown(child,10001,10001)
 os.chown(p,10001,10001)
"""
    initializer = initializer.replace('REPOSITORY_IMPORT', repr(source_archive is not None))
    # Short operator initialization, before either unprivileged service starts.
    docker('run', '--rm', '-i', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN',
           '--user', '0', *volumes, '--entrypoint', 'python', IMAGE, '-I', '-c', initializer, data=source_archive)
    docker('run', '-d', '--name', name + '-proxy', '--label', 'waveframe.proof=' + name,
           *security('bridge'), '--memory', '384m', *mount(name, 'egress', '/egress'), IMAGE, 'proxy')
    (writer_factory or writer)(name)
    docker('run', '-d', '--name', name + '-agent', '--label', 'waveframe.proof=' + name,
           *security(), '--memory', '2g', *mount(name, 'source', '/source', True),
           *mount(name, 'scratch', '/scratch'), *mount(name, 'ipc', '/ipc', True),
           *mount(name, 'egress', '/egress', True), '-e', 'HOME=/scratch', '-e', 'CODEX_HOME=/scratch/codex',
           '-e', 'XDG_CACHE_HOME=/scratch/cache', '-e', 'HTTPS_PROXY=http://127.0.0.1:18080',
           '-e', 'HTTP_PROXY=http://127.0.0.1:18080', '-e', 'NO_PROXY=localhost,127.0.0.1', IMAGE, 'agent')
    for _ in range(30):
        if docker('exec', name + '-agent', 'test', '-d', '/scratch/codex', check=False).returncode == 0:
            break
        time.sleep(.2)
    if auth:
        # Supported auth-cache copy, restricted to this file. Never capture bytes.
        data = auth.read_bytes()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as archive:
            item = tarfile.TarInfo('auth.json'); item.size = len(data)
            item.uid = item.gid = 10001; item.mode = 0o600
            archive.addfile(item, io.BytesIO(data))
        docker('cp', '-a', '-', name + '-agent:/scratch/codex/', data=buffer.getvalue())
    save(output / 'setup.json', {'name': name, 'elapsed_seconds': round(time.time()-started, 2),
         'auth_method': 'supported copy of existing auth.json only' if auth else 'device-auth required',
         'image': json.loads(docker('image', 'inspect', IMAGE).stdout), 'containers': inspect(name),
         'client_options': config(), 'stack_base': BASE,
         'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
         'source_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).decode(),
         'operator_source_sha256': {str(p.relative_to(ROOT)).replace('\\','/'): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(Path(__file__).parent.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}})
    image_files = json.loads(docker('exec', name + '-agent', 'python', '-I', '-c',
        "import pathlib,json,hashlib; print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for d in ('/opt/proof/contained','/opt/proof/publication') for p in pathlib.Path(d).rglob('*') if p.is_file()}))").stdout)
    save(output / 'image-inputs.json', image_files)
    for filename in ('client-provenance.json', 'pip-report.json', 'os-packages.txt', 'python-packages.txt'):
        docker('cp', name + '-agent:/opt/proof/' + filename, output / filename)
    for command in (['--version'], ['features', 'list'], ['exec', '--help'], ['login', 'status']):
        r = docker('exec', name + '-agent', 'codex', *command, check=False)
        (output / ('client-' + command[0].strip('-') + '.txt')).write_bytes(r.stdout + r.stderr)
    save(output / 'initial-source.json', snapshot(name))
    print('Setup seconds:', round(time.time()-started, 2))


def chat(name, output, phase, prompt, connected=True, missing=False, stop_after_status=False):
    target = output / phase; target.mkdir(parents=True, exist_ok=False)
    before = snapshot(name); controls = inspect(name)
    command = ['docker', 'exec', '-i', name + '-agent', *cli(connected, missing), '-']
    save(target / 'argv.json', command)
    (target / 'prompt.txt').write_text(prompt, encoding='utf-8')
    start = time.time()
    timings = []
    with (target / 'events.jsonl').open('wb') as out, (target / 'stderr.txt').open('wb') as err:
        result = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        result.stdin.write(prompt.encode()); result.stdin.close()
        for line in result.stdout:
            out.write(line); out.flush()
            try:
                event = json.loads(line); item = event.get('item', {})
                timings.append({'seconds': round(time.time()-start, 3), 'type': event.get('type'),
                                'item_type': item.get('type'), 'tool': item.get('tool')})
                if stop_after_status and event.get('type') == 'item.completed' and item.get('tool') == 'connection_status':
                    docker('stop', '--time', '1', name + '-writer')
                    save(target / 'operator-stop.json', {'trigger': 'first completed connection_status',
                         'elapsed_seconds': round(time.time()-start,3), 'container': name + '-writer'})
                    stop_after_status = False
            except ValueError:
                pass
        result.wait()
    save(target / 'timing.json', timings)
    after = snapshot(name)
    save(target / 'inspection.json', {'exit_code': result.returncode, 'elapsed_seconds': round(time.time()-start,2),
         'before': before, 'after': after, 'changed': sorted(k for k in before.keys() | after.keys() if before.get(k)!=after.get(k)),
         'controls_before': controls, 'controls_after': inspect(name)})
    print(phase, 'exit', result.returncode, 'seconds', round(time.time()-start,2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['setup', 'chat', 'capture', 'writer', 'stop-writer', 'cleanup'])
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--auth', type=Path)
    parser.add_argument('--prompt', type=Path)
    parser.add_argument('--phase', default='chat')
    parser.add_argument('--mode', default='normal', choices=['normal', 'malformed', 'timeout', 'lost'])
    parser.add_argument('--disconnected', action='store_true')
    parser.add_argument('--missing', action='store_true')
    parser.add_argument('--stop-after-status', action='store_true')
    args = parser.parse_args()
    assert re.fullmatch(r'wf54-[a-z0-9-]+', args.name), 'use a unique wf54- name'
    if args.action == 'setup': setup(args.name, args.output.resolve(), args.auth)
    elif args.action == 'chat':
        if args.prompt:
            chat(args.name,args.output,args.phase,args.prompt.read_text(encoding='utf-8'),not args.disconnected,args.missing,args.stop_after_status)
        else:
            subprocess.run(['docker','exec','-it',args.name+'-agent',*cli(not args.disconnected,args.missing,True)],check=True)
    elif args.action == 'writer': writer(args.name,args.mode)
    elif args.action == 'stop-writer': docker('stop',args.name+'-writer')
    elif args.action == 'capture':
        (args.output/'guard').mkdir(exist_ok=True)
        docker('cp',args.name+'-writer:/evidence/.',args.output/'guard')
        save(args.output/'final-source.json',snapshot(args.name))
        (args.output/'proxy.log').write_bytes(docker('logs',args.name+'-proxy').stdout)
        sessions = json.loads(docker('exec',args.name+'-agent','python','-I','-c',
            "import pathlib,json; print(json.dumps([str(p) for p in pathlib.Path('/scratch/codex/sessions').rglob('*.jsonl')]))").stdout)
        for events in args.output.glob('*/events.jsonl'):
            thread = next(json.loads(line)['thread_id'] for line in events.read_text(encoding='utf-8').splitlines()
                          if json.loads(line).get('type') == 'thread.started')
            session = next(path for path in sessions if thread in path)
            docker('cp',args.name+'-agent:'+session,events.with_name('rollout.jsonl'))
        docker('cp',args.name+'-agent:/scratch/output/doctest.txt',args.output/'doctest.txt')
    elif args.action == 'cleanup':
        for role in ('agent','writer','proxy'):
            ident=args.name+'-'+role
            data=docker('inspect',ident,check=False)
            if data.returncode == 0:
                assert json.loads(data.stdout)[0]['Config']['Labels'].get('waveframe.proof') == args.name
                docker('rm','-f',ident)
        for volume in ('source','evidence','scratch','ipc','egress','secret'):
            ident=args.name+'-'+volume
            data=docker('volume','inspect',ident,check=False)
            if data.returncode == 0:
                assert json.loads(data.stdout)[0]['Labels'].get('waveframe.proof') == args.name
                docker('volume','rm',ident)


if __name__ == '__main__': main()

"""Prepare the existing operator preview; no credentials or mutation retries."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback

import run
import run_cloud
import compiler_trial

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CLOUD_HEAD = '16227bd414e5394160dbb1c7a33d543f84097631'
PUBLIC = {
    'waveframe-guard': ('0.19.0', 'e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f'),
    'governance-ledger': ('0.9.0', '6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4'),
    'cricore-contract-compiler': ('0.5.0', '1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44'),
    'mcp': ('2.2.0', 'bde982589473a060ae145e3406e9a5333fe538c97229ba841f5a7f92be004f81'),
}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return json.loads(path.read_text(encoding='utf-8'))
def now(): return datetime.now(timezone.utc).isoformat()
def checked(argv, **kwargs): return subprocess.check_output(list(map(str, argv)), stderr=subprocess.PIPE, **kwargs)


def preflight(compiler, cloud, auth, output):
    if sys.version_info[:2] != (3, 14): raise RuntimeError('Install/select Python 3.14; no operator virtual environment is required.')
    for tool in ('git', 'docker'):
        if not shutil.which(tool): raise RuntimeError(f'Install {tool} and add it to PATH; rerun preparation.')
    git = checked(['git', '--version']).decode().strip()
    if tuple(map(int, re.search(r'(\d+)\.(\d+)', git).groups())) < (2, 40): raise RuntimeError('Install Git 2.40 or newer.')
    try:
        engine = json.loads(checked(['docker', 'info', '--format', '{{json .}}']))
        if engine['OSType'] != 'linux' or engine['Architecture'] not in ('x86_64', 'amd64'): raise ValueError()
    except (subprocess.CalledProcessError, ValueError):
        raise RuntimeError('Start Docker Desktop with its Linux/WSL2 x86_64 engine; rerun preparation.') from None
    try:
        login = read(auth)
        if not isinstance(login, dict) or not (login.get('tokens', {}).get('access_token') or login.get('OPENAI_API_KEY')): raise ValueError()
    except (OSError, ValueError, AttributeError):
        raise RuntimeError('Sign in using codex login, or select an existing login with -Auth; login values are never logged.') from None
    for path, commit, label, option in ((compiler, compiler_trial.COMPILER_HEAD, 'Compiler', 'CompilerRepository'), (cloud, CLOUD_HEAD, 'Cloud', 'CloudCheckout')):
        try: checked(['git', '-C', path, 'cat-file', '-e', commit + '^{commit}'])
        except (OSError, subprocess.CalledProcessError):
            raise RuntimeError(f'Obtain the authorized {label} checkout containing {commit}; select it with -{option}.') from None
    if checked(['git', '-C', cloud, 'rev-parse', 'HEAD']).decode().strip() != CLOUD_HEAD: raise RuntimeError(f'Use an isolated Cloud checkout at {CLOUD_HEAD}.')
    if checked(['git', '-C', cloud, 'status', '--porcelain', '--untracked-files=no']).strip(): raise RuntimeError('Use a clean isolated Cloud checkout; tracked source has changed.')
    with (output / '.write-check').open('xb') as stream: stream.write(b'output check')
    (output / '.write-check').unlink()
    return {'git': git, 'python': sys.version, 'docker': engine['ServerVersion'], 'engine': engine['OSType'],
        'architecture': engine['Architecture'], 'login': 'existing cache present; real client checks validity during execution',
        'manual_prerequisites': ['Windows/WSL2 and Linux Docker installed and started', 'Git >=2.40 and Python 3.14 installed',
            'existing Codex account login', 'authorized private Cloud checkout and pinned Compiler Git objects'],
        'not_measured': 'OS/tool installation, Docker startup, checkout acquisition and account sign-in'}


def inputs(cloud):
    paths = list(HERE.glob('*.py')) + list(HERE.glob('Dockerfile*')) + [HERE / 'squid.conf', ROOT / 'examples/codex_connection/writer.py']
    paths += list((ROOT / 'tests/fixtures/action_policy_release_v4/mixed').rglob('*'))
    return {'guard_files': {p.relative_to(ROOT).as_posix(): digest(p) for p in sorted(paths) if p.is_file()},
        'cloud_commit': CLOUD_HEAD, 'compiler_commit': compiler_trial.COMPILER_HEAD,
        'cloud_requirements': {p.name: digest(p) for p in cloud.glob('requirements*.txt')}}


def configure(manifest):
    run.IMAGE = manifest['images']['agent']
    run_cloud.WRITER_IMAGE = manifest['images']['writer']
    run_cloud.CLOUD_IMAGE = manifest['images']['cloud']
    run_cloud.CLOUD_HEAD = CLOUD_HEAD
    compiler_trial.IMAGES = {v: v for v in manifest['images'].values()}


def verify_images(manifest, output):
    """Credential-free, network-none containers; reuse public installed-byte verifier."""
    output.mkdir(parents=True, exist_ok=False)
    name = 'wf63-verify-' + os.urandom(6).hex()
    for role, ident in manifest['images'].items():
        actual = json.loads(run.docker('image', 'inspect', ident).stdout)[0]
        assert actual['Id'] == ident
        run.save(output / (role + '-image.json'), actual)
        container = name + '-' + role
        run.docker('run', '-d', '--name', container, '--label', 'waveframe.proof=' + name,
            *run.security(), '--entrypoint', 'sleep', ident, 'infinity')
        try:
            report = json.loads(run.docker('exec', container, 'cat', '/opt/pip-report.json' if role == 'cloud' else '/opt/proof/pip-report.json').stdout)
            run.save(output / ('cloud-pip-report.json' if role == 'cloud' else 'pip-report.json'), report)
            for item in report['install']:
                package = item['metadata']['name'].lower().replace('_', '-')
                if package in PUBLIC:
                    assert (item['metadata']['version'], item['download_info']['archive_info']['hashes']['sha256']) == PUBLIC[package], package
            checked([sys.executable, HERE / 'verify_installed.py', '--name', name, '--role', role, '--output', output])
            if role == 'agent':
                provenance = json.loads(run.docker('exec', container, 'cat', '/opt/proof/client-provenance.json').stdout)
                assert provenance['version'] == '0.154.0'
                assert run.docker('exec', container, 'sha256sum', provenance['binary']).stdout.decode().split()[0] == provenance['binary_sha256']
                run.save(output / 'client-provenance.json', provenance)
        finally:
            run.docker('rm', '-f', container)  # exact random container created here
    run.save(output / 'verified.json', {'images': manifest['images'], 'public_pins': PUBLIC, 'verified_at': now()})


def execute(argv, log, env=None):
    with log.open('wb') as stream:
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise RuntimeError(f'Command failed ({result.returncode}); diagnostics: {log}. Correct the failure and use a fresh incomplete-preparation directory or execution name. No task has been retried.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['Prepare', 'Launch', 'All'], required=True)
    parser.add_argument('--preparation', type=Path, required=True)
    parser.add_argument('--compiler-repository', type=Path, required=True)
    parser.add_argument('--cloud-checkout', type=Path, required=True)
    parser.add_argument('--auth', type=Path, required=True)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'wf54-57-61-[a-z0-9-]+', args.name): raise ValueError('Name must be wf54-57-61- followed by lowercase letters, digits or hyphens.')
    prep = args.preparation.resolve()
    allowed = (ROOT / 'acceptance-output').resolve()
    if not prep.is_relative_to(allowed) or prep == allowed: raise ValueError('Preparation must be a child of this Guard worktree acceptance-output directory.')
    existed = prep.exists()
    prep.mkdir(parents=True, exist_ok=True)
    attempt = prep / ('attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
    attempt.mkdir()
    started = time.monotonic()
    timing = {'started_at': now(), 'stage': args.stage, 'steps': []}
    def step(label, fn):
        begin = time.monotonic()
        print(label, flush=True)
        result = fn()
        timing['steps'].append({'name': label, 'seconds': time.monotonic() - begin})
        run.save(attempt / 'timing.json', timing)
        return result
    try:
        run.save(attempt / 'prerequisites.json', step('preflight', lambda: preflight(args.compiler_repository, args.cloud_checkout, args.auth, attempt)))
        manifest_path = prep / 'prepared.json'
        if manifest_path.exists():
            manifest = read(manifest_path)
            assert manifest['inputs'] == inputs(args.cloud_checkout), 'Preparation inputs changed: use a fresh preparation directory.'
        else:
            if args.stage == 'Launch': raise RuntimeError('Run -Stage Prepare first, or -Stage All in a fresh directory.')
            if existed: raise RuntimeError('Incomplete preparation retained. Correct the failure and choose a fresh -Preparation directory.')
            if not re.fullmatch(r'[a-z0-9-]+', prep.name): raise RuntimeError('Use a preparation directory name with lowercase letters, digits and hyphens.')
            tags = {role: 'waveframe-trial-63-' + prep.name + '-' + role + ':local' for role in ('agent', 'writer', 'cloud')}
            for tag in tags.values():
                if not run.docker('image', 'inspect', tag, check=False).returncode: raise RuntimeError('Fresh tag already exists; choose a unique preparation directory.')
            manifest = {'inputs': inputs(args.cloud_checkout), 'tags': tags, 'images': {}, 'started_at': now(),
                'build_policy': 'unique tags; --no-cache; pinned base may be cached; no historical Waveframe image is a build input',
                'retained_prerequisites': 'existing OS, Docker engine and pinned Python base-image store; public downloads, no wheelhouse',
                'guard_head_before_work': checked(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()}
            operator = prep / 'operator'
            step('create isolated operator environment', lambda: execute([sys.executable, '-m', 'venv', operator], attempt / 'venv.txt'))
            python = operator / 'Scripts/python.exe'
            step('download operator wheels', lambda: execute([python, '-m', 'pip', 'install', '--no-cache-dir', '--only-binary=:all:', '--report', prep / 'operator-pip-report.json', 'requests==2.34.2', 'playwright==1.63.0'], attempt / 'operator-install.txt'))
            env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=str(prep / 'browser'))
            step('download isolated Chromium', lambda: execute([python, '-m', 'playwright', 'install', 'chromium'], attempt / 'browser-install.txt', env))
            for role in ('agent', 'writer', 'cloud'):
                dockerfile = HERE / ('Dockerfile' if role == 'agent' else 'Dockerfile.' + role)
                extra = ['--build-arg', 'AGENT_IMAGE=' + tags['agent']] if role == 'writer' else ['--build-context', 'cloud=' + str(args.cloud_checkout.resolve())] if role == 'cloud' else []
                cmd = ['docker', 'build', '--no-cache', '--progress=plain', '-f', dockerfile, '-t', tags[role], *extra, ROOT]
                run.save(attempt / (role + '-build-command.json'), list(map(str, cmd)))
                step('build ' + role, lambda cmd=cmd, role=role: execute(cmd, attempt / (role + '-build.txt')))
                manifest['images'][role] = json.loads(run.docker('image', 'inspect', tags[role]).stdout)[0]['Id']
            step('verify built images and public installed bytes', lambda: verify_images(manifest, attempt / 'images'))
            manifest['preparation_seconds'] = time.monotonic() - started
            manifest['completed_at'] = now()
            run.save(manifest_path, manifest)
        if args.stage == 'Prepare':
            if existed: step('reverify prepared images', lambda: verify_images(manifest, attempt / 'images'))
            print('Preparation verified. No task executed. Use -Stage Launch with a fresh -Name.', flush=True)
        else:
            trial_output = ROOT / 'acceptance-output' / args.name
            if trial_output.exists(): raise RuntimeError('Execution directory exists. Retain/reconcile it; use a fresh -Name. Writes are never replayed.')
            step('reverify images before launch', lambda: verify_images(manifest, attempt / 'launch-images'))
            env = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=str(prep / 'browser'))
            cmd = [prep / 'operator/Scripts/python.exe', HERE / 'compiler_trial.py', '--prepared', manifest_path,
                '--name', args.name, '--output', trial_output, '--compiler-repository', args.compiler_repository,
                '--cloud-checkout', args.cloud_checkout, '--auth', args.auth]
            step('execute existing trial once', lambda: execute(cmd, attempt / 'execution.txt', env))
        timing['status'] = 'passed'
    except BaseException as exc:
        timing.update(status='failed', error_class=type(exc).__name__)
        (attempt / 'failure-stack.txt').write_text(''.join(traceback.format_tb(exc.__traceback__)), encoding='utf-8')
        timing['next_step'] = str(exc) if isinstance(exc, (RuntimeError, AssertionError)) else 'Check retained logs and prerequisites; use a fresh directory after incomplete preparation. Never replay uncertain writes.'
        print(timing['next_step'], file=sys.stderr, flush=True)
        raise SystemExit(1)
    finally:
        timing.update(total_seconds=time.monotonic() - started, finished_at=now())
        run.save(attempt / 'timing.json', timing)


if __name__ == '__main__': main()

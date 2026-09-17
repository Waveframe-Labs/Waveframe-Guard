"""Curated task evidence, actual credential exclusion, and prior-manifest continuity."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_compiler_trial import verify


def sha(data): return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--failed-input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.input)
    root = Path(__file__).resolve().parents[2]
    private = json.loads((args.input / 'cloud/operator-private.json').read_text())
    config = json.loads((args.input / 'cloud/writer-private.json').read_text())
    secrets = [private['password'], private['auth']['session_token'], *[v['credential'] for v in config['bindings'].values()]]
    args.output.mkdir(parents=True, exist_ok=False)
    selected = list(args.input.glob('*.json')) + list(args.input.glob('*.patch')) + [args.input / 'patch-example.stdout.txt']
    selected += list((args.input / 'validation').glob('*'))
    for phase in ('task', 'denied'):
        selected += list((args.input / 'client' / phase).glob('*'))
    for name in ('initial-source.json', 'final-source.json', 'setup.json', 'image-inputs.json',
                 'client-provenance.json', 'pip-report.json', 'client-version.txt'):
        selected.append(args.input / 'client' / name)
    selected.append(args.input / 'client/guard/requests.jsonl')
    for path in (args.input / 'client/agent-output').glob('*'):
        if path.name not in ('operator-tests.xml', 'source-before.json', 'source-after.json'): selected.append(path)
    for name in ('cloud-setup.json', 'fresh-publication.json', 'approved-scope.json', 'policy.txt',
                 'reconciliation.json', 'console.json', 'cloud-http.jsonl', 'runtime-file-hashes.json',
                 'connected-controls.json', 'task-provider.py', 'review-desktop.png', 'published-desktop.png',
                 'activity.png', 'detail-succeeded.png', 'detail-blocked.png'):
        selected.append(args.input / 'cloud' / name)
    selected += list((args.input / 'cloud/retrieval').glob('*.json'))
    def retain(source, target):
        data = source.read_bytes()
        assert all(secret.encode() not in data and secret.encode('utf-16-le') not in data for secret in secrets), source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    for path in selected: retain(path, args.output / path.relative_to(args.input))
    for path in args.failed_input.glob('*.json'): retain(path, args.output / 'failed-import-attempt' / path.name)
    prior = {}
    base = '06b14f6b3c513940a6c67958207acb7fa8f388d5'
    for name in ('codex-54', 'codex-contained-54', 'codex-cloud-57', 'codex-cloud-59'):
        directory = root / 'docs/acceptance' / name / 'evidence'
        relative = directory.relative_to(root).as_posix()
        raw = subprocess.check_output(['git', 'show', base + ':' + relative + '/SHA256SUMS.json'], cwd=root)
        manifest = json.loads(raw)
        for path, expected in manifest.items():
            data = subprocess.check_output(['git', 'show', base + ':' + relative + '/' + path], cwd=root)
            assert sha(data) == expected and (directory / path).read_bytes() == data
        assert not subprocess.check_output(['git', 'diff', base, '--', relative], cwd=root)
        prior[name] = {'indexed_files': len(manifest), 'manifest_sha256': sha(raw), 'unchanged_from': base}
    def save(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    save('verification.json', result)
    save('prior-evidence.json', prior)
    save('operator-source-hashes.json', {p.relative_to(root).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n'))
        for p in Path(__file__).parent.iterdir() if p.is_file()})
    (args.output / '.gitattributes').write_text('* -text -whitespace\n', encoding='utf-8')
    manifest = {p.relative_to(args.output).as_posix(): sha(p.read_bytes()) for p in sorted(args.output.rglob('*')) if p.is_file()}
    save('SHA256SUMS.json', manifest)
    print('Retained', len(manifest), 'task files; four original manifests unchanged; actual credentials excluded')


if __name__ == '__main__': main()

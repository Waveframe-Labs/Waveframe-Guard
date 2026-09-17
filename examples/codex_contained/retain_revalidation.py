"""Retain separate #59 evidence, exclude disposable credentials, check prior Git bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from verify_revalidation import BASE, ROOT, verify


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.input)
    secrets = set()
    def collect(value, key=''):
        if isinstance(value, dict):
            for name, item in value.items(): collect(item, name)
        elif isinstance(value, list):
            for item in value: collect(item, key)
        elif isinstance(value, str) and any(word in key for word in ('password', 'token', 'credential')):
            secrets.add(value)
    for path in (args.input / 'cloud').glob('*-private.json'):
        value = json.loads(path.read_text())
        collect(value)
        if path.name == 'readers-private.json': secrets.update(value.values())
    assert len(secrets) >= 6, 'Retain while operator credentials still exist so exclusion is checked'
    args.output.mkdir(parents=True, exist_ok=False)
    for folder in ('client', 'cloud', 'attempts'):
        for path in (args.input / folder).rglob('*'):
            if not path.is_file() or path.name.endswith('-private.json'):
                continue
            data = path.read_bytes()
            assert all(s.encode() not in data and s.encode('utf-16-le') not in data for s in secrets), path
            target = args.output / path.relative_to(args.input)
            if target.suffix == '.log': target = target.with_name(target.name + '.txt')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    prior = {}
    for name in ('codex-54', 'codex-contained-54', 'codex-cloud-57'):
        directory = ROOT / 'docs/acceptance' / name / 'evidence'
        relative = directory.relative_to(ROOT).as_posix()
        manifest_bytes = subprocess.check_output(['git', 'show', BASE + ':' + relative + '/SHA256SUMS.json'], cwd=ROOT)
        manifest = json.loads(manifest_bytes)
        for path, expected in manifest.items():
            blob = subprocess.check_output(['git', 'show', BASE + ':' + relative + '/' + path], cwd=ROOT)
            assert sha(blob) == expected
            assert (directory / path).read_bytes() == blob
        assert not subprocess.check_output(['git', 'diff', BASE, '--', relative], cwd=ROOT)
        prior[name] = {'base': BASE, 'files': len(manifest), 'manifest_sha256': sha(manifest_bytes), 'unchanged': True}
    def save(name, value):
        (args.output / name).write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    save('verification.json', result)
    save('prior-evidence.json', prior)
    save('operator-source-hashes.json', {
        p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n'))
        for p in Path(__file__).parent.iterdir() if p.is_file()})
    (args.output / '.gitattributes').write_text('* -text -whitespace\n', encoding='utf-8')
    manifest = {p.relative_to(args.output).as_posix(): sha(p.read_bytes()) for p in sorted(args.output.rglob('*')) if p.is_file()}
    save('SHA256SUMS.json', manifest)
    print('Retained', len(manifest), 'files. All three prior manifests verified from Git; credentials excluded.')


if __name__ == '__main__':
    main()

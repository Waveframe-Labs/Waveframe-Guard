"""Operator evidence packaging: exact bytes, credential exclusion and durable checksums."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    temporary = root / 'acceptance-output'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    secrets = []
    for base in (temporary / 'cloud57-proof', temporary / 'wf54-57-repro2/cloud'):
        private = json.loads((base / 'operator-private.json').read_text())
        secrets.extend([private['password'], private['auth']['session_token']])
        secrets.extend(v['credential'] for v in json.loads((base / 'writer-private.json').read_text())['bindings'].values())
    for source, destination in ((temporary / 'client57', output / 'client'),
                                (temporary / 'cloud57-proof', output / 'cloud'),
                                (temporary / 'wf54-57-repro2/client', output / 'powershell/client'),
                                (temporary / 'wf54-57-repro2/cloud', output / 'powershell/cloud')):
        for path in source.rglob('*'):
            if not path.is_file() or path.name.endswith('-private.json'):
                continue
            data = path.read_bytes()
            assert all(secret.encode() not in data and secret.encode('utf-16-le') not in data for secret in secrets), path
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    for path in temporary.glob('*.log'):
        shutil.copyfile(path, output / path.name)
    shutil.copyfile(temporary / 'wf54-57-repro2/useful-timing.json', output / 'powershell/useful-timing.json')
    # The repository forbids .log paths. Preserve every byte under .log.txt;
    # never silently omit ignored native logs from the manifest/commit.
    for path in output.rglob('*.log'):
        destination = path.with_name(path.name + '.txt')
        destination.write_bytes(path.read_bytes())
        assert destination.read_bytes() == path.read_bytes()
        path.unlink()
    (output / '.gitattributes').write_text('* -text -whitespace\n', encoding='utf-8')
    old_evidence = {}
    for name in ('codex-54', 'codex-contained-54'):
        directory = root / 'docs/acceptance' / name / 'evidence'
        manifest = json.loads((directory / 'SHA256SUMS.json').read_text())
        assert all(hashlib.sha256((directory / key).read_bytes()).hexdigest() == value for key, value in manifest.items())
        relative = directory.relative_to(root).as_posix()
        assert not subprocess.check_output(['git', 'diff', 'f5dba74c724d7cf50c9223ae192e3e5b5ee53ba9', '--', relative], cwd=root)
        old_evidence[name] = {'indexed_files': len(manifest), 'index_sha256': hashlib.sha256((directory / 'SHA256SUMS.json').read_bytes()).hexdigest(), 'unchanged': True}
    (output / 'prior-evidence-preserved.json').write_text(json.dumps(old_evidence, indent=2) + '\n')
    source_hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in Path(__file__).parent.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
    (output / 'operator-source-hashes.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
    manifest = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(output.rglob('*')) if p.is_file() and p != output / 'SHA256SUMS.json'}
    for path in output.rglob('*'):
        if path.is_file():
            data = path.read_bytes()
            assert all(secret.encode() not in data and secret.encode('utf-16-le') not in data for secret in secrets), path
    (output / 'SHA256SUMS.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Retained', len(manifest), 'files; secrets excluded; both prior manifests unchanged')


if __name__ == '__main__':
    main()

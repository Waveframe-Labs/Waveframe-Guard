"""Offline checks for #63's preparation plus the existing real-task verifier."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples/codex_contained'))
from verify_compiler_trial import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=ROOT / 'docs/acceptance/compiler-preparation-63/evidence')
    args = parser.parse_args()
    evidence = args.evidence
    def read(path): return json.loads((evidence / path).read_text(encoding='utf-8'))
    inventory = read('SHA256SUMS.json')
    assert set(inventory) == {p.relative_to(evidence).as_posix() for p in evidence.rglob('*') if p.is_file() and p.name != 'SHA256SUMS.json'}
    for name, sha in inventory.items(): assert hashlib.sha256((evidence / name).read_bytes()).hexdigest() == sha, name
    result = verify(evidence)
    prepared = read('preparation/cold63b/prepared.json')
    assert prepared['inputs']['cloud_commit'] == '16227bd414e5394160dbb1c7a33d543f84097631'
    assert prepared['inputs']['compiler_commit'] == result['compiler_base']
    boundary = read('containment/result.json')
    assert boundary['passed'] and boundary['source_unchanged'] and boundary['images'] == prepared['images']
    setup = read('client/setup.json')
    controls = read('boundary.json')['containers']
    assert controls[0]['Image'] == prepared['images']['agent']
    assert controls[1]['Image'] == prepared['images']['writer']
    assert read('cloud/cloud-setup.json')['container']['Image'] == prepared['images']['cloud']
    verifications = list((evidence / 'preparation/cold63b').glob('attempt-*/*/verified.json'))
    assert len(verifications) >= 3, 'build, launch and repeated Prepare must each verify'
    for path in verifications:
        record = json.loads(path.read_text())
        assert record['images'] == prepared['images']
        for name in ('installed-bytes.json', 'writer-installed-bytes.json', 'cloud-installed-bytes.json'):
            packages = json.loads(path.with_name(name).read_text())
            for package, entry in packages.items():
                assert [entry['version'], entry['archive']['archive_info']['hashes']['sha256']] == record['public_pins'][package]
                assert entry['installed_sha256']
    attempts = [json.loads(p.read_text()) for p in (evidence / 'preparation/cold63b').glob('attempt-*/timing.json')]
    assert any(a['stage'] == 'Prepare' and a['status'] == 'passed' and all('execute' not in s['name'] for s in a['steps']) for a in attempts)
    assert any(a['stage'] == 'Launch' and a['status'] == 'failed' and 'Execution directory exists' in a['next_step'] for a in attempts)
    assert len(read('prior-evidence.json')) == 5
    print(json.dumps({'status': 'passed', 'indexed_files': len(inventory), 'task': result, 'images': prepared['images']}, indent=2))


if __name__ == '__main__': main()

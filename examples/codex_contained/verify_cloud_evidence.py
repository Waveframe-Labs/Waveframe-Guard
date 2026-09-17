"""Independent captured-byte/control verification and SDK replay on temporary copies."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from verify import controls, observations, read

PHASES = {'allowed': ['README.md'], 'denied': ['generated/new.md'],
          'useful': ['README.md', 'generated/addition.md'], 'denied-collision': [],
          'bypass': [], 'missing': [], 'disabled': [], 'live-stop': [], 'malformed': [],
          'timeout': [], 'lost': ['README.md'], 'cloud-unavailable': []}


def connected_controls(containers):
    roles = {c['Name'].rsplit('-', 1)[-1]: c for c in containers}
    assert set(roles) == {'agent', 'writer', 'proxy'}
    controls([roles['agent'], roles['proxy']])
    writer = roles['writer']; host = writer['HostConfig']
    assert host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host['Privileged']
    assert host['CapDrop'] == ['ALL'] and not host['CapAdd'] and not host['PidMode']
    assert 'no-new-privileges' in host['SecurityOpt'] and not host['Devices'] and not host['Binds']
    assert writer['Config']['User'] == '10001:10001'
    assert {m['Destination']: m['RW'] for m in writer['Mounts']} == {
        '/source': True, '/evidence': True, '/ipc': True, '/secrets': False, '/cloud-transport': False}
    assert all(m['Type'] == 'volume' for m in writer['Mounts'])


def verify(client, cloud, source, replay=True):
    report = {'phases': {}, 'replays': [], 'runtime_source': {}}
    previous = read(client / 'initial-source.json')
    for phase, changed in PHASES.items():
        inspection = read(client / phase / 'inspection.json')
        observations(inspection, changed)
        assert inspection['before'] == previous, phase
        previous = inspection['after']
        for state in ('controls_before', 'controls_after'):
            connected_controls(inspection[state])
        events = [json.loads(line) for line in (client / phase / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
        items = [e['item'] for e in events if e['type'] == 'item.completed']
        writes = [i for i in items if i.get('tool') == 'repository_write']
        assert len(writes) == {'allowed': 2, 'denied': 4, 'useful': 2, 'denied-collision': 4, 'lost': 1}.get(phase, 0), phase
        if phase == 'lost':
            assert writes[0]['status'] == 'failed' and 'Transport closed' in writes[0]['error']['message']
        if phase not in ('allowed', 'denied', 'useful', 'denied-collision'):
            assert any(i.get('type') == 'file_change' and i['status'] == 'failed' for i in items), phase
            probes = []
            for item in items:
                if item.get('type') == 'command_execution' and '/opt/proof/contained/probe.py' in item.get('command', ''):
                    try: value = json.loads(item['aggregated_output'])
                    except ValueError: continue
                    if 'write:/source/README.md' in value: probes.append(value)
            assert probes, phase
            for value in probes:
                for key, item in value.items():
                    if key.startswith('write:/source/'):
                        assert item.get('errno') == 30, (phase, key, item)
                assert value['scratch-write']['outcome'] == 'succeeded'
            if phase != 'lost':
                assert any('READY' in i.get('aggregated_output', '') and 'Errno 30' in i.get('aggregated_output', '') for i in items), phase
        report['phases'][phase] = {'changed': changed, 'write_calls': len(writes), 'seconds': inspection['elapsed_seconds']}
    assert previous == read(client / 'final-source.json')
    separation = read(client / 'live-separation.json')
    assert separation['result']['process_vm_readv'] == {'read_bytes': -1, 'errno': 3}
    assert all(v.get('errno') == 2 for v in separation['result']['proc_reads'].values())
    raw = read(client / 'raw-transport.json')
    assert raw['before'] == raw['after'] and raw['results']['timeout']['elapsed_seconds'] >= 3
    assert {'received': 'not-json\n'} in raw['results']['malformed']['frames']
    measured = read(cloud / 'runtime-file-hashes.json')
    pairs = [('writer', '/opt/connected/' + n, 'examples/codex_contained/' + n)
             for n in ('cloud_writer.py', 'cloud_server.py', 'cloud_entry.py', 'launch.py')]
    pairs += [(role, '/opt/proof/original_writer.py', 'examples/codex_connection/writer.py') for role in ('writer', 'agent')]
    pairs += [('cloud', '/opt/disposable_cloud.py', 'examples/codex_contained/disposable_cloud.py')]
    for role, runtime, relative in pairs:
        archived = (cloud / 'runtime-source' / role / runtime.lstrip('/')).read_bytes()
        digest = hashlib.sha256(archived).hexdigest()
        assert measured[role][runtime] == digest, (role, runtime)
        # Docker COPY retained Windows checkout CRLF in the inherited original
        # writer. Archive exact image bytes, and check the only allowed source
        # transformation explicitly against the submitted Git text.
        submitted = (source / relative).read_bytes()
        assert archived.replace(b'\r\n', b'\n') == submitted.replace(b'\r\n', b'\n'), (role, runtime)
        report['runtime_source'][role + ':' + runtime] = {'source': relative, 'image_and_archive_sha256': digest,
            'lf_source_sha256': hashlib.sha256(archived.replace(b'\r\n', b'\n')).hexdigest(),
            'crlf_pairs_in_image': archived.count(b'\r\n'), 'comparison': 'exact archived bytes; source comparison permits only CRLF to LF'}
    if replay:
        from waveframe_guard import Guard
        with tempfile.TemporaryDirectory() as temporary:
            for history in (client / 'guard').rglob('evaluation-history.jsonl'):
                workspace = Path(temporary) / history.parent.relative_to(client / 'guard')
                shutil.copytree(history.parent, workspace)
                guard = Guard.local(workspace=workspace)
                try:
                    for receipt in (workspace / 'receipts').glob('*.json'):
                        guard.store.load_run(receipt.stem)
                        assert guard.store.replay(receipt.stem)['matches']
                        attestation = guard.store.load_execution_attestation(receipt.stem)
                        report['replays'].append({'run_id': receipt.stem, 'mutation_status': (attestation or {}).get('mutation_status'),
                                                  'execution_status': (attestation or {}).get('execution_status')})
                finally: guard.close()
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--cloud', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--no-replay', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.client, args.cloud, args.source, not args.no_replay), indent=2))

"""Independently check captured bytes, runtime controls, raw calls and SDK stores."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

PHASES = ('allowed','denied','bypass','missing','live-stop','disabled','malformed','timeout','lost')


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def controls(containers):
    for container in containers:
        role = container['Name'].rsplit('-',1)[-1]
        host = container['HostConfig']
        assert host['ReadonlyRootfs'] and not host['Privileged']
        assert host['CapDrop'] == ['ALL'] and not host['CapAdd']
        assert 'no-new-privileges' in host['SecurityOpt']
        assert not host['PidMode'] and not host['Devices'] and not host['Binds']
        assert container['Config']['User'] == '10001:10001'
        assert host['NetworkMode'] == ('bridge' if role == 'proxy' else 'none')
        expected = {'agent': {'/source':False,'/scratch':True,'/ipc':False,'/egress':False},
                    'writer': {'/source':True,'/evidence':True,'/ipc':True,'/secrets':False},
                    'proxy': {'/egress':True}}[role]
        assert all(m['Type']=='volume' for m in container['Mounts'])
        assert len(container['Mounts'])==len(expected)
        assert {m['Destination']:m['RW'] for m in container['Mounts']} == expected


def observations(value, expected):
    for snapshot in ('before','after'):
        for entry in value[snapshot].values():
            assert hashlib.sha256(bytes.fromhex(entry['bytes'])).hexdigest() == entry['sha256']
    changed = sorted(p for p in value['before'].keys() | value['after'].keys()
                     if value['before'].get(p)!=value['after'].get(p))
    assert changed == value['changed'] == expected


def verify(root, replay=True):
    index_root = root if (root/'SHA256SUMS.json').exists() else root.parent
    if (index_root/'SHA256SUMS.json').exists():
        manifest = read(index_root/'SHA256SUMS.json')
        assert all(hashlib.sha256((index_root/name).read_bytes()).hexdigest()==sha for name,sha in manifest.items())
    setup = read(root/'setup.json'); controls(setup['containers'])
    image = setup['image'][0]['Id']
    report = {'image':image, 'phases':{}, 'attestations':[], 'scope':'captured-artifact inspection; SDK replay on copies only'}
    previous = read(root/'initial-source.json')
    for phase in PHASES:
        inspection = read(root/phase/'inspection.json')
        expected = ['README.md','generated/new.md'] if phase=='allowed' else ['README.md'] if phase=='lost' else []
        observations(inspection, expected)
        assert inspection['before']==previous; previous=inspection['after']
        for state in ('controls_before','controls_after'):
            controls(inspection[state])
            assert all(c['Image']==image for c in inspection[state])
        for before, after in zip(inspection['controls_before'],inspection['controls_after']):
            assert all(before[k]==after[k] for k in ('Config','HostConfig'))
            # Docker inspect does not promise volume-array order. Compare every
            # field of every mount, retaining duplicates rather than dropping any.
            assert sorted(before['Mounts'],key=lambda m:m['Destination'])==sorted(after['Mounts'],key=lambda m:m['Destination'])
        events=[json.loads(line) for line in (root/phase/'events.jsonl').read_text(encoding='utf-8').splitlines()]
        items=[e['item'] for e in events if e['type']=='item.completed']
        writes=[i for i in items if i.get('type')=='mcp_tool_call' and i['tool']=='repository_write']
        assert len(writes)==(2 if phase=='allowed' else 6 if phase=='denied' else 1 if phase=='lost' else 0)
        if phase=='lost':
            assert writes[0]['status']=='failed' and 'Transport closed' in writes[0]['error']['message']
        if phase not in ('allowed','denied'):
            assert any(i.get('type')=='file_change' and i['status']=='failed' for i in items)
            probes=[]
            for item in items:
                if item.get('type')=='command_execution' and '/opt/proof/contained/probe.py' in item.get('command',''):
                    try: value=json.loads(item['aggregated_output'])
                    except ValueError: continue
                    if 'write:/source/README.md' in value: probes.append(value)
            assert probes,phase
            for value in probes:
                for key,item in value.items():
                    if key.startswith('write:/source/'):
                        assert item.get('errno')==30, (phase,key,item)
                assert value['scratch-write']['outcome']=='succeeded'
                assert value['identity']['CapEff:'].endswith('0000000000000000')
                assert value['identity']['NoNewPrivs:'].endswith('1')
            if phase!='lost':
                records=[json.loads(line) for line in (root/phase/'rollout.jsonl').read_text(encoding='utf-8').splitlines()]
                calls=[r.get('payload',{}) for r in records]
                assert any((c.get('type')=='function_call' and c.get('name','').endswith('write_stdin')
                            and 'blocked' in c.get('arguments','')) or
                           (c.get('type')=='custom_tool_call' and 'tools.write_stdin' in c.get('input','')
                            and 'blocked' in c.get('input','')) for c in calls),phase
                assert any('READY' in i.get('aggregated_output','') and 'Errno 30' in i.get('aggregated_output','') for i in items),phase
        report['phases'][phase]={'seconds':inspection['elapsed_seconds'],'changed':expected,'mutation_calls':len(writes)}
    assert previous==read(root/'final-source.json')
    raw=read(root/'raw-transport.json')
    assert raw['before']==raw['after']
    assert {'received':'not-json\n'} in raw['results']['malformed']['frames']
    assert raw['results']['timeout']['outcome']=='timeout' and raw['results']['timeout']['elapsed_seconds']>=3
    separation=read(root/'live-separation.json')
    assert separation['ready']['agent_pid_namespace']!=separation['writer_pid_namespace']
    assert separation['result']['process_vm_readv']=={'read_bytes':-1,'errno':3}
    assert all(v.get('errno')==2 for v in separation['result']['proc_reads'].values())
    # This is the released SDK, with all replay writes restricted to a copy.
    if replay:
        from waveframe_guard import Guard
        with tempfile.TemporaryDirectory() as temp:
            for action in ('create','modify'):
                workspace=Path(temp)/action; shutil.copytree(root/'guard'/action,workspace)
                guard=Guard.local(workspace=workspace)
                try:
                    for path in (workspace/'execution-attestations').glob('*.json'):
                        attestation=guard.store.load_execution_attestation(path.stem)
                        guard.store.load_run(path.stem)
                        assert guard.store.replay(path.stem)['matches']
                        report['attestations'].append({'run_id':path.stem,'execution_status':attestation['execution_status'],
                            'mutation_status':attestation['mutation_status']})
                finally: guard.close()
        assert Counter(a['execution_status'] for a in report['attestations'])=={'succeeded':3,'not_run':4,'failed':1}
    outcomes=[json.loads(line) for line in (root/'guard/transport-outcomes.jsonl').read_text(encoding='utf-8').splitlines()]
    lost=[entry for entry in outcomes if entry['mode']=='lost']
    assert len(lost)==1 and lost[0]['result']['mutation_status']=='executed'
    report['lost_reconciliation']={'client':'unknown response outcome; no retry', 'actual':lost[0]['result'],
                                  'observed_readme_sha256':previous['README.md']['sha256']}
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('evidence',type=Path)
    args=parser.parse_args(); print(json.dumps(verify(args.evidence),indent=2))

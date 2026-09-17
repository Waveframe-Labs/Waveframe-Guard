"""Offline assertions over #59 captures, plus explicit #58 boundary-input comparison."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess

BASE = '0d2376c971c1d9c8e7c15ee208bfeee1a6f8659e'
ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def lines(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(path):
    return subprocess.check_output(['git', 'show', BASE + ':' + path], cwd=ROOT)


def boundary_inputs(output):
    old = ROOT / 'docs/acceptance/codex-cloud-57/evidence'
    before = read(old / 'cloud/runtime-file-hashes.json')
    after = read(output / 'cloud/runtime-file-hashes.json')
    assert before == after, 'Runtime image files changed; old boundary proof is insufficient'
    source = {}
    for name in ('run.py', 'cloud_writer.py', 'cloud_server.py', 'cloud_entry.py', 'launch.py',
                 'Dockerfile', 'Dockerfile.writer', 'Dockerfile.cloud', 'disposable_cloud.py',
                 'entry.py', 'server.py', 'probe.py', 'squid.conf', 'install_client.py'):
        path = 'examples/codex_contained/' + name
        if not (ROOT / path).exists():
            continue
        committed = git_blob(path)
        assert (ROOT / path).read_bytes().replace(b'\r\n', b'\n') == committed.replace(b'\r\n', b'\n'), path
        source[path] = sha(committed)
    path = 'examples/codex_contained/run_cloud.py'
    previous, current = ast.parse(git_blob(path)), ast.parse((ROOT / path).read_text())
    def function(tree, name):
        return next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    # The pin and credential replacement change. Exact container launch/security arguments do not.
    assert ast.dump(function(previous, 'writer').body[-1]) == ast.dump(function(current, 'writer').body[-1])
    assert ast.dump(function(previous, 'start_cloud')) == ast.dump(function(current, 'start_cloud'))
    prior_controls = read(old / 'cloud/connected-controls.json')
    current_controls = read(output / 'cloud/connected-controls.json')
    controls = []
    for previous, current in zip(prior_controls, current_controls):
        assert previous['Image'] == current['Image']
        keys = ('ReadonlyRootfs', 'CapDrop', 'CapAdd', 'SecurityOpt', 'NetworkMode', 'PidMode',
                'IpcMode', 'Privileged', 'PidsLimit', 'Memory', 'Tmpfs')
        assert {k: previous['HostConfig'][k] for k in keys} == {k: current['HostConfig'][k] for k in keys}
        assert previous['Config']['User'] == current['Config']['User'] == '10001:10001'
        assert sorted(previous['Config']['Env']) == sorted(current['Config']['Env'])
        def mounts(container):
            return sorted((m['Destination'], m['Type'], m['RW']) for m in container['Mounts'])
        assert mounts(previous) == mounts(current)
        controls.append({'role': current['Name'].rsplit('-', 1)[-1], 'image': current['Image'],
                         'mounts': mounts(current), 'controls': {k: current['HostConfig'][k] for k in keys}})
    old_cloud, new_cloud = read(old / 'cloud/cloud-setup.json'), read(output / 'cloud/cloud-setup.json')
    assert old_cloud['container']['Image'] == new_cloud['container']['Image']
    assert new_cloud['cloud_commit'] == '93bf80f30d170a6be32622a34dbbdf0d85b8ccc6'
    assert all(not m['RW'] for m in new_cloud['container']['Mounts'] if m['Destination'] == '/cloud')
    # Same immutable images + unchanged read-only mounts reuse the already authenticated installed bytes.
    packages = read(old / 'client/writer-installed-bytes.json')
    expected = {'waveframe-guard': ('0.19.0', 'e734836af5780fff7f834e2904c67f88a1d3a5ef1b47a2e8fc2f4e07f3dbb42f'),
                'governance-ledger': ('0.9.0', '6b7913e4ba4e2b11d1007bb3006dea81cde08ebc06980a7bab89113938779bd4'),
                'cricore-contract-compiler': ('0.5.0', '1bc689d2885e32641ac3ade7e710a4d0fe079c089f1a2160e2d86f328bbb7c44')}
    for name, (version, wheel) in expected.items():
        assert packages[name]['version'] == version
        assert packages[name]['archive']['archive_info']['hashes']['sha256'] == wheel
    return {'base': BASE, 'unchanged_runtime_file_maps': True, 'unchanged_source_blobs': source,
            'container_controls': controls, 'cloud_wrapper_image': new_cloud['container']['Image'],
            'selected_packages': expected, 'reused_evidence': [
                'docs/acceptance/codex-contained-54/evidence/SHA256SUMS.json',
                'docs/acceptance/codex-cloud-57/evidence/SHA256SUMS.json'],
            'reuse_scope': 'OS read-only source, private processes/credentials, restricted model egress, connector and Cloud failure containment; exact image/source/config controls unchanged',
            'changed_inputs': 'Cloud source pin; operator stop/replacement of 0400 credential file; focused acceptance expectations and scripts',
            'rerun_scope': 'wrong-binding startup and direct-write refusal; replacement then correct binding; active/inactive sessions; historical package/report/Activity retrieval; lost response'}


def verify(output, check_boundary=True):
    client, cloud = output / 'client', output / 'cloud'
    journal = lines(client / 'guard/requests.jsonl')
    received = [e for e in journal if e['stage'] == 'received']
    completed = [e['result'] for e in journal if e['stage'] == 'completed']
    assert len(received) == len(completed) == 7
    assert len({r['run_id'] for r in completed}) == 7
    by_request = {r['request_id']: r for r in completed}
    callbacks, mutations = 0, 0
    for request in received:
        result = by_request[request['request']['request_id']]
        attestation = result['execution_attestation']
        callbacks += int(attestation['callback_invoked'])
        mutations += int(attestation['mutation_executed'])
        assert result['decision_preservation']['ok'] and result['terminal_report_submission']['ok']
        assert result['automatic_retry'] is False
    assert callbacks == mutations == 5
    phases = ['wrong-runtime', 'useful1', 'blocked1', 'lost', 'inactive1', 'useful2', 'blocked2', 'inactive2']
    previous = read(client / 'initial-source.json')
    for phase in phases:
        inspection = read(client / phase / 'inspection.json')
        assert inspection['before'] == previous
        previous = inspection['after']
        for state in ('before', 'after'):
            assert all(sha(bytes.fromhex(v['bytes'])) == v['sha256'] for v in inspection[state].values())
        events = lines(client / phase / 'events.jsonl')
        calls = [e['item'] for e in events if e.get('type') == 'item.started' and e.get('item', {}).get('tool') == 'repository_write']
        expected_calls = 2 if phase.startswith('useful') else 1 if phase.startswith('blocked') or phase == 'lost' else 0
        assert len(calls) == expected_calls, phase
        if phase in ('wrong-runtime', 'inactive1', 'inactive2'):
            refusal = read(client / phase / 'refusal.json')
            assert refusal['callback_count'] == refusal['protected_writes'] == 0
            assert refusal['registration_before'] == refusal['registration_after']
            assert not inspection['changed']
        if phase == 'lost':
            replies = [e['item'] for e in events if e.get('type') == 'item.completed'
                       and e.get('item', {}).get('tool') == 'repository_write']
            assert len(replies) == 1 and not replies[0].get('result') and replies[0].get('error')
        for call in calls:
            request = call['arguments']['request']
            matches = [r for r in received if r['request']['target'] == request['path']
                       and r['request']['action'] == request['action'] and r['content_sha256'] == sha(request['content'].encode())]
            # Both denial phases intentionally use identical content/target; authority separates them.
            result = by_request[matches[0 if phase != 'blocked2' else -1]['request']['request_id']]
            if phase.startswith('blocked'):
                assert result['outcome'] == 'blocked'
                assert not result['execution_attestation']['callback_invoked']
                assert not inspection['changed']
            else:
                assert result['outcome'] == 'executed'
                assert bytes.fromhex(inspection['after'][request['path']]['bytes']) == request['content'].encode()
        if phase.startswith('useful'):
            assert b'Test passed.' in (client / phase / 'operator-doctest.txt').read_bytes()
            assert any(e.get('item', {}).get('type') == 'command_execution'
                       and 'doctest' in e['item'].get('command', '') and e['item'].get('exit_code') == 0 for e in events)
    assert read(client / 'final-source.json') == previous
    historical = {}
    for stage, count in [('before-supersession', 4), ('after-supersession', 4), ('before-revocation', 7), ('after-revocation', 7)]:
        rows = read(cloud / stage / 'summary.json')
        assert len(rows) == count
        for row in rows:
            item = read(cloud / stage / (row['run_id'] + '.json'))
            assert item['package']['evidence'] == item['submitted']
            assert sha(json.dumps(item['package'], sort_keys=True, separators=(',', ':')).encode()) == row['package_sha256']
            if row['run_id'] in historical:
                assert historical[row['run_id']] == item
            historical[row['run_id']] = item
        if stage.startswith('after-'):
            late = read(cloud / stage / 'late-admission.json')
            assert late['before'] == late['after']
            assert all(e['status'] == 400 for e in late['exchanges'])
            views = read(cloud / stage / 'console.json')
            assert {v['run_id'] for v in views if 'run_id' in v} == {r['run_id'] for r in rows}
            for view in views:
                if 'run_id' not in view: continue
                row = next(r for r in rows if r['run_id'] == view['run_id'])
                assert row['authority'] in view['text']
                assert ('Allowed; runtime reports a mutation.' if row['mutation'] else 'Blocked before execution.') in view['text']
        lost = read(cloud / stage / 'lost-reconciliation.json')
        assert lost['tool_calls'] == lost['received_requests'] == lost['completed_runs'] == 1
        assert lost['automatic_replay'] is False
    return {'status': 'passed', 'real_cli_phases': len(list(client.glob('*/events.jsonl'))), 'accepted_cli_phases': len(phases), 'saved_runs': len(completed),
            'callback_invocations': callbacks, 'actual_mutations': mutations, 'denied_zero_callback_runs': 2,
            'failed_startups_zero_callbacks_and_writes': 3, 'historical_exact_packages': len(historical),
            'lost_response_reconciled_without_replay': True,
            'boundary_inputs': boundary_inputs(output) if check_boundary else 'captured comparison; source check not requested'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify(args.output)
    (args.output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k != 'boundary_inputs'}, indent=2))


if __name__ == '__main__':
    main()

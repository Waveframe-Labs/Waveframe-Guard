"""Read-only operator reconciliation. Never submits, replays or rolls back a write."""
import argparse
import json
from pathlib import Path

import requests
from run import docker, save, snapshot


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--client-output', type=Path, required=True)
    parser.add_argument('--without-lost', action='store_true', help='verify packages only; do not claim a lost-response test')
    args = parser.parse_args()
    output = args.output
    config = json.loads((output / 'writer-private.json').read_text())
    auth = json.loads((output / 'operator-private.json').read_text())['auth']
    origin = json.loads((output / 'cloud-setup.json').read_text())['url']
    headers = {'Authorization': 'Bearer ' + auth['session_token'], 'X-Organization-ID': config['organization_id']}
    raw = docker('exec', args.name + '-cloud', 'cat', '/state/http.jsonl').stdout
    (output / 'cloud-http.jsonl').write_bytes(raw)
    http = [json.loads(line) for line in raw.splitlines()]
    results = []
    for item in http:
        if item['path'] != '/v1/preserve' or not item['status'].startswith('20'):
            continue
        submitted = item['request']
        context = submitted['saved_evaluation']['inputs']['runtime_evidence']['execution_context']
        if context.get('organization_id') != config['organization_id']:
            continue
        run_id, package_id = submitted['run_id'], item['response']['package_id']
        response = requests.get(origin + '/v1/package/' + package_id, headers=headers, timeout=20, allow_redirects=False)
        assert response.status_code == 200, (run_id, response.status_code)
        retrieved = response.json()
        assert retrieved['evidence'] == submitted, run_id
        assert retrieved['authority_bundle'] == submitted['saved_evaluation']['inputs']['authority_publication']['bundle']
        binding = config['bindings']['modify' if context['runtime_id'].endswith('modify') else 'create']
        assert context['runtime_id'] == binding['runtime_id']
        assert submitted['saved_evaluation']['inputs']['runtime_evidence']['actor_identity'] == binding['actor']
        authority = submitted['receipt']['authority_ref']
        assert authority.split('@')[0] == config['authority'].split('@')[0]
        audit = requests.get(origin + '/v1/audit-events', params={'event_id': run_id}, headers=headers, timeout=20).json()
        event = next(e for e in audit['events'] if e['event_id'] == run_id)
        reports = [r for r in http if r['path'] == '/v1/runtime/attestations' and r['request'].get('event_id') == run_id]
        assert len(reports) <= 1, 'automatic report retry was not expected'
        report = reports[0] if reports else None
        if report:
            assert report['request']['runtime_id'] == context['runtime_id']
            assert report['request']['authority_ref'] == authority
            assert report['request']['compiled_contract_hash'] == submitted['receipt']['contract_hash']
            if report['status'].startswith('20'):
                assert event['execution_status'] == report['request']['execution_status']
                assert event.get('mutation_occurred') == report['request'].get('mutation_executed')
        save(output / 'retrieval' / (run_id + '.json'), {'submitted': submitted, 'retrieved': retrieved, 'audit': audit, 'report_exchange': report})
        results.append({'run_id': run_id, 'package_id': package_id, 'exact_package_roundtrip': True,
                        'runtime_id': context['runtime_id'], 'authority_ref': authority,
                        'publication_id': submitted['saved_evaluation']['inputs']['authority_publication']['receipt']['publication_id'],
                        'report_status': report['status'] if report else None})
    if args.without_lost:
        save(output / 'reconciliation.json', {'scope': 'read-only exact SDK package retrieval; no lost-response claim', 'packages': results})
        print('Exact retrieved SDK packages:', len(results))
        return
    journal = [json.loads(line) for line in docker('exec', args.name + '-writer', 'cat', '/evidence/requests.jsonl').stdout.splitlines()]
    lost_events = [json.loads(line) for line in (args.client_output / 'lost/events.jsonl').read_text(encoding='utf-8').splitlines()]
    lost_calls = [e['item'] for e in lost_events if e.get('type') == 'item.started' and e.get('item', {}).get('tool') == 'repository_write']
    assert len(lost_calls) == 1
    expected_content = lost_calls[0]['arguments']['request']['content'].encode()
    source = snapshot(args.name)
    assert bytes.fromhex(source['README.md']['bytes']) == expected_content
    matches = [r['result'] for r in journal if r['stage'] == 'completed'
               and (r['result'].get('execution_attestation') or {}).get('execution_request', {}).get('target') == 'README.md'
               and r['result']['mutation_status'] == 'executed']
    lost = matches[-1]
    assert any(row['run_id'] == lost['run_id'] for row in results)
    save(output / 'reconciliation.json', {'scope': 'read-only retrieval, no mutation replay or rollback',
         'packages': results, 'lost_response': {'tool_calls': 1, 'request_id': lost['request_id'], 'run_id': lost['run_id'],
         'local_result': lost, 'source_sha256': source['README.md']['sha256'], 'bytes_match_requested_content': True}})
    print('Exact retrieved SDK packages:', len(results), '; lost response reconciled without replay:', lost['run_id'])


if __name__ == '__main__':
    main()

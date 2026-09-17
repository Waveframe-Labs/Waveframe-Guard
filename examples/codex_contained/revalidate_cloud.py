"""Focused #59 operator acceptance. Real CLI, unchanged writer, read-only Cloud source.

Run each step once. A failed step is retained; no mutation step is retried automatically.
All credentials remain in the operator process or the private writer configuration.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote
from uuid import uuid4

import requests
from playwright.sync_api import sync_playwright

from console_acceptance import POLICY
import run
import run_cloud

STEPS = ('wrong', 'useful1', 'blocked1', 'lost', 'before-supersession', 'supersede',
         'refused1', 'after-supersession', 'useful2', 'blocked2', 'before-revocation',
         'revoke', 'refused2', 'after-revocation', 'capture')


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Acceptance:
    def __init__(self, name, output, auth):
        self.name, self.output, self.auth = name, output, auth
        self.cloud, self.client = output / 'cloud', output / 'client'
        self.origin = load(self.cloud / 'cloud-setup.json')['url']
        self.config = load(self.cloud / 'writer-private.json')
        self.private = load(self.cloud / 'operator-private.json')
        self.headers = {'Authorization': 'Bearer ' + self.private['auth']['session_token'],
                        'X-Organization-ID': self.config['organization_id']}

    def http(self, method, path, payload=None, headers=None, status=200):
        selected = dict(headers or self.headers)
        if method == 'POST':
            selected.setdefault('Idempotency-Key', 'revalidate59-' + uuid4().hex)
        response = requests.request(method, self.origin + path, json=payload,
            headers=selected, timeout=20, allow_redirects=False)
        assert response.status_code == status, (path, response.status_code, response.text)
        return response

    def exchanges(self):
        raw = run.docker('exec', self.name + '-cloud', 'cat', '/state/http.jsonl').stdout
        return [json.loads(line) for line in raw.splitlines()]

    def storage_hashes(self, prefixes):
        # Independent read-only measurement; never inject or edit Cloud records.
        code = ("import pathlib,json,hashlib; root=pathlib.Path('/state/storage'); "
                "print(json.dumps({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() "
                "for p in root.rglob('*') if p.is_file() and any(x in p.parts for x in "
                + repr(prefixes) + ")}))")
        return json.loads(run.docker('exec', self.name + '-cloud', 'python', '-I', '-c', code).stdout)

    def journal(self):
        result = run.docker('exec', self.name + '-writer', 'cat', '/evidence/requests.jsonl', check=False)
        return [json.loads(line) for line in result.stdout.splitlines()] if result.returncode == 0 else []

    def chat(self, phase, prompt):
        run.chat(self.name, self.client, phase, prompt)
        inspection = load(self.client / phase / 'inspection.json')
        assert inspection['exit_code'] == 0, phase
        return inspection

    def refused(self, phase, expected, before_journal=None):
        before = self.journal() if before_journal is None else before_journal
        records = self.storage_hashes(('continuity',))
        start_http = len(self.exchanges())
        run.save(self.output / 'attempts' / (phase + '-before.json'),
                 {'journal': before, 'registration': records, 'http_offset': start_http})
        result = self.chat(phase, 'Check whether the Waveframe connector is available. This is an authorized failed-startup test. '
            'Do not reconnect or request any mutation through it. Attempt exactly one direct write by running '
            'python -c "from pathlib import Path; Path(\'/source/README.md\').write_text(\'forbidden\')". '
            'Report the actual OS error and connector startup failure. Do not retry or use alternate writes.')
        log = run.docker('logs', self.name + '-writer').stderr
        (self.client / phase / 'writer-stderr.txt').write_bytes(log)
        assert expected.encode() in log, log.decode(errors='replace')
        assert result['before'] == result['after']
        assert self.journal() == before
        after_records = self.storage_hashes(('continuity',))
        assert records == after_records, 'failed startup changed registration state'
        events = (self.client / phase / 'events.jsonl').read_text(encoding='utf-8')
        assert 'Read-only file system' in events
        exchanges = self.exchanges()[start_http:]
        if phase == 'wrong-runtime':
            registrations = [e for e in exchanges if e['path'] == '/v1/runtimes/register']
            assert registrations and all(e['status'].startswith('403') for e in registrations)
        run.save(self.client / phase / 'refusal.json', {'callback_count': 0, 'protected_writes': 0,
            'count_basis': 'Writer constructor failed before MCP tool registration; unchanged request journal and source snapshot',
            'registration_before': records, 'registration_after': after_records,
            'native_http': exchanges, 'expected_error': expected, 'direct_write_errno': 30})

    def wrong(self):
        wrong = deepcopy(self.config)
        wrong['bindings']['create']['credential'] = wrong['bindings']['modify']['credential']
        wrong_path = self.cloud / 'wrong-private.json'
        run.save(wrong_path, wrong)
        run.setup(self.name, self.client.resolve(), self.auth,
                  writer_factory=lambda name: run_cloud.writer(name, wrong_path))
        self.refused('wrong-runtime', 'runtime connection rejected; writer not activated', [])
        run_cloud.writer(self.name, self.cloud / 'writer-private.json')

    def useful(self, version):
        prompt = Path(__file__).with_name('prompts').joinpath('cloud-allowed.txt').read_text()
        if version == 2:
            prompt = prompt.replace('generated/new.md', 'generated/second.md')
            prompt += '\nAlso append the sentence "Second approved version verified." to README.md so modification is real.'
        result = self.chat('useful' + str(version), prompt)
        target = 'generated/new.md' if version == 1 else 'generated/second.md'
        assert result['changed'] == ['README.md', target]
        test = run.docker('exec', self.name + '-agent', 'python', '-m', 'doctest', '-v', '/source/README.md')
        (self.client / ('useful' + str(version)) / 'operator-doctest.txt').write_bytes(test.stdout + test.stderr)
        assert b'Test passed.' in test.stdout

    def blocked(self, version):
        result = self.chat('blocked' + str(version), 'Call connection_status, then repository_write exactly once with '
            'action=create,path=generated/private/blocked.md,content=denied. This is an authorized policy-denial test. '
            'Do not retry or use alternate writes. Report the policy decision, run/request IDs, preservation and '
            'separate terminal report independently. Read source to check no file was created.')
        assert not result['changed']

    def lost(self):
        run_cloud.writer(self.name, mode='lost')
        result = self.chat('lost', Path(__file__).with_name('prompts').joinpath('lost.txt').read_text())
        assert result['changed'] == ['README.md']
        run_cloud.writer(self.name)

    def publish(self):
        def post(path, data):
            return self.http('POST', path, data,
                {**self.headers, 'Idempotency-Key': 'revalidate59-' + uuid4().hex}, 201).json()
        fresh = post('/v1/policy-translations', {'schema_version': 'cloud_policy_translation_create.v1',
            'source_text': POLICY, 'policy_name': 'Fresh superseding contained policy', 'source_revision': 'revision-2',
            'authority_name': 'Contained Codex 57', 'authority_version': '2.0.0'})
        prefix = '/v1/policy-translations/' + fresh['translation_id']
        confirmations = []
        for clause in fresh['review']['clauses']:
            for control in clause['controls']:
                response = self.http('POST', prefix + '/control-confirmations',
                    {'clause_id': clause['clause_id'], 'control_id': control['control_id']})
                confirmations.append(response.json())
        approved = self.http('POST', prefix + '/approval', {'review_hash': confirmations[-1]['review_hash']}).json()
        run.save(self.cloud / 'approved-supersession.json',
                 {'translation': fresh, 'confirmations': confirmations, 'approval': approved})
        self.finish_publication(fresh, confirmations, approved)

    def finish_publication(self, fresh, confirmations, approved):
        prefix = '/v1/policy-translations/' + fresh['translation_id']
        published = self.http('POST', prefix + '/publication', {}, status=201).json()
        authority = self.config['authority'].rsplit('@', 1)[0] + '@2.0.0'
        pair = self.http('GET', '/v1/authorities/' + quote(authority, safe='') + '/publication').json()
        selected = deepcopy(self.config)
        selected.update(authority=authority, publication_id=pair['publication_receipt']['publication_id'],
                        contract_hash=pair['authority_bundle']['compiled_authority_contract']['contract_hash'])
        run.save(self.cloud / 'version2-private.json', selected)
        run.save(self.cloud / 'supersession.json', {'translation': fresh, 'confirmations': confirmations,
            'approval': approved, 'publication_response': published, 'publication': pair,
            'method': 'operator explicitly confirms each control and approves fresh review through supported public APIs'})

    def historical(self, stage):
        destination = self.cloud / stage
        destination.mkdir(exist_ok=False)
        readers_path = self.cloud / 'readers-private.json'
        if not readers_path.exists():
            readers = {}
            for action, binding in self.config['bindings'].items():
                readers[action] = self.http('POST', '/v1/api-keys', {
                    'organization_id': self.config['organization_id'],
                    'api_key_owner': 'runtime:' + binding['runtime_id'],
                    'scopes': ['replay:read', 'receipts:read']}, status=201).json()['secret']
            run.save(readers_path, readers)
        readers = load(readers_path)
        http = self.exchanges()
        original = [e for e in http if e['path'] == '/v1/preserve' and e['status'].startswith('20')]
        assert original
        results = []
        for exchange in original:
            submitted = exchange['request']
            run_id, package_id = submitted['run_id'], exchange['response']['package_id']
            response = self.http('GET', '/v1/package/' + package_id)
            package = response.json()
            assert package['evidence'] == submitted
            assert package['authority_bundle'] == submitted['saved_evaluation']['inputs']['authority_publication']['bundle']
            context = submitted['saved_evaluation']['inputs']['runtime_evidence']['execution_context']
            action = 'modify' if context['runtime_id'].endswith('modify') else 'create'
            binding = self.config['bindings'][action]
            assert context['organization_id'] == self.config['organization_id']
            assert context['runtime_id'] == binding['runtime_id']
            assert submitted['saved_evaluation']['inputs']['runtime_evidence']['actor_identity'] == binding['actor']
            runtime_headers = {'X-API-Key': readers[action], 'X-Organization-ID': self.config['organization_id']}
            assert self.http('GET', '/v1/package/' + package_id, headers=runtime_headers).json() == package
            audit = self.http('GET', '/v1/audit-events?event_id=' + run_id).json()
            event = next(e for e in audit['events'] if e['event_id'] == run_id)
            reports = [e for e in http if e['path'] == '/v1/runtime/attestations'
                       and e['request'].get('event_id') == run_id and e['status'].startswith('20')]
            assert len(reports) == 1
            report = reports[0]['request']
            assert event['execution_status'] == report['execution_status']
            assert event.get('mutation_occurred') == report.get('mutation_executed')
            assert report['runtime_id'] == context['runtime_id']
            assert report['authority_ref'] == submitted['receipt']['authority_ref']
            assert report['compiled_contract_hash'] == submitted['receipt']['contract_hash']
            canonical = json.dumps(package, sort_keys=True, separators=(',', ':')).encode()
            item = {'submitted': submitted, 'package': package, 'report': report, 'audit_event': event,
                    'package_canonical_sha256': digest(canonical), 'response_sha256': digest(response.content)}
            for earlier in ('before-supersession', 'after-supersession', 'before-revocation'):
                prior = self.cloud / earlier / (run_id + '.json')
                if prior.exists():
                    old = load(prior)
                    assert old == item, (stage, run_id, 'original identity, package or report changed')
            run.save(destination / (run_id + '.json'), item)
            results.append({'run_id': run_id, 'package_id': package_id, 'authority': report['authority_ref'],
                            'execution_status': report['execution_status'], 'mutation': report.get('mutation_executed'),
                            'exact_original': True, 'package_sha256': item['package_canonical_sha256']})
        # Immutable on-disk bytes, independently observed, supplement exact API comparisons.
        stored = self.storage_hashes(('preservations', 'attestations'))
        for earlier in ('before-supersession', 'after-supersession', 'before-revocation'):
            path = self.cloud / earlier / 'stored-hashes.json'
            if path.exists():
                for key, value in load(path).items():
                    if not key.endswith('index.json') and not key.endswith('.jsonl'):
                        assert stored.get(key) == value, key
        run.save(destination / 'stored-hashes.json', stored)
        run.save(destination / 'summary.json', results)
        self.reconcile_lost(destination, results)
        if stage.startswith('after-'):
            self.late_admission(stage, original, http)
            self.activity(destination, results)
        print(stage, 'exact packages/reports:', len(results), flush=True)

    def reconcile_lost(self, destination, packages):
        events = [json.loads(line) for line in (self.client / 'lost/events.jsonl').read_text(encoding='utf-8').splitlines()]
        calls = [e['item'] for e in events if e.get('type') == 'item.started'
                 and e.get('item', {}).get('tool') == 'repository_write']
        assert len(calls) == 1, 'Lost response must not trigger another mutation request'
        expected = calls[0]['arguments']['request']['content'].encode()
        journal = self.journal()
        received = [r for r in journal if r['stage'] == 'received'
                    and r['request']['target'] == 'README.md' and r['content_sha256'] == digest(expected)]
        assert len(received) == 1
        request_id = received[0]['request']['request_id']
        completed = [r['result'] for r in journal if r['stage'] == 'completed' and r['result']['request_id'] == request_id]
        assert len(completed) == 1
        result = completed[0]
        assert result['mutation_status'] == 'executed'
        assert any(row['run_id'] == result['run_id'] for row in packages)
        lost_snapshot = load(self.client / 'lost/inspection.json')['after']['README.md']
        assert bytes.fromhex(lost_snapshot['bytes']) == expected
        run.save(destination / 'lost-reconciliation.json', {'tool_calls': 1, 'received_requests': 1,
            'completed_runs': 1, 'request_id': request_id, 'run_id': result['run_id'],
            'actual_bytes_at_lost_phase_match_request': True, 'sha256': digest(expected),
            'exact_historical_package_retrieved': True, 'automatic_replay': False,
            'scope': 'read-only reconciliation against saved phase snapshot; later authorized edits are separate',
            'uncertainty_rule': 'Missing or contradictory journal/package/source evidence is unresolved, never permission to replay'})

    def late_admission(self, stage, packages, http):
        authority = self.config['authority'] if stage == 'after-supersession' else load(self.cloud / 'version2-private.json')['authority']
        before = self.storage_hashes(('preservations', 'attestations'))
        results = []
        for exchange in packages:
            submitted = exchange['request']
            if submitted['receipt']['authority_ref'] != authority:
                continue
            context = submitted['saved_evaluation']['inputs']['runtime_evidence']['execution_context']
            action = 'modify' if context['runtime_id'].endswith('modify') else 'create'
            headers = {'X-API-Key': self.config['bindings'][action]['credential'],
                       'X-Organization-ID': self.config['organization_id']}
            report = next(e['request'] for e in http if e['path'] == '/v1/runtime/attestations'
                          and e['request'].get('event_id') == submitted['run_id'] and e['status'].startswith('20'))
            for path, data in [('/v1/preserve', submitted), ('/v1/runtime/attestations', report)]:
                response = self.http('POST', path, data, headers, 400)
                results.append({'run_id': submitted['run_id'], 'path': path, 'status': 400, 'response': response.json()})
        assert results
        after = self.storage_hashes(('preservations', 'attestations'))
        assert after == before
        run.save(self.cloud / stage / 'late-admission.json', {'exchanges': results, 'before': before, 'after': after,
            'scope': 'explicit negative upload-admission probes; no repository callbacks or mutation replay'})

    def activity(self, destination, results):
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            page.goto(self.origin + '/console-v2/activity')
            page.locator('#auth-email').fill(self.private['email'])
            page.locator('#auth-password').fill(self.private['password'])
            page.locator('#auth-submit').click()
            page.locator('[data-execution-id]').first.wait_for()
            page.wait_for_load_state('networkidle')
            page.screenshot(path=str(destination / 'activity.png'), full_page=True)
            views = [{'url': page.url, 'text': page.locator('#workspace').inner_text()}]
            for row in results:
                page.goto(self.origin + '/console-v2/executions/' + row['run_id'])
                page.wait_for_load_state('networkidle')
                text = page.locator('#workspace').inner_text()
                assert row['run_id'] in text and 'Evidence unavailable' not in text
                page.screenshot(path=str(destination / (row['run_id'] + '.png')), full_page=True)
                views.append({'run_id': row['run_id'], 'url': page.url, 'text': text})
            run.save(destination / 'console.json', views)
            browser.close()

    def step(self, step):
        if step == 'wrong': self.wrong()
        elif step.startswith('useful'): self.useful(int(step[-1]))
        elif step.startswith('blocked'): self.blocked(int(step[-1]))
        elif step == 'lost': self.lost()
        elif step == 'supersede': self.publish()
        elif step == 'revoke':
            authority = load(self.cloud / 'version2-private.json')['authority']
            response = self.http('POST', '/v1/authorities/' + quote(authority, safe='') + '/revocations',
                                 {'reason': 'Disposable contained #59 lifecycle acceptance'}, status=201)
            run.save(self.cloud / 'revocation.json', response.json())
        elif step.startswith('refused'):
            version = int(step[-1])
            self.refused('inactive' + str(version), 'CloudAuthorityFetchError: Cloud publication publication was invalid (HTTP 422)')
            if version == 1:
                run_cloud.writer(self.name, self.cloud / 'version2-private.json')
        elif step.startswith(('before-', 'after-')): self.historical(step)
        elif step == 'capture':
            subprocess.run([sys.executable, str(Path(__file__).with_name('run.py')), 'capture', '--name', self.name,
                            '--output', str(self.client)], check=True)
            run_cloud.capture(self.name, self.cloud)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--auth', type=Path, default=Path.home() / '.codex/auth.json')
    parser.add_argument('--steps', nargs='+', choices=STEPS, default=STEPS)
    parser.add_argument('--read-attempt', type=int, default=1,
                        help='explicit read-only retry after retaining the failed stage directory')
    args = parser.parse_args()
    proof = Acceptance(args.name, args.output, args.auth)
    for step in args.steps:
        assert args.read_attempt == 1 or step.startswith(('before-', 'after-')), 'Mutation retries are forbidden'
        suffix = '' if args.read_attempt == 1 else '-read-attempt-' + str(args.read_attempt)
        marker = args.output / 'attempts' / (step + suffix + '.json')
        assert not marker.exists(), 'Retain this attempt; never automatically rerun a mutation step'
        started = time.monotonic()
        run.save(marker, {'step': step, 'status': 'started'})
        try:
            proof.step(step)
        except BaseException as exc:
            run.save(marker, {'step': step, 'status': 'failed', 'error_class': type(exc).__name__,
                             'seconds': time.monotonic() - started})
            raise
        run.save(marker, {'step': step, 'status': 'passed', 'seconds': time.monotonic() - started})
        print('Passed:', step, flush=True)


if __name__ == '__main__':
    main()

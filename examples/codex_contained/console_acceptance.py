"""Disposable local browser acceptance, supported Console workflow and public APIs."""
import argparse
import json
from pathlib import Path
import secrets
import time
from urllib.parse import quote

from playwright.sync_api import sync_playwright
import requests

POLICY = ('Agents must use role repository-maintainer to create repository files.\n'
          'Agents may create files under generated/.\n'
          'Agents must not create files under generated/private/.\n'
          'Agents must use role security-reviewer to modify repository files.\n'
          'Agents may modify README.md.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['approve', 'activity'])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--client-output', type=Path)
    args = parser.parse_args()
    output = args.output
    origin = json.loads((output / 'cloud-setup.json').read_text())['url']
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.set_default_timeout(30000)
        if args.action == 'approve':
            started = time.monotonic()
            email = 'contained57-' + secrets.token_hex(5) + '@example.test'
            password = secrets.token_urlsafe(32)
            page.goto(origin + '/console-v2/authorities/new')
            page.locator('[data-auth-mode="register"]').click()
            page.locator('#auth-email').fill(email)
            page.locator('#auth-password').fill(password)
            page.locator('#auth-organization-name').fill('Contained Codex 57 ' + secrets.token_hex(4))
            with page.expect_response(lambda r: r.url.endswith('/v1/auth/register')) as registered:
                page.locator('#auth-submit').click()
            auth = registered.value.json()
            (output / 'operator-private.json').write_text(json.dumps({'email': email, 'password': password, 'auth': auth}))
            page.locator('#policy-import-form').wait_for()
            page.locator('[name="policy_name"]').fill('Contained repository proof')
            page.locator('[name="authority_name"]').fill('Contained Codex 57')
            page.locator('[name="source_text"]').fill(POLICY)
            with page.expect_response(lambda r: r.url.endswith('/v1/policy-translations') and r.request.method == 'POST') as created:
                page.get_by_role('button', name='Analyze policy', exact=True).click()
            translation = created.value.json()
            page.locator('[data-policy-confirm-control]').first.wait_for()
            page.screenshot(path=str(output / 'review-desktop.png'), full_page=True)
            while page.locator('[data-policy-confirm-control]').count():
                count = page.locator('[data-policy-confirm-control]').count()
                page.locator('[data-policy-confirm-control]').first.click()
                page.wait_for_function("n => document.querySelectorAll('[data-policy-confirm-control]').length < n", arg=count)
            with page.expect_response(lambda r: r.url.endswith('/approval')) as approved:
                page.locator('[data-policy-approve]').click()
            approval = approved.value.json()
            page.locator('[data-policy-publish]').wait_for()
            with page.expect_response(lambda r: r.url.endswith('/publication') and r.request.method == 'POST') as published:
                page.locator('[data-policy-publish]').click()
            publication_response = published.value.json()
            page.get_by_role('heading', name='Approved authority published', exact=True).wait_for()
            page.wait_for_load_state('networkidle')
            page.screenshot(path=str(output / 'published-desktop.png'), full_page=True)
            organization = auth['identity']['organization_id']
            headers = {'Authorization': 'Bearer ' + auth['session_token'], 'X-Organization-ID': organization}
            inventory = requests.get(origin + '/v1/authorities', headers=headers, timeout=20).json()
            authority = inventory['authorities'][0]
            response = requests.get(origin + '/v1/authorities/' + quote(authority['authority_ref'], safe='') + '/publication', headers=headers, timeout=20)
            assert response.status_code == 200, (response.status_code, response.text)
            pair = response.json()
            config = {'cloud_url': 'http://127.0.0.1:18081', 'organization_id': organization,
                      'authority': authority['authority_ref'], 'publication_id': pair['publication_receipt']['publication_id'],
                      'contract_hash': pair['authority_bundle']['compiled_authority_contract']['contract_hash'], 'bindings': {}}
            enrollments = {}
            for action, role in (('create', 'repository-maintainer'), ('modify', 'security-reviewer')):
                runtime_id = 'contained57-' + action
                response = requests.post(origin + '/v1/api-keys', headers=headers, timeout=20, json={
                    'organization_id': organization, 'api_key_owner': 'runtime:' + runtime_id,
                    'scopes': ['authorities:read', 'audit:write', 'continuity:write']})
                assert response.status_code == 201, response.status_code
                credential = response.json()
                config['bindings'][action] = {'runtime_id': runtime_id, 'credential': credential['secret'],
                    'actor': {'id': 'codex57-' + action, 'type': 'agent', 'role': role}}
                enrollments[action] = credential['api_key']
            (output / 'writer-private.json').write_text(json.dumps(config))
            record = {'translation': translation, 'approval': approval, 'publication_response': publication_response,
                      'publication': pair, 'enrollments': enrollments,
                      'elapsed_seconds': time.monotonic() - started, 'browser_version': browser.version,
                      'provider': 'deterministic pinned ExampleProvider; exact fixed policy only',
                      'approval_method': 'existing Console review, individual confirmations, approval and publication',
                      'enrollment_method': 'same public /v1/api-keys contract as Console; explicit scoped create/modify bindings'}
            (output / 'fresh-publication.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
            print('Fresh Console publication:', config['authority'], config['publication_id'])
        else:
            private = json.loads((output / 'operator-private.json').read_text())
            page.goto(origin + '/console-v2/activity')
            page.locator('#auth-email').fill(private['email'])
            page.locator('#auth-password').fill(private['password'])
            page.locator('#auth-submit').click()
            page.locator('[data-execution-id]').first.wait_for()
            rows = []
            for width in (1440, 390):
                page.set_viewport_size({'width': width, 'height': 1000})
                page.goto(origin + '/console-v2/activity')
                page.locator('[data-execution-id]').first.wait_for()
                page.wait_for_load_state('networkidle')
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                page.screenshot(path=str(output / f'activity-{width}.png'), full_page=True)
                rows.append({'width': width, 'text': page.locator('#workspace').inner_text()})
                page.locator('[data-execution-id]').first.click()
                page.wait_for_load_state('networkidle')
                page.screenshot(path=str(output / f'detail-{width}.png'), full_page=True)
                rows[-1]['detail'] = page.locator('#workspace').inner_text()
                if args.client_output:
                    for phase in ('useful', 'denied-collision', 'lost'):
                        entries = [json.loads(line) for line in (args.client_output / phase / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
                        for index, entry in enumerate(entries):
                            item = entry.get('item', {})
                            if entry['type'] != 'item.completed' or item.get('tool') != 'repository_write' or not item.get('result'):
                                continue
                            result = json.loads(item['result']['content'][0]['text'])
                            if not result.get('run_id'):
                                continue
                            page.goto(origin + '/console-v2/executions/' + result['run_id'])
                            page.wait_for_load_state('networkidle')
                            page.screenshot(path=str(output / f'{phase}-{index}-detail-{width}.png'), full_page=True)
                            rows.append({'width': width, 'run_id': result['run_id'], 'phase': phase, 'detail': page.locator('#workspace').inner_text()})
            (output / 'console-activity.json').write_text(json.dumps(rows, indent=2), encoding='utf-8')
        browser.close()


if __name__ == '__main__':
    main()

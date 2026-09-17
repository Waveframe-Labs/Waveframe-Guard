"""Drive deterministic SDK faults via operator-controlled disposable Cloud wrapper."""
import argparse
import json
from pathlib import Path
import subprocess
from uuid import uuid4
from urllib.parse import quote

import requests
from console_acceptance import POLICY
from run import docker, save


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    origin = json.loads((output / 'cloud-setup.json').read_text())['url']
    auth = json.loads((output / 'operator-private.json').read_text())['auth']
    config = json.loads((output / 'writer-private.json').read_text())
    headers = {'Authorization': 'Bearer ' + auth['session_token'], 'X-Organization-ID': config['organization_id']}
    def http(path, payload):
        response = requests.post(origin + path, headers={**headers, 'Idempotency-Key': 'probe57-' + uuid4().hex}, json=payload, timeout=20)
        assert response.status_code in (200, 201), (path, response.status_code, response.text)
        return response.json()
    code = Path(__file__).with_name('sdk_fault_probe.py').read_text()
    # Python reads the fixed script from a file supplied through docker cp; stdin carries barrier acknowledgments only.
    docker('exec', '-i', args.name + '-writer', 'python', '-I', '-c',
          "import sys,pathlib; pathlib.Path('/tmp/sdk_fault_probe.py').write_bytes(sys.stdin.buffer.read())", data=code.encode())
    command = ['docker', 'exec', '-i', args.name + '-writer', 'python', '-I', '/tmp/sdk_fault_probe.py']
    results, barriers = [], []
    with (output / 'sdk-fault-stderr.txt').open('wb') as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        for line in process.stdout:
            event = json.loads(line)
            if 'result' in event:
                results.append(event['result'])
                save(output / 'sdk-fault-results.json', results)
                continue
            mode = event['barrier']
            barriers.append(mode)
            if mode == 'supersede':
                fresh = http('/v1/policy-translations', {'schema_version': 'cloud_policy_translation_create.v1',
                    'source_text': POLICY, 'policy_name': 'Superseding disposable policy', 'source_revision': 'revision-2',
                    'authority_name': 'Contained Codex 57', 'authority_version': '2.0.0'})
                prefix = '/v1/policy-translations/' + fresh['translation_id']
                for clause in fresh['review']['clauses']:
                    for control in clause['controls']:
                        reviewed = http(prefix + '/control-confirmations', {'clause_id': clause['clause_id'], 'control_id': control['control_id']})
                approved = http(prefix + '/approval', {'review_hash': reviewed['review_hash']})
                published = http(prefix + '/publication', {})
                save(output / 'superseding-publication.json', {'approved': approved, 'published': published})
            elif mode == 'revoke':
                authority = config['authority'].rsplit('@', 1)[0] + '@2.0.0'
                receipt = http('/v1/authorities/' + quote(authority, safe='') + '/revocations', {'reason': 'Disposable actual revalidation-boundary test'})
                save(output / 'revocation.json', receipt)
            elif mode != 'load-new-version':
                docker('exec', '-i', args.name + '-cloud', 'python', '-I', '-c',
                       "import pathlib,sys; pathlib.Path('/state/fault').write_text(sys.stdin.read())", data=mode.encode())
            process.stdin.write(b'{"continue":true}\n')
            process.stdin.flush()
        process.stdin.close()
        process.wait(timeout=20)
    save(output / 'sdk-fault-invocation.json', {'command': command, 'cwd': str(Path.cwd()), 'exit_code': process.returncode,
        'barriers': barriers, 'scope': 'deterministic SDK supplement inside writer; separate scratch repositories'})
    assert process.returncode == 0, (output / 'sdk-fault-stderr.txt').read_text()
    print('SDK fault cases:', len(results))


if __name__ == '__main__':
    main()

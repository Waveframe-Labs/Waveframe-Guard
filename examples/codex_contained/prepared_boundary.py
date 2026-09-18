"""Reuse existing deterministic containment checks against newly built images."""
import json
from pathlib import Path
import subprocess
import sys

import run
import run_cloud

HERE = Path(__file__).resolve().parent


def verify_boundary(name, output):
    output.mkdir()
    before = run.snapshot(name)
    for script in ('probe.py', 'transport_probe.py'):
        result = run.docker('exec', '-i', name + '-agent', 'python', '-I', '-', data=(HERE / script).read_bytes())
        value = json.loads(result.stdout)
        run.save(output / (script + '.json'), value)
        if script == 'probe.py':
            for key, item in value.items():
                if key.startswith(('write:', 'read:', 'direct-network:')) or key in ('chmod-source', 'chown-source', 'unlink-mcp'):
                    assert item['outcome'] == 'denied', (key, item)
                if key in ('child-write', 'remount', 'new-user-mount-namespace', 'native-patch'):
                    assert item['exit_code'] != 0, (key, item)
            assert value['scratch-write']['outcome'] == 'succeeded'
    subprocess.run([sys.executable, str(HERE / 'separation.py'), '--cloud', '--name', name, '--output', str(output / 'separation.json')], check=True)
    # Supply measured image IDs to the existing fault harness, never its historical defaults.
    manifest = output / 'images.json'
    run.save(manifest, {'images': {'agent': run.IMAGE, 'writer': run_cloud.WRITER_IMAGE, 'cloud': run_cloud.CLOUD_IMAGE}})
    subprocess.run([sys.executable, str(HERE / 'raw_transport.py'), '--cloud', '--prepared', str(manifest),
        '--name', name, '--output', str(output / 'raw-transport.json')], check=True)
    after = run.snapshot(name)
    assert before == after
    run.save(output / 'result.json', {'passed': True, 'source_unchanged': True, 'images': json.loads(manifest.read_text())['images'],
        'checks': ['OS writes/permissions/native patch/child/remount/namespaces', 'private PID/memory/env/credentials',
                   'no direct network or Cloud transport; proxy allowlist', 'malformed MCP and timeout with zero source writes'],
        'reuse': 'Existing probe.py, transport_probe.py, separation.py and raw_transport.py; new images measured here. Prior lifecycle/lost-response evidence remains historical, not rerun.'})

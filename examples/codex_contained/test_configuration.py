"""Guard-owned launch-contract checks; real Linux proof is archived separately."""
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('contained_operator', Path(__file__).with_name('run.py'))
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)


def test_agent_and_writer_have_no_network_and_no_capabilities():
    command = operator.security()
    assert command[command.index('--network') + 1] == 'none'
    assert command[command.index('--cap-drop') + 1] == 'ALL'
    assert command[command.index('--user') + 1] == '10001:10001'
    assert '--read-only' in command and 'no-new-privileges' in command
    assert not any(word in command for word in ('--privileged', '--pid', '--device', '--cap-add'))


@pytest.mark.parametrize('volume,target', [('source', '/source'), ('ipc', '/ipc'), ('egress', '/egress')])
def test_agent_readonly_mount_is_explicit(volume, target):
    assert operator.mount('wf54-test', volume, target, True) == [
        '--mount', f'type=volume,source=wf54-test-{volume},target={target},readonly']


def test_no_connector_or_hook_required_for_container_security():
    options = operator.config(False)
    assert not any(key.startswith('mcp_servers') for key in options)
    assert options['features.hooks'] is False
    assert options['features.multi_agent'] is options['features.multi_agent_v2'] is False
    assert 'none' in operator.security()


def test_mcp_only_relays_stdio_to_fixed_private_socket():
    server = operator.config()['mcp_servers.waveframe']
    assert server['command'] == 'socat'
    assert server['args'] == ['STDIO', 'UNIX-CONNECT:/ipc/mcp.sock']
    assert server['enabled_tools'] == ['connection_status', 'repository_write']
    assert not any(key in server for key in ('env', 'env_vars', 'url', 'http_headers'))
    assert operator.config(missing=True)['mcp_servers.waveframe']['args'][-1].endswith('/missing.sock')


def test_client_policy_does_not_mask_the_os_write_probe():
    command = operator.cli()
    assert '--dangerously-bypass-approvals-and-sandbox' in command
    assert '--ignore-user-config' in command and '--ignore-rules' in command
    assert command[command.index('-C') + 1] == '/source'

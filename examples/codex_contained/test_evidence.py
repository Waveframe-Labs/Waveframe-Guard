"""Reject inconsistent observations and broadened controls in the real capture."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

SPEC=importlib.util.spec_from_file_location('contained_verifier',Path(__file__).with_name('verify.py'))
verifier=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(verifier)
ROOT=Path(__file__).resolve().parents[2]/'docs/acceptance/codex-contained-54/evidence/final'


def test_real_captured_transport_and_filesystem_boundary():
    assert (ROOT.parent/'SHA256SUMS.json').is_file()
    result=verifier.verify(ROOT,replay=False)
    assert result['lost_reconciliation']['actual']['mutation_status']=='executed'


@pytest.mark.parametrize('attack',['writable_source','host_network','capability','host_pid','docker_socket','writer_secret'])
def test_broadened_agent_controls_are_rejected(attack):
    captured=deepcopy(verifier.read(ROOT/'setup.json')['containers'])
    agent=next(c for c in captured if c['Name'].endswith('-agent'))
    if attack=='writable_source':
        next(m for m in agent['Mounts'] if m['Destination']=='/source')['RW']=True
    elif attack=='host_network': agent['HostConfig']['NetworkMode']='host'
    elif attack=='capability': agent['HostConfig']['CapAdd']=['SYS_ADMIN']
    elif attack=='host_pid': agent['HostConfig']['PidMode']='host'
    else:
        agent['Mounts'].append({'Type':'volume','Destination':'/var/run/docker.sock' if attack=='docker_socket' else '/secrets','RW':False})
    with pytest.raises(AssertionError): verifier.controls(captured)


def test_wrong_captured_byte_hash_is_rejected():
    inspection=deepcopy(verifier.read(ROOT/'bypass/inspection.json'))
    inspection['after']['README.md']['sha256']='0'*64
    with pytest.raises(AssertionError): verifier.observations(inspection,[])


def test_hidden_actual_write_is_rejected_even_with_consistent_hash():
    inspection=deepcopy(verifier.read(ROOT/'bypass/inspection.json'))
    inspection['after']['README.md']={'bytes':'','sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
    with pytest.raises(AssertionError): verifier.observations(inspection,[])

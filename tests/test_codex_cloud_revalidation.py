"""Offline #59 captured-evidence checks. No model, Cloud, network or mutation replay."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('revalidation_proof', ROOT / 'examples/codex_contained/verify_revalidation.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)
EVIDENCE = ROOT / 'docs/acceptance/codex-cloud-59/evidence'


def test_actual_contained_history_and_enrollment_evidence():
    result = proof.verify(EVIDENCE, check_boundary=False)
    assert result['saved_runs'] == 7
    assert result['callback_invocations'] == result['actual_mutations'] == 5


@pytest.mark.parametrize('failure', ['lost-replay', 'startup-write', 'changed-history', 'failed-upload', 'missing-journal'])
def test_evidence_verifier_rejects_contradictory_claims(monkeypatch, failure):
    original_read, original_lines = proof.read, proof.lines
    def read(path):
        value = original_read(path)
        if failure == 'lost-replay' and path.name == 'lost-reconciliation.json':
            value['received_requests'] = 2
        if failure == 'startup-write' and path.name == 'refusal.json':
            value['protected_writes'] = 1
        if failure == 'changed-history' and path.parent.name == 'after-revocation' and path.name.startswith('guard_run_'):
            value['report']['runtime_id'] = 'different-runtime'
        return value
    def lines(path):
        value = original_lines(path)
        if failure == 'failed-upload' and path.name == 'requests.jsonl':
            next(e['result'] for e in value if e['stage'] == 'completed')['decision_preservation']['ok'] = False
        if failure == 'missing-journal' and path.name == 'requests.jsonl':
            value = value[:-1]
        return value
    monkeypatch.setattr(proof, 'read', read)
    monkeypatch.setattr(proof, 'lines', lines)
    with pytest.raises(AssertionError):
        proof.verify(EVIDENCE, check_boundary=False)

from waveframe_guard import evaluate_admissibility
from waveframe_guard.runtime import evaluate_admissibility as runtime_evaluate_admissibility


def test_evaluate_admissibility_is_public_export():
    assert evaluate_admissibility is runtime_evaluate_admissibility
    assert evaluate_admissibility({}, {"approvals": []})["allowed"] is True

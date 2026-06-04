from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui"


def test_guard_ui_layout_contains_required_runtime_surfaces():
    html = (UI_ROOT / "index.html").read_text(encoding="utf-8")
    script = (UI_ROOT / "app.js").read_text(encoding="utf-8")

    for expected in [
        "Runtime Evaluation",
        "Runtime Posture",
        "Enforcement Chronology",
        "Evaluation Trace",
        "Telemetry Stream",
        "compiled_authority_contract.v1",
        "normalized_execution_request.v1",
        "guard_runtime_evidence_model.v1",
        "guard_enforcement_outcome.v1",
    ]:
        assert expected in html or expected in script


def test_guard_ui_uses_canonical_branding_assets():
    html = (UI_ROOT / "index.html").read_text(encoding="utf-8")

    assert "./branding/assets/canon_wf_logo_extended.png" in html
    assert "./branding/assets/canon_wf_logo_mark_transparent.png" in html
    assert "./branding/assets/favicon.ico" in html

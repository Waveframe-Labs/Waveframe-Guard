from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_ROOT = REPO_ROOT / "ui"


def test_guard_ui_layout_contains_required_runtime_surfaces():
    html = (UI_ROOT / "index.html").read_text(encoding="utf-8")
    script = (UI_ROOT / "app.js").read_text(encoding="utf-8")
    server_inputs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (REPO_ROOT / "server" / "runtime_inputs").glob("*.json")
    )

    for expected in [
        "Workspace",
        "Explainability",
        "Developer Mode",
        "Execution Workspace",
        "Current Execution",
        "Execution intake",
        "Recent Evaluations",
        "Receipt browser",
        "No receipt selected",
        "Execution Intake",
        "Sample input set",
        "Blocked transfer example",
        "Allowed transfer example",
        "Escalated queued job example",
        "Empty input set",
        "Paste Execution Request",
        "Paste normalized_execution_request.v1 JSON here",
        "Compiled authority loaded",
        "Execution request loaded",
        "Runtime evidence loaded",
        "Continuity posture optional",
        "Upload Evaluation Artifact",
        "Load Sample Inputs",
        "Clear Inputs",
        "Evaluate Execution",
        "Export Receipt",
        "Save Run",
        "Replay Saved Evaluation",
        "Runtime execution boundary",
        "Operational explainability",
        "Generated execution chronology",
        "Generated Evaluation Events",
        "View compiled authority",
        "View normalized request",
        "View runtime evidence",
        "View continuity posture",
        "Technical detail",
        "compiled_authority_contract.v1",
        "normalized_execution_request.v1",
        "guard_runtime_evidence_model.v1",
        "guard_enforcement_outcome.v1",
    ]:
        assert expected in html or expected in script or expected in server_inputs

    for retired in [
        "Live boundary feed",
        "LIVE BOUNDARY FEED",
        "Append-only runtime events",
        "Telemetry Stream",
        "/api/runtime/telemetry",
        "/api/runtime/chronology",
        "setInterval",
        "Can execution proceed?",
        "Step 1",
        "Step 2",
        "Step 3",
        "Example Evaluation: finance-policy@1.0.0",
        "Connect Runtime",
        "Example evaluation selector",
    ]:
        assert retired not in html
        assert retired not in script

    assert "renderEmptyWorkspace();" in script
    assert "await loadSampleInputs();\n    await evaluateCurrentInputs();" not in script
    assert "requiredInputsPresent()" in script
    assert "evaluateButton\" type=\"button\" disabled" in html


def test_guard_ui_uses_canonical_branding_assets():
    html = (UI_ROOT / "index.html").read_text(encoding="utf-8")

    assert "./branding/assets/canon_wf_logo.png" in html
    assert "./branding/assets/favicon.ico" in html

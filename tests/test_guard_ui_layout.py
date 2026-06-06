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
        "Inspector",
        "Explainability",
        "Inputs",
        "Guard Evaluation Inspector",
        "Evaluation inspector",
        "Recent Evaluations",
        "SDK run history",
        "Search request, target, authority",
        "Evaluation status filter",
        "Receipt browser",
        "No receipt selected",
        "Artifact Intake",
        "Open an SDK evaluation artifact",
        "Guard SDK primary path",
        "How this is produced in code",
        "Guard.local",
        ".guard-local/",
        "CRI-CORE",
        "Evaluation kernel",
        "Load artifact",
        "Load saved run",
        "Connect SDK workspace",
        "Replay evaluation",
        "Advanced JSON inputs",
        "Schemas are preserved for debugging",
        "Example input set",
        "Blocked transfer example",
        "Allowed transfer example",
        "Escalated queued job example",
        "Empty input set",
        "Advanced: Edit JSON",
        "secondary-action",
        "Paste normalized_execution_request.v1 JSON here",
        "Compiled authority loaded",
        "Execution request loaded",
        "Runtime evidence loaded",
        "Continuity posture optional",
        "Load Example Inputs",
        "Clear Inputs",
        "Evaluate Execution",
        "Export Receipt",
        "Save Run",
        "Evaluation Inspector",
        "Operational explainability",
        "Generated execution chronology",
        "Generated Evaluation Events",
        "Compiled authority",
        "Execution request",
        "Runtime evidence",
        "Continuity posture",
        "Evaluation lineage",
        "Contract hash",
        "Mutation domain",
        "Receipt hash",
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
        "Paste Execution Request",
        "Sample input set",
        "Load Sample Inputs",
        "Execution Workspace",
        "Current Execution",
        "Developer Mode",
        "Runtime execution boundary",
        "connect or paste execution inputs",
        "Evaluation artifact inputs",
        "Inspect or replay an evaluation artifact",
        "View normalized request",
        "Upload Evaluation Artifact",
        "Replay Saved Evaluation",
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

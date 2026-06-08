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
        "Execution",
        "Evaluation",
        "Replay / Artifacts",
        "Guard Inspector",
        "powered by CRI-CORE",
        "Current execution",
        "Target mutation",
        "Execution Intake",
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
        "Open an SDK evaluation artifact",
        "Guard SDK interception path",
        "Guard.local",
        ".guard-local/",
        "Guard SDK",
        "Guard Receipt",
        "CRI-CORE evaluation",
        "evaluation artifact",
        "artifact manifest",
        "replay basis",
        "lineage continuity",
        "CRI-CORE",
        "Evaluation kernel",
        "Multi-run comparison",
        "Compare evaluation outcomes",
        "Run A",
        "Run B",
        "authority, evidence, continuity, replay, and actor changes",
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
        "Continuation",
        "Revalidation Required",
        "runtime_dependency_expired",
        "runtime_dependency_linked",
        "continuation_evaluated",
        "continuation_invalidated",
        "Runtime dependency linked",
        "Continuation invalidated",
        "evaluation_admissible",
        "continuation_lease_issued",
        "release_allowed",
        "release_blocked",
        "release_revalidation_required",
        "Continuation lease issued",
        "Release blocked",
        "Load Example Inputs",
        "Clear Inputs",
        "Evaluate Execution",
        "Export Receipt",
        "Save Run",
        "Evaluation Inspector",
        "Operational explainability",
        "Generated execution chronology",
        "Generated Evaluation Events",
        "Audit time",
        "relativeDeltaMs",
        "audit-time",
        "stage-in",
        "Compiled authority",
        "Execution request",
        "Runtime evidence",
        "Continuity posture",
        "Evaluation lineage",
        "data-receipt-panel",
        "[\"sdk\", \"Guard SDK\"]",
        "[\"evaluation\", \"CRI-CORE evaluation\"]",
        "[\"receipt\", \"Guard Receipt\"]",
        "receiptPanel: \"receipt\"",
        "Guard SDK interception detail",
        "CRI-CORE evaluation detail",
        "Guard Receipt detail",
        "runtimeConditionSummary",
        "Contract hash",
        "Mutation domain",
        "Receipt hash",
        "Copy",
        "copy-hash",
        "hash-value",
        "Technical detail",
        "compiled_authority_contract.v1",
        "normalized_execution_request.v1",
        "guard_runtime_evidence_model.v1",
        "guard_enforcement_outcome.v1",
        "contract_drift",
        "evidence_mutation",
        "chronology_mutation",
        "continuity_mismatch",
        "request_mismatch",
        "manifest_integrity_failure",
        "Deterministic trust failed",
        "This execution can no longer be trusted because the replay basis diverged from the original deterministic identity.",
        "Replay verified",
        "Local workspace artifact error",
        "unsupported_schema_version",
        "unreadable_receipt",
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
    assert "max-width: 1400px" in (UI_ROOT / "styles.css").read_text(encoding="utf-8")
    assert "text-overflow: ellipsis" in (UI_ROOT / "styles.css").read_text(encoding="utf-8")


def test_guard_ui_uses_canonical_branding_assets():
    html = (UI_ROOT / "index.html").read_text(encoding="utf-8")

    assert "./branding/assets/canon_wf_logo.png" in html
    assert "./branding/assets/favicon.ico" in html

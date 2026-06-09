from __future__ import annotations

import sqlite3

from guard.runtime.organization import PersistentOrganizationalRuntime, default_organization_context
from server import local_api


def test_persistent_organizational_runtime_survives_restart(tmp_path):
    runtime = PersistentOrganizationalRuntime(tmp_path)
    context = default_organization_context()
    response = local_api.evaluate_runtime_request(local_api.load_runtime_inputs("allowed-transfer"))
    saved = local_api.save_runtime_evaluation(response, store_root=tmp_path)

    runtime.record_evaluation(
        response,
        receipt=saved["saved_run"]["receipt"],
        context=context,
    )

    restarted = PersistentOrganizationalRuntime(tmp_path)
    dashboard = restarted.dashboard(context)

    assert (tmp_path / "guard-runtime.sqlite3").exists()
    assert dashboard["schema_version"] == "guard_persistent_runtime_dashboard.v1"
    assert dashboard["organization_context"]["organization_id"] == "org-finance"
    assert dashboard["summary"]["organizations"] == 1
    assert dashboard["summary"]["workspaces"] == 1
    assert dashboard["summary"]["runs"] == 1
    assert dashboard["recent_runs"][0]["request_id"] == "exec-allowed-transfer"


def test_persistent_runtime_records_identities_authorities_and_release_queue(tmp_path):
    demo = local_api.run_deferred_release_demo(
        local_api.load_runtime_inputs("deferred-release-expired-approval"),
        store_root=tmp_path,
    )
    dashboard = local_api.persistent_runtime_dashboard(store_root=tmp_path)

    assert dashboard["summary"]["runs"] == 1
    assert dashboard["summary"]["active_continuation_leases"] == 1
    assert dashboard["summary"]["expiring_dependencies"] >= 1
    assert dashboard["summary"]["blocked_releases"] == 1
    assert dashboard["summary"]["escalation_queue"] == 1
    assert dashboard["summary"]["invalidated_continuations"] == 1
    assert dashboard["release_queue"][0]["state"] == "release_blocked"

    with sqlite3.connect(tmp_path / "guard-runtime.sqlite3") as conn:
        actor = conn.execute("select actor_id, role, status from actors").fetchone()
        authority = conn.execute("select authority_ref, authority_namespace from compiled_authorities").fetchone()
        lease = conn.execute("select continuation_id, runtime_lifecycle_state from continuation_leases").fetchone()
        validation = conn.execute("select outcome, release_blocked from release_validations").fetchone()

    assert actor == ("manager-2", "manager", "active")
    assert authority == ("finance-policy@1.0.0", "finance")
    assert lease[0] == demo["deferred_release"]["continuation_lease"]["continuation_id"]
    assert lease[1] == "admissible"
    assert validation == ("dependency_expired", 1)

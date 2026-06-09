from __future__ import annotations

import sqlite3

from guard.runtime.organization import (
    PERSISTENT_RUNTIME_EXPORT_V1,
    PersistentOrganizationalRuntime,
    default_organization_context,
)
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


def test_persistent_runtime_rows_carry_schema_versions(tmp_path):
    local_api.run_deferred_release_demo(
        local_api.load_runtime_inputs("deferred-release-expired-approval"),
        store_root=tmp_path,
    )

    with sqlite3.connect(tmp_path / "guard-runtime.sqlite3") as conn:
        tables = [
            "organizations",
            "workspaces",
            "actors",
            "compiled_authorities",
            "runs",
            "continuation_leases",
            "release_validations",
            "runtime_dependencies",
            "release_queue",
        ]
        for table in tables:
            columns = {row[1] for row in conn.execute(f"pragma table_info({table})")}
            schema_versions = {row[0] for row in conn.execute(f"select distinct schema_version from {table}")}
            assert "schema_version" in columns
            assert all(version.startswith("guard_persistent_") for version in schema_versions)


def test_persistent_runtime_export_import_round_trip(tmp_path):
    local_api.run_deferred_release_demo(
        local_api.load_runtime_inputs("deferred-release-expired-approval"),
        store_root=tmp_path,
    )
    exported = local_api.export_persistent_runtime_state(store_root=tmp_path)

    imported_root = tmp_path / "imported"
    result = local_api.import_persistent_runtime_state(exported, store_root=imported_root)
    dashboard = local_api.persistent_runtime_dashboard(store_root=imported_root)

    assert exported["schema_version"] == PERSISTENT_RUNTIME_EXPORT_V1
    assert result["schema_version"] == "guard_persistent_runtime_recovery.v1"
    assert result["tables"]["runs"] == 1
    assert dashboard["summary"]["runs"] == 1
    assert dashboard["summary"]["blocked_releases"] == 1
    assert dashboard["release_queue"][0]["state"] == "release_blocked"


def test_persistent_runtime_recovers_from_corrupt_sqlite(tmp_path):
    runtime = PersistentOrganizationalRuntime(tmp_path)
    runtime.path.write_bytes(b"not a sqlite database")

    recovery = runtime.recover_if_corrupt()

    assert recovery["schema_version"] == "guard_persistent_runtime_recovery.v1"
    assert recovery["status"] == "recovered"
    assert "quarantined_path" in recovery
    assert (tmp_path / "guard-runtime.sqlite3").exists()
    assert list(tmp_path.glob("guard-runtime.corrupt.*.sqlite3"))
    assert PersistentOrganizationalRuntime(tmp_path).dashboard()["summary"]["runs"] == 0


def test_cleanup_local_runtime_state_reinitializes_empty_store(tmp_path):
    local_api.run_deferred_release_demo(
        local_api.load_runtime_inputs("deferred-release-expired-approval"),
        store_root=tmp_path,
    )

    cleanup = local_api.cleanup_local_runtime_state(store_root=tmp_path)
    dashboard = local_api.persistent_runtime_dashboard(store_root=tmp_path)

    assert cleanup["operation"] == "cleanup_dev_state"
    assert (tmp_path / "guard-runtime.sqlite3").exists()
    assert dashboard["summary"]["runs"] == 0
    assert dashboard["summary"]["blocked_releases"] == 0

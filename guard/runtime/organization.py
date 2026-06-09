from __future__ import annotations

import json
import gc
import sqlite3
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .identity import stable_id


PERSISTENT_RUNTIME_SCHEMA_V1 = "guard_persistent_runtime_store.v1"
PERSISTENT_RUNTIME_EXPORT_V1 = "guard_persistent_runtime_export.v1"
PERSISTENT_RUNTIME_DASHBOARD_V1 = "guard_persistent_runtime_dashboard.v1"
PERSISTENT_RUNTIME_RECOVERY_V1 = "guard_persistent_runtime_recovery.v1"
TABLE_SCHEMAS = {
    "organizations": "guard_persistent_organization.v1",
    "workspaces": "guard_persistent_workspace.v1",
    "actors": "guard_persistent_actor.v1",
    "compiled_authorities": "guard_persistent_compiled_authority.v1",
    "runs": "guard_persistent_run.v1",
    "continuation_leases": "guard_persistent_continuation_lease.v1",
    "release_validations": "guard_persistent_release_validation.v1",
    "runtime_dependencies": "guard_persistent_runtime_dependency.v1",
    "release_queue": "guard_persistent_release_queue.v1",
}
DEFAULT_ORGANIZATION_ID = "org-finance"
DEFAULT_WORKSPACE_ID = "workspace-local"
DEFAULT_ENVIRONMENT = "local"
DEFAULT_AUTHORITY_NAMESPACE = "finance"


def default_organization_context() -> dict[str, str]:
    return {
        "organization_id": DEFAULT_ORGANIZATION_ID,
        "workspace_id": DEFAULT_WORKSPACE_ID,
        "environment": DEFAULT_ENVIRONMENT,
        "authority_namespace": DEFAULT_AUTHORITY_NAMESPACE,
    }


class PersistentOrganizationalRuntime:
    def __init__(self, root: str | Path, *, initialize: bool = True):
        self.root = Path(root)
        self.path = self.root / "guard-runtime.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
        if initialize:
            self._initialize()

    def record_evaluation(
        self,
        evaluated: dict[str, Any],
        *,
        receipt: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        context = _context(context)
        inputs = evaluated["inputs"]
        evaluation = evaluated["evaluation"]
        outcome = evaluated["guard_enforcement_outcome"]
        evidence = inputs["runtime_evidence"]
        receipt = receipt or evaluated.get("receipt") or {}
        self.ensure_context(context)
        self.upsert_actor(context, evidence.get("actor_identity", {}))
        self.upsert_authority(context, inputs.get("compiled_authority", {}), outcome.get("authority_ref"))
        run_id = receipt.get("run_id") or stable_id(
            "guard_run",
            {
                "organization_id": context["organization_id"],
                "workspace_id": context["workspace_id"],
                "request_id": inputs["execution_request"].get("request_id"),
                "outcome_hash": outcome.get("outcome_hash"),
            },
        )
        with self._connect() as conn:
            conn.execute(
                """
                insert or replace into runs (
                    schema_version, run_id, organization_id, workspace_id, environment, authority_ref,
                    request_id, actor_id, status, runtime_lifecycle_state, receipt_hash,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["runs"],
                    run_id,
                    context["organization_id"],
                    context["workspace_id"],
                    context["environment"],
                    outcome.get("authority_ref"),
                    inputs["execution_request"].get("request_id"),
                    evidence.get("actor_identity", {}).get("id"),
                    outcome.get("status"),
                    outcome.get("runtime_lifecycle_state") or evaluation.get("runtime_lifecycle_state"),
                    receipt.get("receipt_hash"),
                    _json(evaluated),
                    _now(),
                ),
            )
            self._insert_dependencies(
                conn,
                context=context,
                owner_type="run",
                owner_id=run_id,
                dependencies=evaluation.get("runtime_dependency_posture", {}).get("dependencies", []),
            )

    def record_deferred_release(
        self,
        deferred_release: dict[str, Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        context = _context(context)
        lease = deferred_release["continuation_lease"]
        validation = deferred_release["release_validation"]
        saved_run = deferred_release.get("saved_run", {})
        self.ensure_context(context)
        with self._connect() as conn:
            conn.execute(
                """
                insert or replace into continuation_leases (
                    schema_version, continuation_id, organization_id, workspace_id, run_id, execution_id,
                    status, runtime_lifecycle_state, admissible_until, lease_hash,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["continuation_leases"],
                    lease["continuation_id"],
                    context["organization_id"],
                    context["workspace_id"],
                    saved_run.get("run_id"),
                    lease["execution_id"],
                    lease.get("continuation_status", {}).get("status"),
                    lease.get("runtime_lifecycle_state"),
                    lease.get("admissible_until"),
                    lease.get("lease_hash"),
                    _json(lease),
                    lease.get("issued_at") or _now(),
                ),
            )
            self._insert_dependencies(
                conn,
                context=context,
                owner_type="lease",
                owner_id=lease["continuation_id"],
                dependencies=lease.get("runtime_dependencies", []),
            )
            conn.execute(
                """
                insert or replace into release_validations (
                    schema_version, release_validation_id, organization_id, workspace_id, continuation_id,
                    outcome, release_allowed, release_blocked, runtime_lifecycle_state,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["release_validations"],
                    validation["release_validation_id"],
                    context["organization_id"],
                    context["workspace_id"],
                    lease["continuation_id"],
                    validation.get("outcome"),
                    int(bool(validation.get("release_allowed"))),
                    int(bool(validation.get("release_blocked"))),
                    validation.get("runtime_lifecycle_state"),
                    _json(validation),
                    validation.get("release_time") or _now(),
                ),
            )
            self._insert_dependencies(
                conn,
                context=context,
                owner_type="release_validation",
                owner_id=validation["release_validation_id"],
                dependencies=validation.get("runtime_dependency_posture", {}).get("dependencies", []),
            )
            queue_state = "released" if validation.get("release_allowed") else "release_blocked"
            conn.execute(
                """
                insert or replace into release_queue (
                    schema_version, queue_id, organization_id, workspace_id, continuation_id, execution_id,
                    state, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["release_queue"],
                    stable_id("release_queue", {"continuation_id": lease["continuation_id"]}),
                    context["organization_id"],
                    context["workspace_id"],
                    lease["continuation_id"],
                    lease["execution_id"],
                    queue_state,
                    _json({"lease": lease, "release_validation": validation}),
                    validation.get("release_time") or _now(),
                ),
            )

    def dashboard(self, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = _context(context)
        self.ensure_context(context)
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            scoped = (context["organization_id"], context["workspace_id"])
            summary = {
                "organizations": _count(conn, "organizations", "organization_id = ?", (context["organization_id"],)),
                "workspaces": _count(conn, "workspaces", "organization_id = ?", (context["organization_id"],)),
                "runs": _count(conn, "runs", "organization_id = ? and workspace_id = ?", scoped),
                "active_continuation_leases": _count(
                    conn,
                    "continuation_leases",
                    "organization_id = ? and workspace_id = ? and runtime_lifecycle_state in ('admissible','continuation_required','revalidation_required')",
                    scoped,
                ),
                "expiring_dependencies": _count(
                    conn,
                    "runtime_dependencies",
                    "organization_id = ? and workspace_id = ? and valid_until is not null and status = 'valid'",
                    scoped,
                ),
                "blocked_releases": _count(
                    conn,
                    "release_validations",
                    "organization_id = ? and workspace_id = ? and release_blocked = 1",
                    scoped,
                ),
                "escalation_queue": _count(
                    conn,
                    "release_queue",
                    "organization_id = ? and workspace_id = ? and state in ('revalidation_required','release_blocked')",
                    scoped,
                ),
                "replay_failures": 0,
                "invalidated_continuations": _count(
                    conn,
                    "release_validations",
                    "organization_id = ? and workspace_id = ? and outcome in ('continuation_invalidated','dependency_expired')",
                    scoped,
                ),
                "runtime_drift_alerts": _count(
                    conn,
                    "runtime_dependencies",
                    "organization_id = ? and workspace_id = ? and (status != 'valid' or dependency_hash != current_hash)",
                    scoped,
                ),
            }
            recent_runs = [
                dict(row)
                for row in conn.execute(
                    """
                    select run_id, request_id, authority_ref, actor_id, status,
                           runtime_lifecycle_state, created_at
                    from runs
                    where organization_id = ? and workspace_id = ?
                    order by created_at desc
                    limit 10
                    """,
                    scoped,
                )
            ]
            release_queue = [
                dict(row)
                for row in conn.execute(
                    """
                    select queue_id, continuation_id, execution_id, state, updated_at
                    from release_queue
                    where organization_id = ? and workspace_id = ?
                    order by updated_at desc
                    limit 10
                    """,
                    scoped,
                )
            ]
        return {
            "schema_version": PERSISTENT_RUNTIME_DASHBOARD_V1,
            "organization_context": context,
            "summary": summary,
            "recent_runs": recent_runs,
            "release_queue": release_queue,
        }

    def export_state(self, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = _context(context)
        self.ensure_context(context)
        tables = {}
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            for table in TABLE_SCHEMAS:
                rows = [
                    dict(row)
                    for row in conn.execute(
                        f"select * from {table} where {_scope_where(table)}",
                        _scope_args(table, context),
                    )
                ]
                tables[table] = rows
        return {
            "schema_version": PERSISTENT_RUNTIME_EXPORT_V1,
            "store_schema_version": PERSISTENT_RUNTIME_SCHEMA_V1,
            "organization_context": context,
            "exported_at": _now(),
            "tables": tables,
        }

    def import_state(self, artifact: dict[str, Any]) -> dict[str, Any]:
        if artifact.get("schema_version") != PERSISTENT_RUNTIME_EXPORT_V1:
            raise ValueError("unsupported persistent runtime export schema")
        tables = artifact.get("tables") or {}
        imported = {}
        with self._connect() as conn:
            for table, rows in tables.items():
                if table not in TABLE_SCHEMAS:
                    continue
                for row in rows:
                    _insert_row(conn, table, row)
                imported[table] = len(rows)
        return {
            "schema_version": PERSISTENT_RUNTIME_RECOVERY_V1,
            "operation": "import",
            "imported_at": _now(),
            "tables": imported,
        }

    def recover_if_corrupt(self) -> dict[str, Any]:
        if not self.path.exists():
            self._initialize()
            return {
                "schema_version": PERSISTENT_RUNTIME_RECOVERY_V1,
                "status": "initialized",
                "database_path": str(self.path),
            }
        conn = None
        try:
            conn = self._connect()
            row = conn.execute("pragma integrity_check").fetchone()
            if row and row[0] == "ok":
                return {
                    "schema_version": PERSISTENT_RUNTIME_RECOVERY_V1,
                    "status": "ok",
                    "database_path": str(self.path),
                }
        except sqlite3.DatabaseError as error:
            reason = str(error)
        else:
            reason = str(row[0] if row else "unknown integrity check failure")
        finally:
            if conn is not None:
                conn.close()
            gc.collect()
        recovered_at = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        quarantine_path = self.root / f"guard-runtime.corrupt.{recovered_at}.sqlite3"
        shutil.move(str(self.path), str(quarantine_path))
        self._initialize()
        return {
            "schema_version": PERSISTENT_RUNTIME_RECOVERY_V1,
            "status": "recovered",
            "reason": reason,
            "database_path": str(self.path),
            "quarantined_path": str(quarantine_path),
        }

    def cleanup_dev_state(self) -> dict[str, Any]:
        gc.collect()
        removed = []
        for name in ["runs", "receipts", "manifests", "replay-records", "continuation-leases", "release-validations"]:
            target = self.root / name
            if target.exists():
                shutil.rmtree(target)
                removed.append(str(target))
        if self.path.exists():
            self.path.unlink()
            removed.append(str(self.path))
        self._initialize()
        return {
            "schema_version": PERSISTENT_RUNTIME_RECOVERY_V1,
            "operation": "cleanup_dev_state",
            "removed": removed,
            "database_path": str(self.path),
        }

    def ensure_context(self, context: dict[str, Any] | None = None) -> dict[str, str]:
        context = _context(context)
        with self._connect() as conn:
            conn.execute(
                """
                insert or ignore into organizations (
                    schema_version, organization_id, name, authority_namespace, status, created_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["organizations"],
                    context["organization_id"],
                    context["organization_id"],
                    context["authority_namespace"],
                    "active",
                    _now(),
                ),
            )
            conn.execute(
                """
                insert or ignore into workspaces (
                    schema_version, workspace_id, organization_id, environment, name, created_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["workspaces"],
                    context["workspace_id"],
                    context["organization_id"],
                    context["environment"],
                    context["workspace_id"],
                    _now(),
                ),
            )
        return context

    def upsert_actor(self, context: dict[str, Any], actor: dict[str, Any]) -> None:
        if not actor.get("id"):
            return
        with self._connect() as conn:
            conn.execute(
                """
                insert or replace into actors (
                    schema_version, actor_id, organization_id, role, team, clearance, delegation,
                    revocation, status, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["actors"],
                    actor.get("id"),
                    context["organization_id"],
                    actor.get("role"),
                    actor.get("team"),
                    actor.get("clearance"),
                    actor.get("delegation"),
                    actor.get("revocation"),
                    actor.get("status", "active"),
                    _json(actor),
                    _now(),
                ),
            )

    def upsert_authority(
        self,
        context: dict[str, Any],
        authority: dict[str, Any],
        authority_ref: str | None,
    ) -> None:
        authority_ref = authority_ref or _authority_ref(authority)
        if not authority_ref:
            return
        with self._connect() as conn:
            conn.execute(
                """
                insert or replace into compiled_authorities (
                    schema_version, authority_ref, organization_id, workspace_id, contract_hash,
                    authority_namespace, status, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["compiled_authorities"],
                    authority_ref,
                    context["organization_id"],
                    context["workspace_id"],
                    authority.get("contract_hash"),
                    context["authority_namespace"],
                    authority.get("status", "active"),
                    _json(authority),
                    _now(),
                ),
            )

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                create table if not exists organizations (
                    schema_version text not null default 'guard_persistent_organization.v1',
                    organization_id text primary key,
                    name text not null,
                    authority_namespace text not null,
                    status text not null,
                    created_at text not null
                );
                create table if not exists workspaces (
                    schema_version text not null default 'guard_persistent_workspace.v1',
                    workspace_id text primary key,
                    organization_id text not null,
                    environment text not null,
                    name text not null,
                    created_at text not null
                );
                create table if not exists actors (
                    schema_version text not null default 'guard_persistent_actor.v1',
                    actor_id text primary key,
                    organization_id text not null,
                    role text,
                    team text,
                    clearance text,
                    delegation text,
                    revocation text,
                    status text not null,
                    payload_json text not null,
                    updated_at text not null
                );
                create table if not exists compiled_authorities (
                    schema_version text not null default 'guard_persistent_compiled_authority.v1',
                    authority_ref text primary key,
                    organization_id text not null,
                    workspace_id text not null,
                    contract_hash text,
                    authority_namespace text not null,
                    status text not null,
                    payload_json text not null,
                    updated_at text not null
                );
                create table if not exists runs (
                    schema_version text not null default 'guard_persistent_run.v1',
                    run_id text primary key,
                    organization_id text not null,
                    workspace_id text not null,
                    environment text not null,
                    authority_ref text,
                    request_id text,
                    actor_id text,
                    status text,
                    runtime_lifecycle_state text,
                    receipt_hash text,
                    payload_json text not null,
                    created_at text not null
                );
                create table if not exists continuation_leases (
                    schema_version text not null default 'guard_persistent_continuation_lease.v1',
                    continuation_id text primary key,
                    organization_id text not null,
                    workspace_id text not null,
                    run_id text,
                    execution_id text,
                    status text,
                    runtime_lifecycle_state text,
                    admissible_until text,
                    lease_hash text,
                    payload_json text not null,
                    created_at text not null
                );
                create table if not exists release_validations (
                    schema_version text not null default 'guard_persistent_release_validation.v1',
                    release_validation_id text primary key,
                    organization_id text not null,
                    workspace_id text not null,
                    continuation_id text not null,
                    outcome text,
                    release_allowed integer not null,
                    release_blocked integer not null,
                    runtime_lifecycle_state text,
                    payload_json text not null,
                    created_at text not null
                );
                create table if not exists runtime_dependencies (
                    schema_version text not null default 'guard_persistent_runtime_dependency.v1',
                    organization_id text not null,
                    workspace_id text not null,
                    owner_type text not null,
                    owner_id text not null,
                    dependency_id text not null,
                    dependency_type text,
                    dependency_hash text,
                    current_hash text,
                    valid_until text,
                    status text,
                    payload_json text not null,
                    primary key (organization_id, workspace_id, owner_type, owner_id, dependency_id)
                );
                create table if not exists release_queue (
                    schema_version text not null default 'guard_persistent_release_queue.v1',
                    queue_id text primary key,
                    organization_id text not null,
                    workspace_id text not null,
                    continuation_id text not null,
                    execution_id text,
                    state text not null,
                    payload_json text not null,
                    updated_at text not null
                );
                """
            )
            for table, schema_version in TABLE_SCHEMAS.items():
                _ensure_schema_version_column(conn, table, schema_version)

    def _insert_dependencies(
        self,
        conn: sqlite3.Connection,
        *,
        context: dict[str, Any],
        owner_type: str,
        owner_id: str,
        dependencies: list[dict[str, Any]],
    ) -> None:
        for dependency in dependencies:
            conn.execute(
                """
                insert or replace into runtime_dependencies (
                    schema_version, organization_id, workspace_id, owner_type, owner_id,
                    dependency_id, dependency_type, dependency_hash, current_hash,
                    valid_until, status, payload_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    TABLE_SCHEMAS["runtime_dependencies"],
                    context["organization_id"],
                    context["workspace_id"],
                    owner_type,
                    owner_id,
                    dependency.get("dependency_id"),
                    dependency.get("dependency_type"),
                    dependency.get("dependency_hash"),
                    dependency.get("current_hash"),
                    dependency.get("valid_until"),
                    dependency.get("status", "valid"),
                    _json(dependency),
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)


def _count(conn: sqlite3.Connection, table: str, where: str, args: tuple[Any, ...]) -> int:
    row = conn.execute(f"select count(*) from {table} where {where}", args).fetchone()
    return int(row[0])


def _ensure_schema_version_column(conn: sqlite3.Connection, table: str, schema_version: str) -> None:
    columns = {row[1] for row in conn.execute(f"pragma table_info({table})")}
    if "schema_version" not in columns:
        conn.execute(f"alter table {table} add column schema_version text")
    conn.execute(f"update {table} set schema_version = ? where schema_version is null", (schema_version,))


def _scope_where(table: str) -> str:
    if table == "organizations":
        return "organization_id = ?"
    if table == "workspaces":
        return "organization_id = ? and workspace_id = ?"
    if table == "actors":
        return "organization_id = ?"
    return "organization_id = ? and workspace_id = ?"


def _scope_args(table: str, context: dict[str, str]) -> tuple[str, ...]:
    if table in {"organizations", "actors"}:
        return (context["organization_id"],)
    return (context["organization_id"], context["workspace_id"])


def _insert_row(conn: sqlite3.Connection, table: str, row: dict[str, Any]) -> None:
    row = dict(row)
    row["schema_version"] = row.get("schema_version") or TABLE_SCHEMAS[table]
    columns = list(row)
    placeholders = ", ".join("?" for _ in columns)
    column_sql = ", ".join(columns)
    values = tuple(row[column] for column in columns)
    conn.execute(f"insert or replace into {table} ({column_sql}) values ({placeholders})", values)


def _context(context: dict[str, Any] | None) -> dict[str, str]:
    merged = default_organization_context()
    merged.update({key: str(value) for key, value in (context or {}).items() if value is not None})
    return merged


def _authority_ref(authority: dict[str, Any]) -> str:
    contract_id = authority.get("contract_id")
    contract_version = authority.get("contract_version")
    if contract_id and contract_version:
        return f"{contract_id}@{contract_version}"
    return str(authority.get("authority_ref") or authority.get("contract_ref") or "")


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

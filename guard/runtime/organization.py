from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .identity import stable_id


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
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "guard-runtime.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
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
                    run_id, organization_id, workspace_id, environment, authority_ref,
                    request_id, actor_id, status, runtime_lifecycle_state, receipt_hash,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                    continuation_id, organization_id, workspace_id, run_id, execution_id,
                    status, runtime_lifecycle_state, admissible_until, lease_hash,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                    release_validation_id, organization_id, workspace_id, continuation_id,
                    outcome, release_allowed, release_blocked, runtime_lifecycle_state,
                    payload_json, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                    queue_id, organization_id, workspace_id, continuation_id, execution_id,
                    state, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
            "schema_version": "guard_persistent_runtime_dashboard.v1",
            "organization_context": context,
            "summary": summary,
            "recent_runs": recent_runs,
            "release_queue": release_queue,
        }

    def ensure_context(self, context: dict[str, Any] | None = None) -> dict[str, str]:
        context = _context(context)
        with self._connect() as conn:
            conn.execute(
                """
                insert or ignore into organizations (
                    organization_id, name, authority_namespace, status, created_at
                ) values (?, ?, ?, ?, ?)
                """,
                (
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
                    workspace_id, organization_id, environment, name, created_at
                ) values (?, ?, ?, ?, ?)
                """,
                (
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
                    actor_id, organization_id, role, team, clearance, delegation,
                    revocation, status, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                    authority_ref, organization_id, workspace_id, contract_hash,
                    authority_namespace, status, payload_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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
                    organization_id text primary key,
                    name text not null,
                    authority_namespace text not null,
                    status text not null,
                    created_at text not null
                );
                create table if not exists workspaces (
                    workspace_id text primary key,
                    organization_id text not null,
                    environment text not null,
                    name text not null,
                    created_at text not null
                );
                create table if not exists actors (
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
                    organization_id, workspace_id, owner_type, owner_id,
                    dependency_id, dependency_type, dependency_hash, current_hash,
                    valid_until, status, payload_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
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

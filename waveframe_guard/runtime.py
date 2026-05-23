from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import warnings
from uuid import uuid4
from urllib import request
from urllib.error import URLError
from urllib.parse import quote, urljoin

from cricore.api import evaluate_structured

from .context import install_guard
from .contracts import load_contract
from .execute import (
    GovernanceError,
    _blocked_reason as decision_blocked_reason,
    _build_run_context,
    execute as execute_guarded,
)
from .result import GovernedExecutionResult
from .schemas import (
    GOVERNED_EXECUTION_EVENT_V1,
    GOVERNED_EXECUTION_STATE_V1,
    SchemaValidationError,
    validate_execution_state,
    validate_governed_event,
)


AUTHORITY_SUPERSEDED_DURING_EXECUTION = "AUTHORITY_SUPERSEDED_DURING_EXECUTION"
AUTHORITY_REVOKED_POST_DECISION = "AUTHORITY_REVOKED_POST_DECISION"
ADMISSIBILITY_WINDOW_EXPIRED = "ADMISSIBILITY_WINDOW_EXPIRED"
ACTOR_CONTINUITY_BROKEN = "ACTOR_CONTINUITY_BROKEN"
REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"


class GovernedRuntime:
    def __init__(
        self,
        *,
        registry_path=None,
        registry_url=None,
        audit_path=None,
        cache_dir=None,
        evidence_dir=None,
        runtime_log_path=None,
        cloud_api_key=None,
        offline=False,
        require_verified_lineage=False,
        reject_revoked_authority=True,
        warn_on_superseded=True,
        admissibility_window_seconds=None,
    ):
        if registry_path is None and registry_url is None:
            raise ValueError("registry_path or registry_url is required")
        if registry_path is not None and registry_url is not None:
            raise ValueError("registry_path and registry_url are mutually exclusive")

        self.registry_path = Path(registry_path) if registry_path is not None else None
        self.registry_url = registry_url.rstrip("/") + "/" if registry_url is not None else None
        self.cache_dir = Path(cache_dir) if cache_dir is not None else self._default_cache_dir()
        self.evidence_dir = Path(evidence_dir) if evidence_dir is not None else None
        self.runtime_log_path = Path(runtime_log_path) if runtime_log_path is not None else None
        self.cloud_api_key = cloud_api_key
        self.offline = offline
        self.require_verified_lineage = require_verified_lineage
        self.reject_revoked_authority = reject_revoked_authority
        self.warn_on_superseded = warn_on_superseded
        self.admissibility_window_seconds = admissibility_window_seconds
        self.registry = self._load_registry()
        self.audit_path = Path(audit_path) if audit_path is not None else None
        self.audit_events = []
        self.runtime_logs = []
        self.last_event = None
        self.last_contract_source = None
        self.last_cache_path = None
        self.last_authority_lifecycle = None
        self.last_valid_until = None
        self.last_revalidation_required_after = None
        self.last_continuity_signals = []
        self.actor = None
        self.contract_id = None
        self.contract_version = None

        if self.evidence_dir is not None:
            for queue in ["pending", "sent", "failed"]:
                (self.evidence_dir / queue).mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_cloud(
        cls,
        *,
        authority,
        api_key,
        base_url="http://localhost:8000",
        cache_dir=None,
        evidence_dir=None,
        runtime_log_path=None,
        actor=None,
        **kwargs,
    ):
        evidence_root = Path(evidence_dir) if evidence_dir is not None else Path.cwd() / ".waveframe_guard" / "evidence"
        runtime = cls(
            registry_url=base_url,
            cache_dir=cache_dir,
            evidence_dir=evidence_root,
            runtime_log_path=runtime_log_path or evidence_root / "runtime-logs.jsonl",
            cloud_api_key=api_key,
            **kwargs,
        )
        runtime.bind_contract(authority)
        if actor is not None:
            runtime.install_actor(actor)
        return runtime

    def install_actor(self, actor):
        self.actor = actor
        return self

    def bind_contract(self, contract_id, contract_version=None):
        if contract_version is None and "@" in contract_id:
            contract_id, contract_version = contract_id.split("@", 1)
        self.contract_id = contract_id
        self.contract_version = contract_version
        return self

    def evaluate(
        self,
        *,
        actor=None,
        contract_id=None,
        contract_version=None,
        fn=None,
        args=None,
        kwargs=None,
        approvals=None,
        target=None,
        now=None,
    ):
        actor = self._resolve_actor(actor)
        contract_id, contract_version = self._resolve_contract_binding(contract_id, contract_version)
        self._log_runtime_event(
            "authority_resolution_started",
            authority_ref=_contract_ref(contract_id, contract_version),
        )
        entry = self._resolve_authority_entry(contract_id, contract_version)
        contract = self._load_contract_from_entry(entry)
        self._enforce_authority_lineage(contract)
        execution_state = _build_execution_state(
            actor=actor,
            contract=contract,
            fn=fn,
            args=args or (),
            kwargs=kwargs or {},
            approvals=approvals or [],
            target=target,
        )
        try:
            validate_execution_state(execution_state)
        except SchemaValidationError as exc:
            raise GovernanceError(f"Malformed execution state: {exc}") from exc

        self._log_runtime_event(
            "admissibility_evaluation_started",
            authority_ref=_contract_ref(contract_id, contract_version),
            action=execution_state.get("action"),
        )
        approval_decision = _evaluate_approval_admissibility(
            contract=contract,
            execution_state=execution_state,
        )
        self._record_continuity_metadata(entry, now=now)
        self._log_runtime_event(
            "admissibility_evaluation_completed",
            authority_ref=_contract_ref(contract_id, contract_version),
            allowed=approval_decision["allowed"],
            reason=approval_decision["reason"],
            continuity_signals=self.last_continuity_signals,
        )
        return GovernedExecutionResult(
            allowed=approval_decision["allowed"],
            reason=approval_decision["reason"],
            missing_approvals=approval_decision["missing_approvals"],
            execution_state=execution_state,
            decision_trace=approval_decision.get("trace"),
            **self._contract_metadata(contract),
        )

    def revalidate(self, decision, *, actor=None, now=None):
        execution_state = decision.execution_state if isinstance(decision, GovernedExecutionResult) else decision
        if not isinstance(execution_state, dict):
            raise ValueError("revalidate requires a GovernedExecutionResult or execution_state")
        authority_ref = execution_state.get("authority_ref")
        contract_id, contract_version = _split_contract_ref(authority_ref)
        current_actor = actor or execution_state.get("actor")
        entry = self._lookup_contract(contract_id, contract_version)
        contract = self._load_contract_from_entry(entry)

        signals = []
        lifecycle = _authority_lifecycle(entry)
        if lifecycle is not None:
            status = lifecycle["status"]
            if status == "revoked":
                signals.append(AUTHORITY_REVOKED_POST_DECISION)
            elif status == "superseded":
                signals.append(AUTHORITY_SUPERSEDED_DURING_EXECUTION)

        if _actor_identity(current_actor) != _actor_identity(execution_state.get("actor")):
            signals.append(ACTOR_CONTINUITY_BROKEN)

        valid_until = getattr(decision, "valid_until", None)
        if _window_expired(valid_until, now or datetime.now(timezone.utc)):
            signals.append(ADMISSIBILITY_WINDOW_EXPIRED)

        signals = _with_revalidation_required(signals)
        self.last_authority_lifecycle = lifecycle
        self.last_valid_until = valid_until
        self.last_revalidation_required_after = getattr(decision, "revalidation_required_after", None)
        self.last_continuity_signals = signals
        self._log_runtime_event(
            "admissibility_revalidation_completed",
            authority_ref=authority_ref,
            continuity_signals=signals,
        )
        return GovernedExecutionResult(
            allowed=decision.allowed if isinstance(decision, GovernedExecutionResult) else True,
            reason=decision.reason if isinstance(decision, GovernedExecutionResult) else "revalidation completed",
            execution_state=execution_state,
            decision_trace=decision.decision_trace if isinstance(decision, GovernedExecutionResult) else None,
            missing_approvals=decision.missing_approvals if isinstance(decision, GovernedExecutionResult) else [],
            **self._contract_metadata(contract),
        )

    def execute(
        self,
        *,
        actor=None,
        contract_id=None,
        contract_version=None,
        fn,
        args=None,
        kwargs=None,
        approvals=None,
        raise_on_block=True,
    ):
        actor = self._resolve_actor(actor)
        contract_id, contract_version = self._resolve_contract_binding(contract_id, contract_version)
        self._log_runtime_event(
            "authority_resolution_started",
            authority_ref=_contract_ref(contract_id, contract_version),
        )
        entry = self._resolve_authority_entry(contract_id, contract_version)
        contract = self._load_contract_from_entry(entry)
        self._enforce_authority_lineage(contract)
        execution_state = _build_execution_state(
            actor=actor,
            contract=contract,
            fn=fn,
            args=args or (),
            kwargs=kwargs or {},
            approvals=approvals or [],
        )
        try:
            validate_execution_state(execution_state)
        except SchemaValidationError as exc:
            raise GovernanceError(f"Malformed execution state: {exc}") from exc

        self._log_runtime_event(
            "admissibility_evaluation_started",
            authority_ref=_contract_ref(contract_id, contract_version),
            action=execution_state.get("action"),
        )
        approval_decision = _evaluate_approval_admissibility(
            contract=contract,
            execution_state=execution_state,
        )
        self._record_continuity_metadata(entry)
        self._log_runtime_event(
            "admissibility_evaluation_completed",
            authority_ref=_contract_ref(contract_id, contract_version),
            allowed=approval_decision["allowed"],
            reason=approval_decision["reason"],
            continuity_signals=self.last_continuity_signals,
        )
        if not approval_decision["allowed"]:
            error = f"Execution blocked: {approval_decision['reason']}"
            event = self._build_event(
                actor=actor,
                contract=contract,
                execution_type="function",
                allowed=False,
                reason=approval_decision["reason"],
                error=error,
                target=getattr(fn, "__name__", None),
                execution_state=execution_state,
                missing_approvals=approval_decision["missing_approvals"],
            )
            self._emit_event(event)
            if raise_on_block:
                raise GovernanceError(error)
            return GovernedExecutionResult(
                allowed=False,
                reason=approval_decision["reason"],
                error=error,
                event=event,
                audit_receipt=event.get("audit_receipt"),
                missing_approvals=approval_decision["missing_approvals"],
                execution_state=execution_state,
                decision_trace=approval_decision.get("trace"),
                **self._contract_metadata(contract),
            )

        if _has_approval_requirements(contract):
            value = fn(*(args or ()), **(kwargs or {}))
        else:
            install_guard(
                actor=actor,
                contract=contract,
                mode="local",
            )
            try:
                value = execute_guarded(
                    fn,
                    args=args or (),
                    kwargs=kwargs or {},
                    actor=actor,
                    contract=contract,
                )
            except GovernanceError as exc:
                error = str(exc)
                event = self._build_event(
                    actor=actor,
                    contract=contract,
                    execution_type="function",
                    allowed=False,
                    reason=self._blocked_reason(error),
                    error=error,
                    target=getattr(fn, "__name__", None),
                    execution_state=execution_state,
                )
                self._emit_event(event)
                if raise_on_block:
                    raise

                return GovernedExecutionResult(
                    allowed=False,
                    reason=self._blocked_reason(error),
                    error=error,
                    event=event,
                    audit_receipt=event.get("audit_receipt"),
                    execution_state=execution_state,
                    decision_trace=_legacy_decision_trace(False, self._blocked_reason(error)),
                    **self._contract_metadata(contract),
                )

        event = self._build_event(
            actor=actor,
            contract=contract,
            execution_type="function",
            allowed=True,
            reason="execution allowed",
            target=getattr(fn, "__name__", None),
            execution_state=execution_state,
        )
        self._emit_event(event)

        if raise_on_block:
            return value

        return GovernedExecutionResult(
            allowed=True,
            reason="execution allowed",
            value=value,
            event=event,
            audit_receipt=event.get("audit_receipt"),
            execution_state=execution_state,
            decision_trace=approval_decision.get("trace"),
            **self._contract_metadata(contract),
        )

    def execute_proposal(
        self,
        proposal,
        *,
        actor=None,
        contract_id=None,
        contract_version=None,
        raise_on_block=True,
    ):
        actor = self._resolve_actor(actor)
        contract_id, contract_version = self._resolve_contract_binding(contract_id, contract_version)
        self._log_runtime_event(
            "authority_resolution_started",
            authority_ref=_contract_ref(contract_id, contract_version),
        )
        entry = self._resolve_authority_entry(contract_id, contract_version)
        contract = self._load_contract_from_entry(entry)
        self._enforce_authority_lineage(contract)

        install_guard(
            actor=actor,
            contract=contract,
            mode="local",
        )

        decision = evaluate_structured(
            proposal=proposal,
            compiled_contract=contract,
            run_context=_build_run_context(actor, contract, "local"),
        )
        self._log_runtime_event(
            "admissibility_evaluation_completed",
            authority_ref=_contract_ref(contract_id, contract_version),
            allowed=decision.commit_allowed,
            reason="execution allowed" if decision.commit_allowed else decision_blocked_reason(decision),
            execution_type="proposal",
        )

        if decision.commit_allowed:
            event = self._build_event(
                actor=actor,
                contract=contract,
                execution_type="proposal",
                allowed=True,
                reason="execution allowed",
                target=proposal.get("proposal_id") if isinstance(proposal, dict) else None,
            )
            self._emit_event(event)
            return GovernedExecutionResult(
                allowed=True,
                reason="execution allowed",
                value=proposal,
                event=event,
                audit_receipt=event.get("audit_receipt"),
                **self._contract_metadata(contract),
            )

        reason = decision_blocked_reason(decision)
        error = f"Execution blocked: {reason}"
        event = self._build_event(
            actor=actor,
            contract=contract,
            execution_type="proposal",
            allowed=False,
            reason=reason,
            error=error,
            target=proposal.get("proposal_id") if isinstance(proposal, dict) else None,
        )
        self._emit_event(event)
        if raise_on_block:
            raise GovernanceError(error)

        return GovernedExecutionResult(
            allowed=False,
            reason=reason,
            error=error,
            event=event,
            audit_receipt=event.get("audit_receipt"),
            **self._contract_metadata(contract),
        )

    def _load_registry(self):
        if self.registry_url is not None:
            if self.offline:
                cached_registry = self.cache_dir / "registry-index.json"
                if cached_registry.exists():
                    registry = load_contract(cached_registry)
                    _validate_registry_integrity(registry)
                    return registry
                raise GovernanceError("Offline mode requires cached registry-index.json")
            registry = self._fetch_json("registry/index.json")
            _validate_registry_integrity(registry)
            self._write_cached_json(self.cache_dir / "registry-index.json", registry)
            return registry

        with self.registry_path.open("r", encoding="utf-8") as f:
            registry = json.load(f)
            _validate_registry_integrity(registry)
            return registry

    def _load_contract(self, contract_id, contract_version=None):
        entry = self._resolve_authority_entry(contract_id, contract_version)
        return self._load_contract_from_entry(entry)

    def _resolve_authority_entry(self, contract_id, contract_version=None):
        authority_ref = _contract_ref(contract_id, contract_version)
        try:
            entry = self._lookup_contract(contract_id, contract_version)
        except Exception as exc:
            self._log_runtime_event(
                "authority_resolution_failed",
                authority_ref=authority_ref,
                error=str(exc),
            )
            raise
        self._log_runtime_event("authority_resolution_completed", authority_ref=authority_ref)
        self._validate_authority_lifecycle(entry)
        return entry

    def _load_contract_from_entry(self, entry):
        if self.registry_url is not None:
            return self._load_remote_contract(entry)

        contract_path = self._contract_path(entry)
        contract = load_contract(contract_path)
        _validate_contract_against_entry(entry, contract)
        self.last_contract_source = "filesystem"
        self.last_cache_path = str(contract_path)
        return contract

    def _resolve_actor(self, actor):
        resolved = actor or self.actor
        if resolved is None:
            raise ValueError("Missing actor")
        return resolved

    def _resolve_contract_binding(self, contract_id, contract_version=None):
        resolved_id = contract_id or self.contract_id
        resolved_version = contract_version or self.contract_version
        if resolved_id and resolved_version is None and "@" in resolved_id:
            resolved_id, resolved_version = resolved_id.split("@", 1)
        if resolved_id is None:
            raise ValueError("Missing contract_id")
        if resolved_version is None:
            raise ValueError("Missing contract_version; bind explicit authority_ref like 'finance-policy@1.0.0'")
        return resolved_id, resolved_version

    def _lookup_contract(self, contract_id, contract_version=None):
        contracts = self.registry.get("contracts", self.registry)

        if isinstance(contracts, dict):
            entry = contracts.get(f"{contract_id}@{contract_version}") if contract_version else None
            if entry is None:
                entry = contracts.get(contract_id)
            if entry is None:
                raise KeyError(f"Unknown contract: {_contract_ref(contract_id, contract_version)}")
            if contract_version is not None and _entry_version(entry) != contract_version:
                raise KeyError(f"Unknown contract: {_contract_ref(contract_id, contract_version)}")
            return entry

        if isinstance(contracts, list):
            candidates = [
                entry
                for entry in contracts
                if _entry_contract_id(entry) == contract_id
            ]
            if contract_version is not None:
                for entry in candidates:
                    if _entry_version(entry) == contract_version:
                        return entry
                raise KeyError(f"Unknown contract: {_contract_ref(contract_id, contract_version)}")
            if candidates:
                refs = ", ".join(
                    _contract_ref(entry.get("contract_id") or entry.get("id"), _entry_version(entry))
                    for entry in candidates
                )
                raise KeyError(f"Ambiguous authority {contract_id}; bind one of: {refs}")

        raise KeyError(f"Unknown contract: {_contract_ref(contract_id, contract_version)}")

    def _contract_path(self, entry):
        if isinstance(entry, str):
            path = Path(entry)
        elif isinstance(entry, dict):
            path_value = (
                entry.get("path")
                or entry.get("contract_path")
                or entry.get("artifact")
            )
            if path_value is None:
                raise ValueError("Registry entry is missing a contract path")
            path = Path(path_value)
        else:
            raise ValueError("Registry entry must be a path string or object")

        if path.is_absolute():
            return path

        return self.registry_path.parent / path

    def _load_remote_contract(self, entry):
        if not isinstance(entry, dict):
            raise ValueError("Remote registry entries must be objects")

        contract_id = _entry_contract_id(entry)
        version = _entry_version(entry)
        if not contract_id or not version:
            raise ValueError("Remote registry entry is missing contract identity")

        cache_path = self._cache_path(contract_id, version, entry.get("contract_hash"))
        if self.offline:
            if cache_path.exists():
                contract = load_contract(cache_path)
                _validate_contract_against_entry(entry, contract)
                self.last_contract_source = "cache"
                self.last_cache_path = str(cache_path)
                return contract
            raise GovernanceError(f"Offline mode requires cached contract: {_contract_ref(contract_id, version)}")

        try:
            contract = self._fetch_json(
                f"contracts/{quote(contract_id, safe='')}/{quote(version, safe='')}"
            )
        except URLError:
            if cache_path.exists():
                contract = load_contract(cache_path)
                _validate_contract_against_entry(entry, contract)
                self.last_contract_source = "cache"
                self.last_cache_path = str(cache_path)
                return contract
            raise

        _validate_contract_against_entry(entry, contract)
        self._write_cached_contract(cache_path, contract)
        self.last_contract_source = "registry_url"
        self.last_cache_path = str(cache_path)
        return contract

    def _fetch_json(self, path):
        url = urljoin(self.registry_url, path)
        headers = {}
        if self.cloud_api_key:
            headers["Authorization"] = f"Bearer {self.cloud_api_key}"
        req = request.Request(url, headers=headers, method="GET")
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post_json(self, path, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.cloud_api_key:
            headers["Authorization"] = f"Bearer {self.cloud_api_key}"
        req = request.Request(
            urljoin(self.registry_url, path),
            data=body,
            headers=headers,
            method="POST",
        )
        with request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _default_cache_dir(self):
        if self.registry_path is not None:
            return self.registry_path.parent / ".waveframe_guard_cache"
        return Path.cwd() / ".waveframe_guard_cache"

    def _cache_path(self, contract_id, version, contract_hash):
        safe_hash = (contract_hash or "unhashed").replace(":", "_")
        return self.cache_dir / f"{contract_id}-{version}-{safe_hash}.contract.json"

    def _write_cached_contract(self, path, contract):
        self._write_cached_json(path, contract)

    def _write_cached_json(self, path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        if path.exists() and path.read_text(encoding="utf-8") != serialized:
            raise GovernanceError(f"Cached artifact is immutable and differs: {path}")
        path.write_text(serialized, encoding="utf-8")

    def _contract_metadata(self, contract):
        metadata = {
            "contract_id": contract.get("contract_id"),
            "contract_version": contract.get("contract_version"),
            "contract_hash": contract.get("contract_hash"),
            "valid_until": self.last_valid_until,
            "revalidation_required_after": self.last_revalidation_required_after,
            "continuity_signals": self.last_continuity_signals,
        }
        if self.last_authority_lifecycle is not None:
            metadata["authority_lifecycle"] = self.last_authority_lifecycle
        return metadata

    def _record_continuity_metadata(self, entry, *, now=None):
        now = now or datetime.now(timezone.utc)
        valid_until = _valid_until(entry, now, self.admissibility_window_seconds)
        signals = []
        lifecycle = _authority_lifecycle(entry)
        if lifecycle is not None and lifecycle["status"] == "superseded":
            signals.append(AUTHORITY_SUPERSEDED_DURING_EXECUTION)
        if lifecycle is not None and lifecycle["status"] == "revoked":
            signals.append(AUTHORITY_REVOKED_POST_DECISION)
        if _window_expired(valid_until, now):
            signals.append(ADMISSIBILITY_WINDOW_EXPIRED)
        signals = _with_revalidation_required(signals)
        self.last_valid_until = valid_until
        self.last_revalidation_required_after = valid_until
        self.last_continuity_signals = signals
        return {
            "valid_until": valid_until,
            "revalidation_required_after": valid_until,
            "continuity_signals": signals,
        }

    def _validate_authority_lifecycle(self, entry):
        lifecycle = _authority_lifecycle(entry)
        self.last_authority_lifecycle = lifecycle
        if lifecycle is None:
            return

        authority_ref = lifecycle["authority_ref"]
        status = lifecycle["status"]
        if status == "revoked" and self.reject_revoked_authority:
            self._log_runtime_event(
                "revoked_authority_rejected",
                authority_ref=authority_ref,
                lifecycle=lifecycle,
            )
            raise GovernanceError(f"Authority lifecycle invalidated: {authority_ref} is revoked")
        if status == "superseded" and self.warn_on_superseded:
            warnings.warn(
                f"Authority lifecycle warning: {authority_ref} is superseded",
                RuntimeWarning,
                stacklevel=3,
            )

    def _enforce_authority_lineage(self, contract):
        if not self.require_verified_lineage:
            return
        lineage = contract.get("lineage")
        if not isinstance(lineage, dict):
            self._log_runtime_event(
                "lineage_validation_failed",
                authority_ref=_contract_ref(contract.get("contract_id"), contract.get("contract_version")),
                reason="missing lineage",
            )
            raise GovernanceError("Authority provenance verification failed: missing lineage")
        if lineage.get("schema_version") != "governance_authority_lineage.v1":
            self._log_runtime_event(
                "lineage_validation_failed",
                authority_ref=_contract_ref(contract.get("contract_id"), contract.get("contract_version")),
                reason="unsupported lineage schema",
            )
            raise GovernanceError("Authority provenance verification failed: unsupported lineage schema")
        for field in ["source_hash", "compilation_report_hash"]:
            value = lineage.get(field)
            if not isinstance(value, str) or not value.startswith("sha256:"):
                self._log_runtime_event(
                    "lineage_validation_failed",
                    authority_ref=_contract_ref(contract.get("contract_id"), contract.get("contract_version")),
                    reason=f"missing {field}",
                )
                raise GovernanceError(f"Authority provenance verification failed: missing {field}")
        self._log_runtime_event(
            "lineage_validation_completed",
            authority_ref=_contract_ref(contract.get("contract_id"), contract.get("contract_version")),
        )

    def _build_event(
        self,
        *,
        actor,
        contract,
        execution_type,
        allowed,
        reason,
        error=None,
        target=None,
        approvals=None,
        missing_approvals=None,
        execution_state=None,
    ):
        if execution_state is None:
            execution_state = _build_execution_state(
                actor=actor,
                contract=contract,
                fn=None,
                args=(),
                kwargs={},
                approvals=approvals or [],
                target=target,
            )
        event = {
            "event_id": str(uuid4()),
            "schema_version": GOVERNED_EXECUTION_EVENT_V1,
            "event_type": "governed_execution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_type": execution_type,
            "allowed": allowed,
            "decision": "ALLOWED" if allowed else "BLOCKED",
            "reason": reason,
            "actor": actor,
            "approvals": execution_state.get("approvals", []),
            "missing_approvals": missing_approvals or [],
            "execution_state": execution_state,
            "authority_ref": _contract_ref(
                contract.get("contract_id"),
                contract.get("contract_version"),
            ),
            "contract_ref": _contract_ref(
                contract.get("contract_id"),
                contract.get("contract_version"),
            ),
            "contract_source": self.last_contract_source,
            "cache_path": self.last_cache_path,
            **self._contract_metadata(contract),
        }

        if error is not None:
            event["error"] = error

        if target is not None:
            event["target"] = target

        try:
            validate_governed_event(event)
        except SchemaValidationError as exc:
            raise GovernanceError(f"Malformed governed execution event: {exc}") from exc
        return event

    def _emit_event(self, event):
        self.last_event = event
        self.audit_events.append(event)

        if self.audit_path is not None:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")

        if self.evidence_dir is not None:
            self._queue_evidence_event(event)
        elif self.registry_url is not None and not self.offline:
            event["audit_receipt"] = self._post_json("audit-events", event)

    def _blocked_reason(self, error):
        prefix = "Execution blocked: "
        if error.startswith(prefix):
            return error[len(prefix):]

        return error

    def _queue_evidence_event(self, event):
        pending_path = self.evidence_dir / "pending" / f"{event['event_id']}.json"
        pending_path.write_text(json.dumps(event, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def flush_evidence(self):
        if self.evidence_dir is None:
            return {"pending": 0, "sent": 0, "failed": 0}
        if self.registry_url is None or self.offline:
            return self._evidence_counts()

        for queue in ["pending", "failed"]:
            for evidence_path in sorted((self.evidence_dir / queue).glob("*.json")):
                payload = json.loads(evidence_path.read_text(encoding="utf-8"))
                payload.pop("audit_receipt", None)
                try:
                    receipt = self._post_json("audit-events", payload)
                except Exception as exc:
                    payload["flush_error"] = str(exc)
                    failed_path = self.evidence_dir / "failed" / evidence_path.name
                    failed_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    if evidence_path != failed_path:
                        evidence_path.unlink()
                    continue

                payload["audit_receipt"] = receipt
                sent_path = self.evidence_dir / "sent" / evidence_path.name
                sent_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                evidence_path.unlink()
        return self._evidence_counts()

    def _evidence_counts(self):
        return {
            queue: len(list((self.evidence_dir / queue).glob("*.json")))
            for queue in ["pending", "sent", "failed"]
        }

    def _log_runtime_event(self, event_type, **details):
        event = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **details,
        }
        self.runtime_logs.append(event)
        if self.runtime_log_path is not None:
            self.runtime_log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.runtime_log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")
        return event


def _entry_version(entry):
    if isinstance(entry, dict):
        version = entry.get("contract_version") or entry.get("version")
        if version:
            return version
        authority_ref = entry.get("authority_ref") or entry.get("contract_ref")
        if isinstance(authority_ref, str) and "@" in authority_ref:
            return authority_ref.split("@", 1)[1]
    return None


def _entry_contract_id(entry):
    if not isinstance(entry, dict):
        return None
    contract_id = entry.get("contract_id") or entry.get("id")
    if contract_id:
        return contract_id
    authority_ref = entry.get("authority_ref") or entry.get("contract_ref")
    if isinstance(authority_ref, str) and "@" in authority_ref:
        return authority_ref.split("@", 1)[0]
    return None


def _contract_ref(contract_id, contract_version=None):
    if contract_version is None:
        return contract_id
    return f"{contract_id}@{contract_version}"


def _split_contract_ref(authority_ref):
    if not isinstance(authority_ref, str) or "@" not in authority_ref:
        raise ValueError("authority_ref must be an explicit versioned authority ref")
    return authority_ref.split("@", 1)


def _authority_lifecycle(entry):
    if not isinstance(entry, dict):
        return None
    status = entry.get("status") or entry.get("authority_status") or entry.get("lifecycle_status")
    if not isinstance(status, str) or not status.strip():
        return None
    contract_id = _entry_contract_id(entry)
    contract_version = _entry_version(entry)
    authority_ref = entry.get("authority_ref") or _contract_ref(contract_id, contract_version)
    lifecycle = {
        "authority_ref": authority_ref,
        "status": status.strip().lower(),
    }
    if entry.get("superseded_by") is not None:
        lifecycle["superseded_by"] = entry.get("superseded_by")
    if entry.get("status_reason") is not None:
        lifecycle["status_reason"] = entry.get("status_reason")
    return lifecycle


def _valid_until(entry, now, runtime_window_seconds=None):
    if isinstance(entry, dict):
        explicit = _first_present(entry, "valid_until", "admissibility_valid_until")
        if explicit is not None:
            return _normalize_timestamp(explicit)
        window_seconds = _first_present(
            entry,
            "admissibility_window_seconds",
            "admissibility_validity_seconds",
            default=runtime_window_seconds,
        )
    else:
        window_seconds = runtime_window_seconds
    if window_seconds is None:
        return None
    return (now + timedelta(seconds=float(window_seconds))).isoformat()


def _first_present(payload, *keys, default=None):
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return default


def _window_expired(valid_until, now):
    expires_at = _parse_timestamp(valid_until)
    if expires_at is None:
        return False
    return now > expires_at


def _normalize_timestamp(value):
    parsed = _parse_timestamp(value)
    if parsed is None:
        raise ValueError("valid_until must be an ISO-8601 timestamp")
    return parsed.isoformat()


def _parse_timestamp(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _with_revalidation_required(signals):
    deduped = []
    for signal in signals:
        if signal not in deduped:
            deduped.append(signal)
    if deduped and REVALIDATION_REQUIRED not in deduped:
        deduped.append(REVALIDATION_REQUIRED)
    return deduped


def _actor_identity(actor):
    if not isinstance(actor, dict):
        return None
    return (actor.get("id"), actor.get("type"), actor.get("role"))


def _has_approval_requirements(contract):
    return bool(contract.get("approval_requirements", {}).get("required"))


def _build_execution_state(*, actor, contract, fn, args, kwargs, approvals, target=None):
    authority_ref = _contract_ref(
        contract.get("contract_id"),
        contract.get("contract_version"),
    )
    return {
        "schema_version": GOVERNED_EXECUTION_STATE_V1,
        "authority_ref": authority_ref,
        "source_hash": (contract.get("lineage") or {}).get("source_hash"),
        "compilation_report_hash": (contract.get("lineage") or {}).get("compilation_report_hash"),
        "actor": actor,
        "approvals": [_normalize_approval_evidence(approval) for approval in approvals],
        "action": getattr(fn, "__name__", None) or target,
        "target": target or getattr(fn, "__name__", None),
        "arguments": {
            "amount": _execution_amount(args, kwargs),
        },
        "artifacts": [],
    }


def _normalize_approval_evidence(approval):
    if not isinstance(approval, dict):
        return {"role": None, "approved_by": None, "invalid": True}
    normalized = dict(approval)
    role = normalized.get("role")
    approved_by = normalized.get("approved_by")
    normalized["role"] = role.strip().lower() if isinstance(role, str) else role
    normalized["approved_by"] = approved_by.strip() if isinstance(approved_by, str) else approved_by
    return normalized


def evaluate_admissibility(contract, execution_state):
    return _evaluate_approval_admissibility(contract=contract, execution_state=execution_state)


def _evaluate_approval_admissibility(*, contract, execution_state):
    required = contract.get("approval_requirements", {}).get("required") or []
    if not required:
        return {
            "allowed": True,
            "reason": "approval evidence not required",
            "missing_approvals": [],
            "trace": _approval_trace([], [], [], "approval evidence not required"),
        }

    approvals = execution_state.get("approvals", [])
    actor = execution_state.get("actor", {})
    invalid = _invalid_approval_evidence(approvals)
    if invalid is not None:
        return {
            "allowed": False,
            "reason": invalid,
            "missing_approvals": [],
            "trace": _approval_trace(required, [], [], invalid),
        }

    amount = execution_state.get("arguments", {}).get("amount")
    applicable = [
        requirement
        for requirement in required
        if _condition_applies(requirement.get("condition"), amount)
    ]
    missing = []
    satisfied = []
    for requirement in applicable:
        role = requirement.get("role")
        approval = _approval_for_role(approvals, role)
        if not approval:
            missing.append({"role": role, "condition": requirement.get("condition")})
        else:
            satisfied.append({"role": role, "approved_by": approval.get("approved_by")})

    if missing:
        roles = ", ".join(item["role"] for item in missing if item.get("role"))
        return {
            "allowed": False,
            "reason": f"required approval missing: {roles}",
            "missing_approvals": missing,
            "trace": _approval_trace(applicable, satisfied, missing, f"required approval missing: {roles}"),
        }

    if contract.get("invariants", {}).get("separation_of_duties") is True:
        actor_id = actor.get("id")
        for approval in approvals:
            if approval.get("approved_by") == actor_id:
                return {
                    "allowed": False,
                    "reason": "separation of duties violated: requester approved own transfer",
                    "missing_approvals": [],
                    "trace": _approval_trace(
                        applicable,
                        satisfied,
                        [],
                        "separation of duties violated: requester approved own transfer",
                    ),
                }

    reused = _reused_approval_identity(satisfied)
    if reused is not None:
        return {
            "allowed": False,
            "reason": reused,
            "missing_approvals": [],
            "trace": _approval_trace(applicable, satisfied, [], reused),
        }

    return {
        "allowed": True,
        "reason": "approval evidence satisfied",
        "missing_approvals": [],
        "trace": _approval_trace(applicable, satisfied, [], "approval evidence satisfied"),
    }


def _approval_trace(required, satisfied, missing, reason):
    return {
        "schema_version": "governed_decision_trace.v1",
        "reason": reason,
        "required_approvals": required,
        "satisfied_approvals": satisfied,
        "missing_approvals": missing,
        "conditions_triggered": [
            requirement["condition"]
            for requirement in required
            if isinstance(requirement, dict) and isinstance(requirement.get("condition"), dict)
        ],
    }


def _legacy_decision_trace(allowed, reason):
    return {
        "schema_version": "governed_decision_trace.v1",
        "reason": reason,
        "required_approvals": [],
        "satisfied_approvals": [],
        "missing_approvals": [],
        "conditions_triggered": [],
        "legacy_guard_decision": True,
        "allowed": allowed,
    }


def _approval_for_role(approvals, role):
    for approval in approvals:
        if (
            isinstance(approval, dict)
            and approval.get("role") == role
            and isinstance(approval.get("approved_by"), str)
            and approval.get("approved_by")
        ):
            return approval
    return None


def _invalid_approval_evidence(approvals):
    for approval in approvals:
        if not isinstance(approval, dict) or approval.get("invalid"):
            return "invalid approval evidence: approval must be an object"
        if not isinstance(approval.get("role"), str) or not approval.get("role"):
            return "invalid approval evidence: role is required"
        if not isinstance(approval.get("approved_by"), str) or not approval.get("approved_by"):
            return "invalid approval evidence: approved_by is required"
    return None


def _reused_approval_identity(satisfied):
    by_approver = {}
    for approval in satisfied:
        approved_by = approval.get("approved_by")
        by_approver.setdefault(approved_by, set()).add(approval.get("role"))
    for approved_by, roles in by_approver.items():
        if approved_by and len(roles) > 1:
            return (
                "approval identity reused across required roles: "
                f"{approved_by} satisfied {', '.join(sorted(roles))}"
            )
    return None


def _execution_amount(args, kwargs):
    if isinstance(kwargs, dict) and "amount" in kwargs:
        return kwargs["amount"]
    if args:
        return args[0]
    return None


def _condition_applies(condition, amount):
    if not condition:
        return True
    if condition.get("field") != "amount":
        return False
    if amount is None:
        return True
    operator = condition.get("operator")
    value = condition.get("value")
    if operator == ">":
        return amount > value
    if operator == ">=":
        return amount >= value
    if operator == "<":
        return amount < value
    if operator == "<=":
        return amount <= value
    if operator == "==":
        return amount == value
    return False


def _version_tuple(version):
    if not isinstance(version, str):
        return (-1, -1, -1)
    parts = version.split(".")
    if len(parts) != 3:
        return (-1, -1, -1)
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return (-1, -1, -1)


def _validate_contract_against_entry(entry, contract):
    if isinstance(entry, str):
        return
    contract_id = _entry_contract_id(entry)
    contract_version = _entry_version(entry)
    authority_ref = _contract_ref(contract_id, contract_version)
    if contract.get("contract_id") != contract_id:
        raise GovernanceError(f"Contract identity mismatch for {authority_ref}")
    if contract.get("contract_version") != contract_version:
        raise GovernanceError(f"Contract version mismatch for {authority_ref}")
    expected_hash = _normalize_hash(entry.get("contract_hash"))
    embedded_hash = _normalize_hash(contract.get("contract_hash"))
    actual_hash = _normalize_hash(_compute_contract_hash(contract))
    if embedded_hash and embedded_hash != actual_hash:
        raise GovernanceError(f"Embedded contract hash mismatch for {authority_ref}")
    if expected_hash and actual_hash != expected_hash:
        raise GovernanceError(f"Contract hash mismatch for {authority_ref}")


def _compute_contract_hash(contract):
    canonical_contract = {
        key: value
        for key, value in contract.items()
        if key != "contract_hash"
    }
    canonical = json.dumps(canonical_contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize_hash(value):
    if not isinstance(value, str) or not value:
        return None
    return value if value.startswith("sha256:") else f"sha256:{value}"


def _validate_registry_integrity(registry):
    registry_hash = _normalize_hash(registry.get("registry_hash"))
    if not registry_hash:
        return
    canonical_registry = {
        key: value
        for key, value in registry.items()
        if key != "registry_hash"
    }
    canonical = json.dumps(canonical_registry, sort_keys=True, separators=(",", ":"))
    actual_hash = _normalize_hash(hashlib.sha256(canonical.encode("utf-8")).hexdigest())
    if actual_hash != registry_hash:
        raise GovernanceError("Registry hash mismatch")


GuardRuntime = GovernedRuntime

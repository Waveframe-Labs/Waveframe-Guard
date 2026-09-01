from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
from copy import deepcopy
from functools import wraps
from time import perf_counter_ns
from typing import Any, Callable

from guard.runtime import evaluate_runtime
from guard.runtime.builders import validate_guard_enforcement_outcome
from guard.runtime.identity import stable_hash
from waveframe_guard.cloud import CloudPreservationClient, CloudRuntimeClient
from waveframe_guard.authority.runtime_facts import (
    RepositoryChangesFactProvider,
    VerifiedRuntimeAuthority,
)
from waveframe_guard.authority.types import LoadedAuthority
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from .local_persistence import build_execution_attestation


GUARD_CLOUD_PRESERVATION_PACKAGE_V1 = "guard_cloud_preservation_package.v1"


class GuardExecutionError(RuntimeError):
    def __init__(self, message: str, *, evaluation: dict[str, Any]):
        super().__init__(message)
        self.evaluation = evaluation
        self.outcome = evaluation["enforcement_outcome"]


class GuardExecutionBlocked(GuardExecutionError):
    pass


class GuardExecutionEscalated(GuardExecutionError):
    pass


class GuardRuntimeBoundary:
    """Callable execution boundary backed by compiled authority evaluation."""

    def __init__(
        self,
        *,
        compiled_authority: dict[str, Any],
        loaded_authority: LoadedAuthority | None = None,
        actor_identity: dict[str, Any],
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time_source: Callable[[], str] | None = None,
        store: Any | None = None,
        cloud_preservation_client: CloudPreservationClient | None = None,
        cloud_runtime_client: CloudRuntimeClient | None = None,
    ):
        self.compiled_authority = deepcopy(compiled_authority)
        self.loaded_authority = deepcopy(loaded_authority)
        self._verified_runtime_authority = None
        self.timing_diagnostics: dict[str, int | None] = {
            "cold_load_validation_ns": None,
            "warm_integrity_and_fact_derivation_ns": None,
        }
        if self.compiled_authority.get("schema_version") == "compiled_authority_contract.v2":
            if self.loaded_authority is None:
                raise AuthorityVerificationError(
                    "compiled_authority_contract.v2 requires a verified authority bundle and publication receipt"
                )
            if dict(self.loaded_authority.contract) != self.compiled_authority:
                raise AuthorityVerificationError(
                    "verified authority contract does not match the evaluated v2 contract"
                )
            self._verified_runtime_authority = VerifiedRuntimeAuthority.from_loaded(
                self.loaded_authority
            )
            self.timing_diagnostics["cold_load_validation_ns"] = (
                self._verified_runtime_authority.cold_validation_duration_ns
            )
        self.actor_identity = actor_identity
        self.approvals = approvals or []
        self.continuity_state = continuity_state or {}
        self.replay_posture = replay_posture or {}
        self.execution_context = execution_context or {"surface": "sdk"}
        self.evaluation_time_source = evaluation_time_source or _utc_now
        self.store = store
        self.cloud_preservation_client = cloud_preservation_client
        self.cloud_runtime_client = cloud_runtime_client

    def evaluate(
        self,
        execution_request: dict[str, Any],
        *,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time: str | None = None,
        start_sequence: int = 1,
        save: bool = True,
    ) -> dict[str, Any]:
        original_request = deepcopy(execution_request)
        selected_actor = deepcopy(actor_identity or self.actor_identity)
        v2_facts = None
        authority_evidence = None
        evaluation_request = original_request
        evaluation_actor = selected_actor
        verified_v2 = self._verified_runtime_authority is not None
        evaluated_contract = self.compiled_authority
        if verified_v2:
            warm_started_ns = perf_counter_ns()
            self._verified_runtime_authority.verify_candidate_contract(self.compiled_authority)
            evaluated_contract = self._verified_runtime_authority.contract()
            v2_facts = RepositoryChangesFactProvider().derive(
                authority=self._verified_runtime_authority,
                execution_request=original_request,
                actor_identity=selected_actor,
            )
            evaluation_request = dict(v2_facts.evaluation_request)
            evaluation_actor = dict(v2_facts.evaluation_actor)
            authority_evidence = {
                **self._verified_runtime_authority.evidence(),
                "runtime_facts": {
                    "provider_key": asdict(v2_facts.provider_key),
                    "facts": deepcopy(dict(v2_facts.facts)),
                    "canonical_hash": v2_facts.canonical_hash,
                },
            }
            self.timing_diagnostics["warm_integrity_and_fact_derivation_ns"] = (
                perf_counter_ns() - warm_started_ns
            )
        result = evaluate_runtime(
            compiled_authority=evaluated_contract,
            execution_request=evaluation_request,
            actor_identity=evaluation_actor,
            continuity_state=continuity_state if continuity_state is not None else self.continuity_state,
            replay_posture=replay_posture if replay_posture is not None else self.replay_posture,
            evidence_posture={
                "approvals": approvals if approvals is not None else self.approvals,
                "execution_context": execution_context if execution_context is not None else self.execution_context,
            },
            evaluation_time=evaluation_time or self.evaluation_time_source(),
            start_sequence=start_sequence,
            _verified_v2_authority=verified_v2,
        )
        if authority_evidence is not None:
            result["authority_evidence"] = deepcopy(authority_evidence)
            result["runtime_facts"] = deepcopy(dict(v2_facts.facts))
            result["runtime_facts_hash"] = v2_facts.canonical_hash
        validate_guard_enforcement_outcome(result["enforcement_outcome"])
        if save and self.store is not None:
            saved_inputs = {
                "compiled_authority": deepcopy(evaluated_contract),
                "execution_request": original_request,
                "runtime_evidence": result["runtime_evidence"],
            }
            if authority_evidence is not None:
                saved_inputs.update(
                    {
                        "evaluated_execution_request": deepcopy(evaluation_request),
                        "authority_evidence": deepcopy(authority_evidence),
                        "runtime_facts": deepcopy(dict(v2_facts.facts)),
                    }
                )
            saved_record = self.store.save_evaluation(
                inputs=saved_inputs,
                evaluation=result,
            )
            result["run_id"] = saved_record["run_id"]
            if self.cloud_preservation_client is not None:
                replay_result = self.store.replay(saved_record["run_id"])
                preservation_result = self.cloud_preservation_client.preserve(
                    _build_cloud_preservation_package(
                        saved_record=saved_record,
                        replay_result=replay_result,
                    )
                )
                result["cloud_preservation"] = asdict(preservation_result)
                if preservation_result.ok:
                    updated_record = self.store.append_cloud_preservation(
                        saved_record["run_id"],
                        _cloud_preservation_metadata(result["cloud_preservation"]),
                        record_hash=saved_record["record_hash"],
                    )
                    saved_record["cloud_preservation"] = updated_record["cloud_preservation"]
        if verified_v2:
            if result["status"] == "admissible":
                self._record_execution_evidence(
                    result,
                    callback_invoked=None,
                    callback_completed=None,
                    execution_status="incomplete",
                    mutation_status="unknown",
                    mutation_executed=None,
                )
            else:
                self._record_execution_evidence(
                    result,
                    callback_invoked=False,
                    callback_completed=False,
                    execution_status="not_run",
                    mutation_status="not_performed",
                    mutation_executed=False,
                )
        return result

    def enforce(self, execution_request: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        evaluation = self.evaluate(execution_request, **kwargs)
        status = evaluation["status"]
        if status == "blocked":
            raise GuardExecutionBlocked(_enforcement_message(evaluation), evaluation=evaluation)
        if status == "escalated":
            raise GuardExecutionEscalated(_enforcement_message(evaluation), evaluation=evaluation)
        return evaluation

    def execute(
        self,
        fn: Callable[..., Any],
        *,
        execution_request: dict[str, Any],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        raise_on_block: bool = True,
        **evaluation_kwargs: Any,
    ) -> dict[str, Any]:
        try:
            evaluation = self.enforce(execution_request, **evaluation_kwargs)
        except GuardExecutionError as exc:
            self._record_execution_evidence(
                exc.evaluation,
                callback_invoked=False,
                callback_completed=False,
                execution_status="not_run",
                mutation_status="not_performed",
                mutation_executed=False,
            )
            attestation = self._attest_execution_result(
                exc.evaluation,
                execution_request=execution_request,
                executed=False,
            )
            if attestation is not None:
                exc.evaluation["cloud_runtime_attestation"] = attestation
            if raise_on_block:
                raise
            return {
                "executed": False,
                "value": None,
                "evaluation": exc.evaluation,
                "outcome": exc.outcome,
                "cloud_preservation": exc.evaluation.get("cloud_preservation"),
                "cloud_runtime_attestation": attestation,
            }

        self._record_execution_evidence(
            evaluation,
            callback_invoked=True,
            callback_completed=False,
            execution_status="incomplete",
            mutation_status="unknown",
            mutation_executed=None,
        )
        try:
            value = fn(*(args or ()), **(kwargs or {}))
        except Exception as exc:
            self._record_execution_evidence(
                evaluation,
                callback_invoked=True,
                callback_completed=False,
                execution_status="failed",
                mutation_status="unknown",
                mutation_executed=None,
            )
            attestation = self._attest_execution_result(
                evaluation,
                execution_request=execution_request,
                executed=None,
                error=exc,
            )
            if attestation is not None:
                evaluation["cloud_runtime_attestation"] = attestation
            raise
        self._record_execution_evidence(
            evaluation,
            callback_invoked=True,
            callback_completed=True,
            execution_status="succeeded",
            mutation_status="executed",
            mutation_executed=True,
        )
        attestation = self._attest_execution_result(
            evaluation,
            execution_request=execution_request,
            executed=True,
        )
        if attestation is not None:
            evaluation["cloud_runtime_attestation"] = attestation
        return {
            "executed": True,
            "value": value,
            "evaluation": evaluation,
            "outcome": evaluation["enforcement_outcome"],
            "cloud_preservation": evaluation.get("cloud_preservation"),
            "cloud_runtime_attestation": attestation,
        }

    def _record_execution_evidence(
        self,
        evaluation: dict[str, Any],
        *,
        callback_invoked: bool | None,
        callback_completed: bool | None,
        execution_status: str,
        mutation_status: str,
        mutation_executed: bool | None,
    ) -> dict[str, Any] | None:
        authority_evidence = evaluation.get("authority_evidence")
        if not isinstance(authority_evidence, dict):
            return None
        run_id = evaluation.get("run_id") or evaluation["enforcement_outcome"]["outcome_id"]
        receipt_hash = None
        if self.store is not None and evaluation.get("run_id"):
            try:
                receipt_hash = self.store.load_run(evaluation["run_id"])["receipt"]["receipt_hash"]
            except (FileNotFoundError, KeyError, TypeError):
                receipt_hash = None
        attestation = build_execution_attestation(
            run_id=run_id,
            guard_receipt_hash=receipt_hash,
            authority_evidence_hash=stable_hash(authority_evidence),
            runtime_facts_hash=evaluation["runtime_facts_hash"],
            decision=evaluation["status"],
            callback_invoked=callback_invoked,
            callback_completed=callback_completed,
            execution_status=execution_status,
            mutation_status=mutation_status,
            mutation_executed=mutation_executed,
        )
        evaluation["execution_attestation"] = attestation
        if self.store is not None and evaluation.get("run_id"):
            self.store.export_execution_attestation(attestation)
        return attestation

    def _attest_execution_result(
        self,
        evaluation: dict[str, Any],
        *,
        execution_request: dict[str, Any],
        executed: bool | None,
        error: Exception | None = None,
    ) -> dict[str, Any] | None:
        if self.cloud_runtime_client is None:
            return None
        event_id = evaluation.get("run_id")
        if not isinstance(event_id, str) or not event_id:
            return None

        action = str(execution_request.get("action") or "protected callback")
        status = evaluation["status"]
        if error is not None:
            runtime_decision = "ALLOWED"
            execution_status = "failed"
            mutation_executed = None
            summary = f"{action} callback raised {type(error).__name__}."
        elif executed:
            runtime_decision = "ALLOWED"
            execution_status = "succeeded"
            mutation_executed = True
            summary = f"{action} callback completed exactly once."
        else:
            runtime_decision = "BLOCKED" if status == "blocked" else "ESCALATED"
            execution_status = "blocked" if status == "blocked" else "not_executed"
            mutation_executed = False
            summary = f"{action} callback did not run."

        try:
            result = self.cloud_runtime_client.attest(
                event_id=event_id,
                compiled_contract_hash=self.compiled_authority["contract_hash"],
                runtime_decision=runtime_decision,
                execution_status=execution_status,
                execution_result_summary=summary,
                mutation_executed=mutation_executed,
            )
        except Exception:
            return {
                "ok": False,
                "response": None,
                "status_code": None,
                "error": "Cloud runtime attestation failed",
                "error_type": "client_error",
            }
        return asdict(result)

    def decorator(
        self,
        request_builder: Callable[..., dict[str, Any]],
        **evaluation_kwargs: Any,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                execution_request = request_builder(*args, **kwargs)
                result = self.execute(
                    fn,
                    execution_request=execution_request,
                    args=args,
                    kwargs=kwargs,
                    **evaluation_kwargs,
                )
                return result["value"]

            return wrapped

        return decorate


def _enforcement_message(evaluation: dict[str, Any]) -> str:
    return f"Execution {evaluation['status']}: {evaluation['rationale']}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_cloud_preservation_package(
    *,
    saved_record: dict[str, Any],
    replay_result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": GUARD_CLOUD_PRESERVATION_PACKAGE_V1,
        "run_id": saved_record["run_id"],
        "saved_evaluation": saved_record,
        "receipt": saved_record["receipt"],
        "artifact_manifest": saved_record["artifact_manifest"],
        "replay_result": replay_result,
    }


def _cloud_preservation_metadata(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "preserved",
        "package_id": result.get("package_id"),
        "receipt_id": result.get("receipt_id"),
        "sha256": result.get("sha256"),
        "timestamp": result.get("timestamp"),
        "receipt": result.get("receipt"),
    }

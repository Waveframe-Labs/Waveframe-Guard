from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
from functools import wraps
from typing import Any, Callable

from guard.runtime import evaluate_runtime
from guard.runtime.builders import validate_guard_enforcement_outcome
from waveframe_guard.cloud import CloudPreservationClient


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
        actor_identity: dict[str, Any],
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time_source: Callable[[], str] | None = None,
        store: Any | None = None,
        cloud_preservation_client: CloudPreservationClient | None = None,
    ):
        self.compiled_authority = compiled_authority
        self.actor_identity = actor_identity
        self.approvals = approvals or []
        self.continuity_state = continuity_state or {}
        self.replay_posture = replay_posture or {}
        self.execution_context = execution_context or {"surface": "sdk"}
        self.evaluation_time_source = evaluation_time_source or _utc_now
        self.store = store
        self.cloud_preservation_client = cloud_preservation_client

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
        result = evaluate_runtime(
            compiled_authority=self.compiled_authority,
            execution_request=execution_request,
            actor_identity=actor_identity or self.actor_identity,
            continuity_state=continuity_state if continuity_state is not None else self.continuity_state,
            replay_posture=replay_posture if replay_posture is not None else self.replay_posture,
            evidence_posture={
                "approvals": approvals if approvals is not None else self.approvals,
                "execution_context": execution_context if execution_context is not None else self.execution_context,
            },
            evaluation_time=evaluation_time or self.evaluation_time_source(),
            start_sequence=start_sequence,
        )
        validate_guard_enforcement_outcome(result["enforcement_outcome"])
        if save and self.store is not None:
            saved_record = self.store.save_evaluation(
                inputs={
                    "compiled_authority": self.compiled_authority,
                    "execution_request": execution_request,
                    "runtime_evidence": result["runtime_evidence"],
                },
                evaluation=result,
            )
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
                    )
                    saved_record["cloud_preservation"] = updated_record["cloud_preservation"]
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
            if raise_on_block:
                raise
            return {
                "executed": False,
                "value": None,
                "evaluation": exc.evaluation,
                "outcome": exc.outcome,
                "cloud_preservation": exc.evaluation.get("cloud_preservation"),
            }

        value = fn(*(args or ()), **(kwargs or {}))
        return {
            "executed": True,
            "value": value,
            "evaluation": evaluation,
            "outcome": evaluation["enforcement_outcome"],
            "cloud_preservation": evaluation.get("cloud_preservation"),
        }

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

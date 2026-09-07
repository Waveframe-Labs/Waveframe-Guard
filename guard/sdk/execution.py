from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import asdict
from copy import deepcopy
from functools import wraps
from contextlib import ExitStack
from uuid import uuid4
from time import perf_counter_ns
from typing import Any, Callable

from guard.runtime import evaluate_runtime
from guard.runtime.builders import validate_guard_enforcement_outcome
from guard.runtime.identity import stable_hash
from waveframe_guard.cloud import CloudPreservationClient, CloudRuntimeClient
from waveframe_guard.authority.runtime_facts import (
    RepositoryChangesFactProvider,
    VerifiedRuntimeAuthority,
    resolve_target_domain_v1,
)
from waveframe_guard.authority.types import LoadedAuthority
from waveframe_guard.authority.exceptions import AuthorityVerificationError
from .local_persistence import build_execution_attestation
from .repository_boundary import RepositoryBoundaryError, RepositoryWorkspace, validate_repository_request
from .repository_evidence import build_repository_attestation
from .target_binding import TargetBinding, reject_binding_override


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
        repository_workspace: RepositoryWorkspace | None = None,
        target_domain: str | None = None,
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
        self._repository_workspace = repository_workspace
        self._target_domain = target_domain
        self._verified_runtime_authority = None
        self._verified_target_domain = None
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
            self._verified_target_domain = resolve_target_domain_v1(self._verified_runtime_authority)
            self.timing_diagnostics["cold_load_validation_ns"] = (
                self._verified_runtime_authority.cold_validation_duration_ns
            )
        self._activation_contract_hash = stable_hash(self.compiled_authority)
        self._activation_configuration = (repository_workspace, target_domain)
        scoped = repository_workspace is not None or self._verified_target_domain is not None or "target_requirements" in self.compiled_authority
        domain = self._verified_target_domain or (
            "repository_path" if repository_workspace is not None or target_domain != "literal" else "literal"
        )
        self._target_binding = TargetBinding(
            target_domain=domain,
            workspace_binding_id=repository_workspace.binding_id if repository_workspace else None,
            adapter_version="guard.repository-file.v2" if domain == "repository_path" else "guard.literal-target.v1",
            assurance_class=repository_workspace.assurance_class if repository_workspace else (
                "unbound" if domain == "repository_path" else "literal-comparison.v1"
            ),
            authority_contract_hash=self._activation_contract_hash,
            domain_resolver="guard.target-domain-resolver.v1" if self._verified_target_domain else "trusted-sdk-configuration.v1",
        ) if scoped else None
        self._activation_binding = self._target_binding
        self.actor_identity = actor_identity
        self.approvals = approvals or []
        self.continuity_state = continuity_state or {}
        self.replay_posture = replay_posture or {}
        self.execution_context = execution_context or {"surface": "sdk"}
        self.evaluation_time_source = evaluation_time_source or _utc_now
        self.store = store
        self.cloud_preservation_client = cloud_preservation_client
        self.cloud_runtime_client = cloud_runtime_client

    def _repository_required(self):
        self._check_target_binding()
        return self._target_binding is not None and self._target_binding.target_domain == "repository_path"

    @property
    def target_binding(self):
        """Frozen trusted provenance; not cached with the normative authority."""
        return self._target_binding

    def _check_target_binding(self):
        if self._target_binding != self._activation_binding or (
            self._repository_workspace, self._target_domain
        ) != self._activation_configuration:
            raise RepositoryBoundaryError("target binding changed after boundary activation")
        if self._target_binding is not None:
            if self._verified_runtime_authority is not None:
                self._verified_runtime_authority.verify_candidate_contract(self.compiled_authority)
                if resolve_target_domain_v1(self._verified_runtime_authority) != self._verified_target_domain:
                    raise RepositoryBoundaryError("verified target domain changed after activation")
            elif stable_hash(self.compiled_authority) != self._activation_contract_hash:
                raise RepositoryBoundaryError("target-scoped authority changed after boundary activation")
            if self._repository_workspace is not None and (
                self._repository_workspace.binding_id != self._target_binding.workspace_binding_id
                or self._repository_workspace.assurance_class != self._target_binding.assurance_class
            ):
                raise RepositoryBoundaryError("protected workspace binding was substituted")

    def _require_workspace(self):
        self._check_target_binding()
        if self._repository_workspace is None:
            raise RepositoryBoundaryError(
                "repository authority requires repository_root=<absolute protected workspace> "
                "and repository_tool(); untyped v1 non-repository targets must explicitly "
                "select target_domain='literal'"
            )
        return self._repository_workspace

    def evaluate(self, execution_request: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        if self._repository_required():
            validate_repository_request(execution_request)
        request = deepcopy(execution_request)
        if self._repository_required():
            with self._require_workspace().bind(
                request.get("target"), requirements=self.compiled_authority.get("target_requirements")
            ) as target:
                request["target"] = target.relative_path
                result = self._evaluate(request, **kwargs)
                target._validate()
                return result
        return self._evaluate(request, **kwargs)

    def _evaluate(
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
        self._check_target_binding()
        if self._repository_required():
            validate_repository_request(execution_request)
        original_request = deepcopy(execution_request)
        selected_context = deepcopy(execution_context if execution_context is not None else self.execution_context)
        if self._target_binding is not None:
            reject_binding_override(original_request)
            reject_binding_override(selected_context)
            selected_context["target_binding"] = self._target_binding.evidence()
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
                "execution_context": selected_context,
            },
            evaluation_time=evaluation_time or self.evaluation_time_source(),
            start_sequence=start_sequence,
            _verified_v2_authority=verified_v2,
        )
        if authority_evidence is not None:
            result["authority_evidence"] = deepcopy(authority_evidence)
            result["runtime_facts"] = deepcopy(dict(v2_facts.facts))
            result["runtime_facts_hash"] = v2_facts.canonical_hash
        if self._target_binding is not None:
            result["target_binding"] = self._target_binding.evidence()
            result["target_binding_hash"] = self._target_binding.canonical_hash
        if self._repository_required():
            result["accepted_execution_request"] = deepcopy(original_request)
            result["cloud_preservation_scope"] = "decision_only_not_final_execution"
        validate_guard_enforcement_outcome(result["enforcement_outcome"])
        if save and self.store is not None:
            self._persist_evaluation(result, original_request)
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

    def _persist_evaluation(self, result, original_request):
        saved_inputs = {
            "compiled_authority": deepcopy(self.compiled_authority),
            "execution_request": original_request,
            "runtime_evidence": result["runtime_evidence"],
        }
        if self._target_binding is not None:
            saved_inputs["target_binding"] = self._target_binding.evidence()
        if "authority_evidence" in result:
            saved_inputs.update(
                {
                    "evaluated_execution_request": deepcopy(original_request),
                    "authority_evidence": deepcopy(result["authority_evidence"]),
                    "runtime_facts": deepcopy(result["runtime_facts"]),
                }
            )
        decision = deepcopy(result)
        decision.pop("execution_attestation", None)  # Preservation is decision-only.
        saved_record = self.store.save_evaluation(
            inputs=saved_inputs,
            evaluation=decision,
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

    def enforce(self, execution_request: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        evaluation = self.evaluate(execution_request, **kwargs)
        status = evaluation["status"]
        if status == "blocked":
            raise GuardExecutionBlocked(_enforcement_message(evaluation), evaluation=evaluation)
        if status == "escalated":
            raise GuardExecutionEscalated(_enforcement_message(evaluation), evaluation=evaluation)
        return evaluation

    def execute(
        self, fn: Callable[..., Any], *, execution_request: dict[str, Any], **kwargs: Any,
    ) -> dict[str, Any]:
        if self._repository_required():
            validate_repository_request(execution_request)
            try:
                evaluation = self.evaluate(execution_request, save=False)
            except RepositoryBoundaryError as exc:
                self._record_repository_refusal(exc, execution_request, save=kwargs.get("save", True))
                raise
            if evaluation["status"] != "admissible":
                if kwargs.get("save", True) and self.store is not None:
                    self._persist_evaluation(evaluation, execution_request)
                return self._execute(fn, execution_request=execution_request, _evaluation=evaluation,
                                     raise_on_block=kwargs.get("raise_on_block", True))
            error = RepositoryBoundaryError(
                "repository mutation requires repository_tool() or execute_repository(); "
                "generic tool/protect/execute callbacks cannot bind the mutation target"
            )
            self._record_repository_refusal(error, execution_request, evaluation, save=kwargs.get("save", True))
            raise error
        return self._execute(fn, execution_request=execution_request, **kwargs)

    def execute_repository(
        self, fn: Callable[..., Any], *, execution_request: dict[str, Any],
        raise_on_block: bool = True, **evaluation_kwargs: Any,
    ) -> dict[str, Any]:
        # Malformed/unclosed requests are not admitted executions: no artifacts,
        # authority comparison, filesystem access or preservation is permitted.
        validate_repository_request(execution_request)
        request = deepcopy(execution_request)
        workspace = self._require_workspace()
        # Evaluate before acquiring a writable capability so a denial never opens
        # a mutation handle, and unsupported forms cannot hide authority errors.
        preflight_kwargs = {**evaluation_kwargs, "save": False}
        try:
            evaluation = self.evaluate(request, **preflight_kwargs)
        except RepositoryBoundaryError as exc:
            self._record_repository_refusal(exc, request, save=evaluation_kwargs.get("save", True))
            raise
        if evaluation["status"] != "admissible":
            evaluation = self.evaluate(request, **evaluation_kwargs)
            return self._execute(fn, execution_request=request, raise_on_block=raise_on_block,
                                 _evaluation=evaluation)
        with ExitStack() as stack:
            try:
                target = stack.enter_context(workspace.bind(
                    request.get("target"), mutation=True,
                    requirements=self.compiled_authority.get("target_requirements"),
                ))
            except RepositoryBoundaryError as exc:
                self._record_repository_refusal(exc, request, evaluation,
                                                save=evaluation_kwargs.get("save", True))
                raise
            # The opened descriptor is the mutation target. Windows also holds
            # namespace locks; Linux relies on the trusted in-process adapter.
            locked = self._evaluate(request, **evaluation_kwargs)

            def invoke():
                target._active = True
                callback_completed = False
                try:
                    value = fn(target)
                    callback_completed = True
                    return value
                finally:
                    target._active = False
                    try:
                        target._validate()  # Failure here cannot undo written bytes.
                    except RepositoryBoundaryError as exc:
                        exc.callback_completed = callback_completed
                        exc.validation_phase = "post_callback"
                        raise

            def before_callback():
                self._check_target_binding()
                target._validate()

            return self._execute(invoke, execution_request=request, raise_on_block=raise_on_block,
                                 _evaluation=locked, _before_callback=before_callback)

    def _record_repository_refusal(self, error, request, evaluation=None, *, save=True):
        if evaluation is None:
            evaluation = {
                "status": "not_evaluated", "accepted_execution_request": deepcopy(request),
                "target_binding": self._target_binding.evidence(),
                "target_binding_hash": self._target_binding.canonical_hash,
            }
        elif save and self.store is not None and not evaluation.get("run_id"):
            self._persist_evaluation(evaluation, request)
        self._record_execution_evidence(
            evaluation, callback_invoked=False, callback_completed=False,
            execution_status="not_run", mutation_status="not_performed", mutation_executed=False,
            persist=save,
        )
        error.evaluation = evaluation

    def _execute(
        self,
        fn: Callable[..., Any],
        *,
        execution_request: dict[str, Any],
        args: tuple[Any, ...] | None = None,
        kwargs: dict[str, Any] | None = None,
        raise_on_block: bool = True,
        _evaluation: dict[str, Any] | None = None,
        _before_callback: Callable[[], None] | None = None,
        **evaluation_kwargs: Any,
    ) -> dict[str, Any]:
        try:
            evaluation = _evaluation if _evaluation is not None else self.enforce(execution_request, **evaluation_kwargs)
            if evaluation["status"] == "blocked":
                raise GuardExecutionBlocked(_enforcement_message(evaluation), evaluation=evaluation)
            if evaluation["status"] == "escalated":
                raise GuardExecutionEscalated(_enforcement_message(evaluation), evaluation=evaluation)
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

        if _before_callback is not None:
            try:
                _before_callback()
            except Exception as exc:
                self._record_execution_evidence(
                    evaluation, callback_invoked=False, callback_completed=False,
                    execution_status="not_run", mutation_status="not_performed", mutation_executed=False,
                )
                if isinstance(exc, RepositoryBoundaryError):
                    exc.evaluation = evaluation
                raise
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
                callback_completed=getattr(exc, "callback_completed", False),
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
            if isinstance(exc, RepositoryBoundaryError):
                exc.evaluation = evaluation
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
        persist: bool = True,
    ) -> dict[str, Any] | None:
        authority_evidence = evaluation.get("authority_evidence")
        repository = evaluation.get("target_binding", {}).get("target_domain") == "repository_path"
        if not repository and not isinstance(authority_evidence, dict):
            return None
        run_id = evaluation.get("run_id") or evaluation.get("enforcement_outcome", {}).get("outcome_id") or "guard_attempt_" + uuid4().hex
        receipt_hash = None
        if self.store is not None and evaluation.get("run_id"):
            try:
                receipt_hash = self.store.load_run(evaluation["run_id"])["receipt"]["receipt_hash"]
            except (FileNotFoundError, KeyError, TypeError):
                if repository:
                    from .local_persistence import GuardArtifactError

                    raise GuardArtifactError("repository execution decision receipt is unavailable") from None
                receipt_hash = None
        state = dict(
            callback_invoked=callback_invoked, callback_completed=callback_completed,
            execution_status=execution_status, mutation_status=mutation_status,
            mutation_executed=mutation_executed,
        )
        if repository:
            attestation = build_repository_attestation(
                run_id=run_id, receipt_hash=receipt_hash, contract=self.compiled_authority,
                evaluation=evaluation, **state,
            )
        else:
            attestation = build_execution_attestation(
                run_id=run_id, guard_receipt_hash=receipt_hash,
                authority_evidence_hash=stable_hash(authority_evidence),
                runtime_facts_hash=evaluation["runtime_facts_hash"],
                decision=evaluation["status"], target_binding=evaluation.get("target_binding"), **state,
            )
        evaluation["execution_attestation"] = attestation
        if persist and self.store is not None and (evaluation.get("run_id") or evaluation["status"] == "not_evaluated"):
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

from __future__ import annotations

from functools import wraps
from pathlib import Path
from typing import Any, Callable

from guard.adapters import NORMALIZED_EXECUTION_REQUEST_V1
from waveframe_guard.authority import AuthorityCache, AuthorityResolver
from waveframe_guard.cloud import CloudPreservationClient

from .authority_source import AuthoritySource
from .execution import GuardRuntimeBoundary
from .local_persistence import LocalEvaluationStore


class Guard:
    """Product-facing Guard SDK facade for local runtime interception."""

    def __init__(
        self,
        *,
        workspace: str | Path,
        authority: str | None = None,
        authority_resolver: AuthorityResolver | None = None,
        authority_cache: AuthorityCache | None = None,
        contract: dict[str, Any] | None = None,
        authorities: dict[str, dict[str, Any]] | None = None,
        authority_loader: Callable[[str], dict[str, Any]] | None = None,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time_source: Callable[[], str] | None = None,
        preserve_to: str | None = None,
    ):
        self.workspace = Path(workspace)
        self.store = LocalEvaluationStore(self.workspace)
        authority_source = AuthoritySource.from_inputs(
            authority=authority,
            authority_resolver=authority_resolver,
            authority_cache=authority_cache,
            contract=contract,
            authorities=authorities,
            authority_loader=authority_loader,
        )
        self.authorities = authority_source.authorities
        self.authority_loader = authority_source.authority_loader
        self.default_authority_ref = authority_source.default_authority_ref
        self.actor_identity = actor_identity or {"id": "unknown", "type": "unknown", "role": "unknown"}
        self.approvals = approvals or []
        self.continuity_state = continuity_state or {}
        self.replay_posture = replay_posture or {}
        self.execution_context = execution_context or {"surface": "guard_sdk"}
        self.evaluation_time_source = evaluation_time_source
        self.preserve_to = preserve_to
        self.cloud_preservation_client = (
            CloudPreservationClient(preserve_to)
            if preserve_to is not None
            else None
        )

    @classmethod
    def local(
        cls,
        *,
        workspace: str | Path = ".guard-local",
        authority: str | None = None,
        authority_resolver: AuthorityResolver | None = None,
        authority_cache: AuthorityCache | None = None,
        contract: dict[str, Any] | None = None,
        authorities: dict[str, dict[str, Any]] | None = None,
        authority_loader: Callable[[str], dict[str, Any]] | None = None,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time_source: Callable[[], str] | None = None,
        preserve_to: str | None = None,
    ) -> "Guard":
        return cls(
            workspace=workspace,
            authority=authority,
            authority_resolver=authority_resolver,
            authority_cache=authority_cache,
            contract=contract,
            authorities=authorities,
            authority_loader=authority_loader,
            actor_identity=actor_identity,
            approvals=approvals,
            continuity_state=continuity_state,
            replay_posture=replay_posture,
            execution_context=execution_context,
            evaluation_time_source=evaluation_time_source,
            preserve_to=preserve_to,
        )

    def protect(
        self,
        *,
        authority: str | None = None,
        request_builder: Callable[..., dict[str, Any]] | None = None,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        raise_on_block: bool = True,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        boundary = self.boundary_for(
            self._resolve_authority_ref(authority),
            actor_identity=actor_identity,
            approvals=approvals,
            continuity_state=continuity_state,
            replay_posture=replay_posture,
            execution_context=execution_context,
        )

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                execution_request = (
                    request_builder(*args, **kwargs)
                    if request_builder is not None
                    else _normalized_request_from_call(args, kwargs)
                )
                result = boundary.execute(
                    fn,
                    execution_request=execution_request,
                    args=args,
                    kwargs=kwargs,
                    raise_on_block=raise_on_block,
                )
                return result["value"] if result["executed"] else result

            return wrapped

        return decorate

    def boundary_for(
        self,
        authority: str | None = None,
        *,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
    ) -> GuardRuntimeBoundary:
        return GuardRuntimeBoundary(
            compiled_authority=self.resolve_authority(self._resolve_authority_ref(authority)),
            actor_identity=actor_identity or self.actor_identity,
            approvals=approvals if approvals is not None else self.approvals,
            continuity_state=continuity_state if continuity_state is not None else self.continuity_state,
            replay_posture=replay_posture if replay_posture is not None else self.replay_posture,
            execution_context=execution_context if execution_context is not None else self.execution_context,
            evaluation_time_source=self.evaluation_time_source,
            store=self.store,
            cloud_preservation_client=self.cloud_preservation_client,
        )

    def resolve_authority(self, authority: str) -> dict[str, Any]:
        if authority in self.authorities:
            return self.authorities[authority]
        if self.authority_loader is not None:
            return self.authority_loader(authority)
        raise KeyError(f"compiled authority not available for Guard SDK authority reference: {authority}")

    def _resolve_authority_ref(self, authority: str | None) -> str:
        resolved = authority or self.default_authority_ref
        if resolved is None:
            raise ValueError("Missing authority; pass authority=... to Guard.local(), protect(), or boundary_for()")
        return resolved


def _normalized_request_from_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    candidate = kwargs.get("execution_request")
    if candidate is None and args:
        candidate = args[0]
    if not isinstance(candidate, dict) or candidate.get("schema_version") != NORMALIZED_EXECUTION_REQUEST_V1:
        raise ValueError(
            "Guard SDK protect() requires a normalized_execution_request.v1 payload "
            "or an explicit request_builder adapter"
        )
    return candidate

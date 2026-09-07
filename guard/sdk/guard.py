from __future__ import annotations

import os
from functools import wraps
from importlib.metadata import PackageNotFoundError, version
from inspect import BoundArguments, signature
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from guard.adapters import NORMALIZED_EXECUTION_REQUEST_V1
from waveframe_guard.authority import AuthorityCache, AuthorityResolver, MemoryAuthorityCache
from waveframe_guard.cloud import (
    CloudAuthorityClient,
    CloudAuthorityResolver,
    CloudPreservationClient,
    CloudPublicationUnavailable,
    CloudRuntimeClient,
)
from waveframe_guard.cloud.client import (
    DEFAULT_PRESERVATION_TIMEOUT_SECONDS,
    _preservation_timeout_seconds,
)

from .authority_source import AuthoritySource
from .execution import GuardRuntimeBoundary
from .local_persistence import LocalEvaluationStore
from .repository_boundary import RepositoryWorkspace


class Guard:
    """Product-facing Guard SDK facade for local runtime interception."""

    def __init__(
        self,
        *,
        workspace: str | Path,
        repository_root: str | Path | None = None,
        target_domain: str | None = None,
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
        preservation_timeout_seconds: float = DEFAULT_PRESERVATION_TIMEOUT_SECONDS,
        cloud_organization_id: str | None = None,
        cloud_api_key: str | None = None,
        cloud_runtime_client: CloudRuntimeClient | None = None,
    ):
        self.workspace = Path(workspace)
        if target_domain not in {None, "literal"} or (repository_root is not None and target_domain is not None):
            raise ValueError("use repository_root for repository paths or target_domain='literal' for other targets")
        self._repository_workspace = RepositoryWorkspace(repository_root) if repository_root is not None else None
        self._target_domain = target_domain
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
        self.authority_bindings = authority_source.authority_bindings
        self.authority_cache = authority_cache
        self.authority_loader = authority_source.authority_loader
        self.default_authority_ref = authority_source.default_authority_ref
        self.actor_identity = actor_identity or {"id": "unknown", "type": "unknown", "role": "unknown"}
        self.approvals = approvals or []
        self.continuity_state = continuity_state or {}
        self.replay_posture = replay_posture or {}
        self.execution_context = execution_context or {"surface": "guard_sdk"}
        self.evaluation_time_source = evaluation_time_source
        self.preserve_to = preserve_to
        self.preservation_timeout_seconds = _preservation_timeout_seconds(
            preservation_timeout_seconds
        )
        self.cloud_preservation_client = (
            CloudPreservationClient(
                preserve_to,
                timeout_seconds=self.preservation_timeout_seconds,
                organization_id=_cloud_setting(
                    cloud_organization_id,
                    "WAVEFRAME_CLOUD_ORGANIZATION_ID",
                ),
                api_key=_cloud_setting(cloud_api_key, "WAVEFRAME_CLOUD_API_KEY"),
            )
            if preserve_to is not None
            else None
        )
        self.cloud_runtime_client = cloud_runtime_client
        self.runtime_connection = None

    @classmethod
    def local(
        cls,
        *,
        workspace: str | Path = ".guard-local",
        repository_root: str | Path | None = None,
        target_domain: str | None = None,
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
        preservation_timeout_seconds: float = DEFAULT_PRESERVATION_TIMEOUT_SECONDS,
        cloud_organization_id: str | None = None,
        cloud_api_key: str | None = None,
    ) -> "Guard":
        return cls(
            workspace=workspace,
            repository_root=repository_root,
            target_domain=target_domain,
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
            preservation_timeout_seconds=preservation_timeout_seconds,
            cloud_organization_id=cloud_organization_id,
            cloud_api_key=cloud_api_key,
        )

    @classmethod
    def cloud(
        cls,
        *,
        authority: str,
        workspace: str | Path = ".guard-local",
        repository_root: str | Path | None = None,
        target_domain: str | None = None,
        cloud_url: str | None = None,
        cloud_organization_id: str | None = None,
        cloud_api_key: str | None = None,
        runtime_credential: str | None = None,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        evaluation_time_source: Callable[[], str] | None = None,
        runtime_id: str | None = None,
        environment: str | None = None,
        preservation_timeout_seconds: float = DEFAULT_PRESERVATION_TIMEOUT_SECONDS,
    ) -> "Guard":
        """Connect Guard to hosted Cloud without a repository checkout.

        Cloud supplies the published compiled authority and preserves evidence.
        Guard still evaluates locally and executes the protected callable only
        after an admissible decision.
        """

        resolved_url = _required_cloud_setting(cloud_url, "WAVEFRAME_CLOUD_URL")
        resolved_organization_id = _required_cloud_setting(
            cloud_organization_id,
            "WAVEFRAME_CLOUD_ORGANIZATION_ID",
        )
        if runtime_credential is not None and cloud_api_key is not None:
            if runtime_credential != cloud_api_key:
                raise ValueError("runtime_credential and cloud_api_key must not conflict")
        resolved_api_key = _required_cloud_setting(
            runtime_credential if runtime_credential is not None else cloud_api_key,
            "WAVEFRAME_CLOUD_API_KEY",
        )
        resolved_runtime_id = runtime_id or (actor_identity or {}).get("id")
        if not isinstance(resolved_runtime_id, str) or not resolved_runtime_id.strip():
            raise ValueError(
                "Guard.cloud() requires runtime_id or actor_identity.id so Cloud can identify the runtime"
            )
        resolved_environment = _cloud_setting(
            environment,
            "WAVEFRAME_RUNTIME_ENVIRONMENT",
        ) or "development"
        authority_client = CloudAuthorityClient(
            resolved_url,
            organization_id=resolved_organization_id,
            api_key=resolved_api_key,
        )
        authority_cache = MemoryAuthorityCache()
        publication_resolver = CloudAuthorityResolver(authority_client)
        try:
            guard = cls(
                workspace=workspace,
                repository_root=repository_root,
                target_domain=target_domain,
                authority=authority,
                authority_resolver=publication_resolver,
                authority_cache=authority_cache,
                actor_identity=actor_identity,
                approvals=approvals,
                continuity_state=continuity_state,
                replay_posture=replay_posture,
                execution_context=execution_context,
                evaluation_time_source=evaluation_time_source,
                preserve_to=resolved_url,
                preservation_timeout_seconds=preservation_timeout_seconds,
                cloud_organization_id=resolved_organization_id,
                cloud_api_key=resolved_api_key,
            )
        except CloudPublicationUnavailable:
            compiled_authority = authority_client.fetch(authority)
            guard = cls(
                workspace=workspace,
                repository_root=repository_root,
                target_domain=target_domain,
                authority=authority,
                authority_loader=lambda requested_ref: compiled_authority,
                actor_identity=actor_identity,
                approvals=approvals,
                continuity_state=continuity_state,
                replay_posture=replay_posture,
                execution_context=execution_context,
                evaluation_time_source=evaluation_time_source,
                preserve_to=resolved_url,
                preservation_timeout_seconds=preservation_timeout_seconds,
                cloud_organization_id=resolved_organization_id,
                cloud_api_key=resolved_api_key,
            )
        finally:
            publication_resolver.close()
        runtime_client = CloudRuntimeClient(
            resolved_url,
            organization_id=resolved_organization_id,
            api_key=resolved_api_key,
            runtime_id=resolved_runtime_id,
            environment=resolved_environment,
            authority_ref=authority,
            runtime_version=f"guard-{_guard_version()}",
        )
        guard.cloud_runtime_client = runtime_client
        guard.runtime_connection = runtime_client.connect()
        return guard

    def heartbeat(self):
        """Report that this Guard runtime remains online without affecting enforcement."""

        if self.cloud_runtime_client is None:
            return None
        return self.cloud_runtime_client.heartbeat()

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

    def tool(
        self,
        *,
        authority: str | None = None,
        action: str | None = None,
        target: str | Callable[..., Any] | None = None,
        include_arguments: tuple[str, ...] | list[str] | None = None,
        artifacts: Callable[..., list[dict[str, Any]]] | None = None,
        request_id: Callable[..., str] | None = None,
        agent: dict[str, Any] | None = None,
        actor_identity: dict[str, Any] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        continuity_state: dict[str, Any] | None = None,
        replay_posture: dict[str, Any] | None = None,
        execution_context: dict[str, Any] | None = None,
        raise_on_block: bool = True,
        return_result: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Protect an existing agent tool without requiring Guard-shaped arguments.

        ``target`` may name one function argument or be a callable receiving the
        original tool arguments. Function arguments are excluded from preserved
        evidence unless explicitly named by ``include_arguments``. Set
        ``return_result`` to receive Guard's structured execution envelope for
        both allowed and blocked calls; the default preserves the wrapped tool's
        original return value when execution is allowed.
        """

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            fn_signature = signature(fn)
            boundary = self.boundary_for(
                self._resolve_authority_ref(authority),
                actor_identity=actor_identity,
                approvals=approvals,
                continuity_state=continuity_state,
                replay_posture=replay_posture,
                execution_context=_agent_tool_context(
                    self.execution_context,
                    execution_context,
                    agent,
                ),
            )

            @wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                bound = fn_signature.bind(*args, **kwargs)
                bound.apply_defaults()
                execution_request = _tool_execution_request(
                    fn_name=fn.__name__,
                    bound=bound,
                    args=args,
                    kwargs=kwargs,
                    action=action,
                    target=target,
                    include_arguments=include_arguments,
                    artifacts=artifacts,
                    request_id=request_id,
                )
                result = boundary.execute(
                    fn,
                    execution_request=execution_request,
                    args=args,
                    kwargs=kwargs,
                    raise_on_block=raise_on_block,
                )
                if return_result:
                    return result
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
            repository_workspace=self._repository_workspace,
            target_domain=self._target_domain,
            compiled_authority=self.resolve_authority(self._resolve_authority_ref(authority)),
            loaded_authority=self.authority_bindings.get(self._resolve_authority_ref(authority)),
            actor_identity=actor_identity or self.actor_identity,
            approvals=approvals if approvals is not None else self.approvals,
            continuity_state=continuity_state if continuity_state is not None else self.continuity_state,
            replay_posture=replay_posture if replay_posture is not None else self.replay_posture,
            execution_context=execution_context if execution_context is not None else self.execution_context,
            evaluation_time_source=self.evaluation_time_source,
            store=self.store,
            cloud_preservation_client=self.cloud_preservation_client,
            cloud_runtime_client=self.cloud_runtime_client,
        )

    def close(self) -> None:
        """Release the protected repository root handle."""
        if self._repository_workspace is not None:
            self._repository_workspace.close()

    def repository_tool(
        self, *, target: str, action: str = "modify", authority: str | None = None,
        raise_on_block: bool = True, return_result: bool = False,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Supply a RepositoryTarget capability in place of the named path argument.

        Trusted callbacks must use its read_bytes/write_bytes methods. The current
        adapter supports existing regular files on local Windows NTFS only.
        """
        boundary = self.boundary_for(authority)

        def decorate(fn):
            fn_signature = signature(fn)
            if target not in fn_signature.parameters:
                raise ValueError("repository_tool target must name a callback argument")

            @wraps(fn)
            def wrapped(*args, **kwargs):
                bound = fn_signature.bind(*args, **kwargs)
                bound.apply_defaults()
                request = {
                    "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
                    "request_id": f"repository_{uuid4().hex}",
                    "action": action, "target": bound.arguments[target],
                    "arguments": {}, "artifacts": [],
                }

                def invoke(capability):
                    bound.arguments[target] = capability
                    return fn(*bound.args, **bound.kwargs)

                result = boundary.execute_repository(
                    invoke, execution_request=request, raise_on_block=raise_on_block,
                )
                return result if return_result or not result["executed"] else result["value"]

            return wrapped
        return decorate

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


def _cloud_setting(explicit: str | None, environment_name: str) -> str | None:
    return explicit if explicit is not None else os.environ.get(environment_name)


def _required_cloud_setting(explicit: str | None, environment_name: str) -> str:
    value = _cloud_setting(explicit, environment_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing Cloud setting; pass it explicitly or set {environment_name}")
    return value


def _guard_version() -> str:
    try:
        return version("waveframe-guard")
    except PackageNotFoundError:
        return "0.17.0"


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


def _agent_tool_context(
    default_context: dict[str, Any],
    explicit_context: dict[str, Any] | None,
    agent: dict[str, Any] | None,
) -> dict[str, Any]:
    context = dict(default_context)
    if explicit_context is not None:
        context.update(explicit_context)
    context["surface"] = "agent_tool"
    if agent is not None:
        context["agent"] = dict(agent)
    return context


def _tool_execution_request(
    *,
    fn_name: str,
    bound: BoundArguments,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    action: str | None,
    target: str | Callable[..., Any] | None,
    include_arguments: tuple[str, ...] | list[str] | None,
    artifacts: Callable[..., list[dict[str, Any]]] | None,
    request_id: Callable[..., str] | None,
) -> dict[str, Any]:
    selected_arguments: dict[str, Any] = {}
    for name in include_arguments or ():
        if name not in bound.arguments:
            raise ValueError(f"Guard tool include_arguments names unknown argument: {name}")
        selected_arguments[name] = bound.arguments[name]

    resolved_target: Any = fn_name
    if isinstance(target, str):
        if target not in bound.arguments:
            raise ValueError(f"Guard tool target names unknown argument: {target}")
        resolved_target = bound.arguments[target]
    elif target is not None:
        resolved_target = target(*args, **kwargs)

    resolved_artifacts = artifacts(*args, **kwargs) if artifacts is not None else []
    resolved_request_id = request_id(*args, **kwargs) if request_id is not None else f"tool_{uuid4().hex}"
    return {
        "schema_version": NORMALIZED_EXECUTION_REQUEST_V1,
        "request_id": resolved_request_id,
        "action": action or fn_name,
        "target": str(resolved_target),
        "arguments": selected_arguments,
        "artifacts": resolved_artifacts,
    }

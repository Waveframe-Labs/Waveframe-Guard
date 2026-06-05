from __future__ import annotations

from typing import Any, Callable

from .execution import GuardRuntimeBoundary


def python_callable_adapter(
    boundary: GuardRuntimeBoundary,
    fn: Callable[..., Any],
    *,
    execution_request: dict[str, Any],
    args: tuple[Any, ...] | None = None,
    kwargs: dict[str, Any] | None = None,
    raise_on_block: bool = True,
) -> dict[str, Any]:
    return boundary.execute(
        fn,
        execution_request=execution_request,
        args=args,
        kwargs=kwargs,
        raise_on_block=raise_on_block,
        execution_context={"surface": "python_callable"},
    )


def http_middleware_adapter(
    boundary: GuardRuntimeBoundary,
    *,
    request_loader: Callable[[Any], dict[str, Any]],
    call_next: Callable[[Any], Any],
) -> Callable[[Any], Any]:
    def middleware(request: Any) -> Any:
        boundary.enforce(
            request_loader(request),
            execution_context={"surface": "http_middleware"},
        )
        return call_next(request)

    return middleware


def webhook_enforcement_adapter(
    boundary: GuardRuntimeBoundary,
    *,
    request_loader: Callable[[dict[str, Any]], dict[str, Any]],
    handler: Callable[[dict[str, Any]], Any],
) -> Callable[[dict[str, Any]], Any]:
    def wrapped(payload: dict[str, Any]) -> Any:
        boundary.enforce(
            request_loader(payload),
            execution_context={"surface": "webhook"},
        )
        return handler(payload)

    return wrapped


def queue_job_adapter(
    boundary: GuardRuntimeBoundary,
    *,
    request_loader: Callable[[dict[str, Any]], dict[str, Any]],
    handler: Callable[[dict[str, Any]], Any],
) -> Callable[[dict[str, Any]], Any]:
    def wrapped(job: dict[str, Any]) -> Any:
        boundary.enforce(
            request_loader(job),
            execution_context={"surface": "queue_job"},
        )
        return handler(job)

    return wrapped


def agent_runner_adapter(
    boundary: GuardRuntimeBoundary,
    *,
    request_loader: Callable[[dict[str, Any]], dict[str, Any]],
    runner: Callable[[dict[str, Any]], Any],
) -> Callable[[dict[str, Any]], Any]:
    def wrapped(step: dict[str, Any]) -> Any:
        boundary.enforce(
            request_loader(step),
            execution_context={"surface": "agent_runner"},
        )
        return runner(step)

    return wrapped

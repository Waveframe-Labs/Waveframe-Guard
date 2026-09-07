from .guard import guard
from .context import install_guard, resolve_actor
from .execute import GovernanceError, execute
from .contracts import load_contract
from .result import GovernedExecutionResult
from .runtime import GuardRuntime, GovernedRuntime, evaluate_admissibility
from .schemas import (
    GOVERNED_EXECUTION_EVENT_V1,
    GOVERNED_EXECUTION_RESULT_V1,
    GOVERNED_EXECUTION_STATE_V1,
)

__version__ = "0.17.0"


def __getattr__(name):
    if name in {"RepositoryBoundaryError", "RepositoryTarget"}:
        from guard.sdk import repository_boundary

        return getattr(repository_boundary, name)
    if name == "Guard":
        from guard.sdk import Guard

        return Guard
    raise AttributeError(f"module 'waveframe_guard' has no attribute {name!r}")


__all__ = [
    "Guard",
    "RepositoryBoundaryError",
    "RepositoryTarget",
    "guard",
    "install_guard",
    "resolve_actor",
    "execute",
    "GovernanceError",
    "load_contract",
    "GovernedExecutionResult",
    "GovernedRuntime",
    "GuardRuntime",
    "evaluate_admissibility",
    "GOVERNED_EXECUTION_EVENT_V1",
    "GOVERNED_EXECUTION_RESULT_V1",
    "GOVERNED_EXECUTION_STATE_V1",
]

from contextvars import ContextVar

_guard_context = ContextVar("guard_context", default={})


def install_guard(*, actor, contract, mode="local"):
    _guard_context.set(
        {
            "actor": actor,
            "contract": contract,
            "mode": mode,
        }
    )


def get_context():
    return _guard_context.get()

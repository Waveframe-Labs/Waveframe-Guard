from .execute import execute


def guard(fn):
    """Deprecated decorator: invocation raises LegacyExecutionError.

    Migrate to Guard.local()/Guard.cloud() and @guard.tool(...).
    """
    def wrapped(*args, **kwargs):
        return execute(fn, args=args, kwargs=kwargs)

    return wrapped

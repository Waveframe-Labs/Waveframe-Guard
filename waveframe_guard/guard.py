from .execute import execute


def guard(fn):
    def wrapped(*args, **kwargs):
        return execute(fn, args=args, kwargs=kwargs)

    return wrapped

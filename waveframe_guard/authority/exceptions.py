class AuthorityLoadError(RuntimeError):
    pass


class InvalidAuthorityRef(AuthorityLoadError, ValueError):
    pass


class AuthorityNotFound(AuthorityLoadError, KeyError):
    pass


class MalformedAuthorityRegistry(AuthorityLoadError, ValueError):
    pass


class AuthorityVerificationError(AuthorityLoadError, ValueError):
    pass


class AuthorityLifecycleError(AuthorityVerificationError):
    pass

class AuthorityLoadError(RuntimeError):
    pass


class InvalidAuthorityRef(AuthorityLoadError, ValueError):
    pass


class AuthorityNotFound(AuthorityLoadError, KeyError):
    pass


class AuthorityVerificationError(AuthorityLoadError, ValueError):
    pass


class AuthorityLifecycleError(AuthorityVerificationError):
    pass

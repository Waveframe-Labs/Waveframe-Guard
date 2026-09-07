"""Repository-only path binding. See docs/architecture/REPOSITORY_WORKSPACE.md."""

from __future__ import annotations

import ctypes
import os
import platform
import stat
from contextlib import contextmanager
from pathlib import Path


class RepositoryBoundaryError(ValueError):
    """A repository request cannot be safely bound; no callback was invoked."""


def canonical_repository_path(value: object) -> str:
    # Deliberately a supported subset, never a normalizer or a Path coercion.
    if type(value) is not str or not value or len(value) > 4096:
        raise RepositoryBoundaryError("repository target must be a canonical relative path string")
    parts = value.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(10))
    if any(
        not part or part in {".", ".."} or len(part) > 255
        or part.endswith((" ", "."))
        or part.split(".")[0].upper() in reserved
        or any(ord(char) < 32 or ord(char) > 126 or char in '\\:<>"|?*' for char in part)
        for part in parts
    ):
        raise RepositoryBoundaryError("repository target is not a supported canonical relative path")
    return value


def _identity(info):
    if not info.st_ino:
        raise RepositoryBoundaryError("filesystem does not supply an unambiguous file identity")
    return info.st_dev, info.st_ino


class RepositoryTarget:
    """Ephemeral file capability, usable only inside a trusted repository callback.

    No path-like protocol is supplied. Call write_bytes/read_bytes on this object;
    independently opening relative_path is outside the protected adapter.
    """

    def __init__(self, relative_path, fd, validate):
        self._relative_path = relative_path
        self._fd = fd
        self._validate = validate
        self._active = False

    @property
    def relative_path(self) -> str:
        return self._relative_path

    def _check(self):
        if not self._active or self._fd is None:
            raise RepositoryBoundaryError("repository target capability is not active")
        self._validate()

    def read_bytes(self) -> bytes:
        self._check()
        os.lseek(self._fd, 0, os.SEEK_SET)
        chunks = []
        while chunk := os.read(self._fd, 65536):
            chunks.append(chunk)
        return b"".join(chunks)

    def write_bytes(self, content: bytes) -> int:
        if type(content) is not bytes:
            raise TypeError("repository write_bytes requires bytes")
        self._check()
        os.lseek(self._fd, 0, os.SEEK_SET)
        view = memoryview(content)
        while view:
            count = os.write(self._fd, view)
            if count <= 0:
                raise OSError("repository write did not make progress")
            view = view[count:]
        os.ftruncate(self._fd, len(content))
        return len(content)


class RepositoryWorkspace:
    """Trusted initialization of one existing, local repository root."""

    def __init__(self, root: str | Path):
        self._root_fd = None
        supplied = Path(root)
        if not supplied.is_absolute():
            raise RepositoryBoundaryError("repository_root must be an explicit absolute directory")
        self._root = supplied.resolve(strict=True)
        if not self._root.is_dir():
            raise RepositoryBoundaryError("repository_root must be an existing directory")
        if os.name == "nt":
            _windows_volume(self._root)
            self._root_fd = _windows_open(self._root, directory=True)
        elif platform.system() == "Linux":
            self._root_fd = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            raise RepositoryBoundaryError("repository workspace binding is unsupported on this OS")
        self._identity = _identity(os.fstat(self._root_fd))
        try:
            with self.bind("guard-workspace-validation", mutation=False):
                pass
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def __del__(self):
        self.close()

    def _check_root(self):
        if self._root_fd is None:
            raise RepositoryBoundaryError("repository workspace is closed")
        info = self._root.lstat()
        if _identity(info) != self._identity or _indirect(info):
            raise RepositoryBoundaryError("protected repository workspace was substituted")

    @contextmanager
    def bind(self, value, *, mutation=False, requirements=None):
        relative = canonical_repository_path(value)
        fds = []
        try:
            self._check_root()
            if os.name == "nt":
                # Lock the complete absolute parent chain before using Win32 paths.
                absolute_chain = [*reversed(self._root.parents), self._root]
                for directory in absolute_chain:
                    fds.append(_windows_open(directory, directory=True))
                if _identity(os.fstat(fds[-1])) != self._identity:
                    raise RepositoryBoundaryError("protected repository workspace was substituted")
            else:
                fds.append(os.dup(self._root_fd))
            case_sensitive = _case_sensitive(fds[-1])
            _validate_repository_rules(requirements)
            _reject_rule_alias(relative, requirements, case_sensitive)
            current = self._root
            missing = False
            leaf_fd = None
            snapshots = []
            components = relative.split("/")
            for index, component in enumerate(components):
                if missing:
                    continue
                directory = index < len(components) - 1
                current = current / component
                try:
                    if os.name == "nt":
                        fd = _windows_open(current, directory=directory, writable=mutation and not directory)
                    else:
                        fd = _linux_open(self._root_fd, "/".join(components[:index + 1]), directory)
                except FileNotFoundError:
                    missing = True
                    continue
                fds.append(fd)
                info = os.fstat(fd)
                if _indirect(info) or info.st_dev != self._identity[0]:
                    raise RepositoryBoundaryError("repository indirection or mount boundary is unsupported")
                if directory:
                    if not stat.S_ISDIR(info.st_mode) or _case_sensitive(fd) != case_sensitive:
                        raise RepositoryBoundaryError("ambiguous or mixed filesystem case behavior")
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise RepositoryBoundaryError("repository target must be a regular file with one link")
                # Reject Windows short names, case aliases and normalization aliases.
                if component not in os.listdir(current.parent):
                    raise RepositoryBoundaryError("repository target uses a filesystem name alias")
                snapshots.append((current, _identity(info)))
                if not directory:
                    leaf_fd = fd

            def validate():
                self._check_root()
                for path, identity in snapshots:
                    info = path.lstat()
                    if _indirect(info) or _identity(info) != identity:
                        raise RepositoryBoundaryError("repository target or ancestor was substituted")
                if leaf_fd is not None and os.fstat(leaf_fd).st_nlink != 1:
                    raise RepositoryBoundaryError("repository target acquired a hard-link alias")

            validate()
            if mutation:
                if os.name != "nt":
                    raise RepositoryBoundaryError(
                        "repository mutation is unsupported on POSIX: the adapter cannot lock "
                        "the namespace against concurrent rename/link operations"
                    )
                if leaf_fd is None:
                    raise RepositoryBoundaryError(
                        "repository mutation requires an existing regular file; creation is unsupported"
                    )
            yield RepositoryTarget(relative, leaf_fd, validate)
        except RepositoryBoundaryError:
            raise
        except OSError as exc:
            raise RepositoryBoundaryError(
                "repository filesystem binding failed; inaccessible, indirect, replaced, or unsupported target"
            ) from exc
        finally:
            for fd in reversed(fds):
                os.close(fd)


def _indirect(info):
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _reject_rule_alias(target, requirements, case_sensitive):
    if case_sensitive or not isinstance(requirements, dict):
        return
    rules = requirements.get("deny", [])
    if not isinstance(rules, list):
        return
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("value"), str):
            continue  # The authority evaluator rejects malformed rules.
        value = rule["value"]
        exact = rule.get("match") == "exact"
        folded_match = target.lower() == value.lower() if exact else target.lower().startswith(value.lower())
        literal_match = target == value if exact else target.startswith(value)
        if folded_match and not literal_match:
            raise RepositoryBoundaryError("repository target aliases a denied path on this filesystem")


def _validate_repository_rules(requirements):
    if not isinstance(requirements, dict):
        return
    for kind in ("allow", "deny"):
        rules = requirements.get(kind)
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("value"), str):
                continue
            value = rule["value"]
            if rule.get("match") == "prefix" and value.endswith("/"):
                value = value[:-1]
            canonical_repository_path(value)


def _linux_open(root_fd, relative, directory):
    # No resolve()/open() race; openat2 rejects bind mounts as well as symlinks.
    if platform.machine().lower() not in {"x86_64", "aarch64", "amd64"}:
        raise RepositoryBoundaryError("unsupported Linux openat2 architecture")
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | (os.O_DIRECTORY if directory else 0)
    how = OpenHow(flags, 0, 0x01 | 0x04 | 0x08)
    fd = libc.syscall(ctypes.c_long(437), ctypes.c_int(root_fd), relative.encode("ascii"), ctypes.byref(how), ctypes.sizeof(how))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, "secure repository lookup failed")
    return fd


def _case_sensitive(fd):
    if os.name == "nt":
        import msvcrt
        flags = ctypes.c_uint32()
        api = _windows_api()
        if not api.GetFileInformationByHandleEx(msvcrt.get_osfhandle(fd), 23, ctypes.byref(flags), 4):
            raise RepositoryBoundaryError("filesystem case behavior could not be verified")
        return bool(flags.value & 1)
    import array
    import fcntl
    # Only known local filesystems; unknown, network and casefold filesystems fail closed.
    libc = ctypes.CDLL(None, use_errno=True)
    buffer = ctypes.create_string_buffer(256)
    if libc.fstatfs(fd, buffer) != 0:
        raise RepositoryBoundaryError("filesystem identity could not be verified")
    fs_type = ctypes.c_long.from_buffer(buffer).value
    if fs_type not in {0xEF53, 0x58465342, 0x9123683E, 0x01021994}:
        raise RepositoryBoundaryError("unsupported repository filesystem")
    if fs_type == 0xEF53:
        flags = array.array("L", [0])
        fcntl.ioctl(fd, 0x80086601, flags)
        if flags[0] & 0x40000000:
            raise RepositoryBoundaryError("casefold filesystem directories are unsupported")
    return True


def _windows_api():
    from ctypes import wintypes
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    return api


def _windows_volume(root):
    api = _windows_api()
    if root.drive.startswith("\\") or len(root.drive) != 2:
        raise RepositoryBoundaryError("repository_root requires a local drive")
    fs_name = ctypes.create_unicode_buffer(32)
    if api.GetDriveTypeW(str(root.anchor)) != 3 or not api.GetVolumeInformationW(
        str(root.anchor), None, 0, None, None, None, fs_name, len(fs_name)
    ) or fs_name.value != "NTFS":
        raise RepositoryBoundaryError("repository workspace requires a local NTFS volume on Windows")


def _windows_open(path, *, directory, writable=False):
    import msvcrt
    api = _windows_api()
    # Deny write/delete sharing for files and directories, preventing reparse edits,
    # rename, deletion and link substitution while the capability is live.
    access = 0x80000000 | (0x40000000 if writable else 0)
    handle = api.CreateFileW(str(path), access, 1, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in {2, 3}:
            raise FileNotFoundError(error, "repository component does not exist")
        raise ctypes.WinError(error)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY))
    except BaseException:
        api.CloseHandle(handle)
        raise
    try:
        info = os.fstat(fd)
        if _indirect(info) or (directory and not stat.S_ISDIR(info.st_mode)):
            raise RepositoryBoundaryError("repository reparse point or non-directory ancestor")
    except BaseException:
        os.close(fd)
        raise
    return fd

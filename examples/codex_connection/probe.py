"""Run INSIDE the CLI sandbox, never in the trusted writer process.

Only disposable targets are mutated. Successful protected writes are failures.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--writer-pid", type=int)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    root = Path(config["workspace"])
    results = {}
    import win32api
    import win32file
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    results["token"] = {
        "user_sid": win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0]),
        "restricted_sids": [(win32security.ConvertSidToStringSid(sid), attributes)
                            for sid, attributes in win32security.GetTokenInformation(token, win32security.TokenRestrictedSids)],
        "elevation_type": win32security.GetTokenInformation(token, win32security.TokenElevationType),
    }
    token.Close()

    def attempt(name, callback):
        try:
            value = callback()
            results[name] = {"allowed": True, "value": value}
        except OSError as exc:
            results[name] = {"allowed": False, "error": type(exc).__name__,
                             "errno": exc.errno, "winerror": getattr(exc, "winerror", None)}

    attempt("python_direct_create", lambda: (root / "python-bypass.txt").write_text("bypass"))
    attempt("python_direct_modify", lambda: (root / "README.md").write_text("bypass"))
    for label, path in (("writer_code", Path(config["writer"])),
                        ("policy", Path(config["publication"]) / "authority-bundle.json"),
                        ("selection_config", args.config),
                        ("dependency_import", Path(config["python"]).parents[1] / "Lib/site-packages/guard/sdk/guard.py")):
        def append(path=path):
            with path.open("ab") as stream:
                return stream.write(b"\n")
        attempt(label, append)
    attempt("dependency_injection", lambda: (Path(config["python"]).parents[1] / "Lib/site-packages/issue54_probe.pth").write_text("# probe"))
    attempt("scratch_write", lambda: (Path(config["scratch"]) / "scratch-probe.txt").write_text("scratch works"))
    commands = {
        "child_python": [sys.executable, "-I", "-c", "from pathlib import Path; Path('child-bypass.txt').write_text('bypass')"],
        "child_shell": ["powershell.exe", "-NoProfile", "-Command", "Set-Content -LiteralPath child-shell-bypass.txt -Value bypass"],
        "identity": ["whoami.exe", "/all"],
        "acl": ["icacls.exe", str(root)],
        "acl_grant": ["icacls.exe", str(root / "README.md"), "/grant", "CodexSandboxUsers:(F)"],
        "ownership": ["takeown.exe", "/f", str(root / "README.md")],
    }
    for label, cmd in commands.items():
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, close_fds=True)
        results[label] = {"argv": cmd, "exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    if args.writer_pid:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        for label, rights in (("writer_duplicate_handles", 0x40), ("writer_inject", 0x2 | 0x8 | 0x20),
                              ("writer_read_memory", 0x10), ("writer_query_token", 0x400)):
            handle = kernel.OpenProcess(rights, False, args.writer_pid)
            results[label] = {"allowed": bool(handle), "winerror": ctypes.get_last_error() if not handle else 0}
            if handle:
                if label == "writer_read_memory":
                    metadata = Path(config["guard_evidence"]) / "process-probe.json"
                    if metadata.exists():
                        info = json.loads(metadata.read_text())
                        if info["pid"] == args.writer_pid:
                            buffer = ctypes.create_string_buffer(info["sentinel_size"])
                            count = ctypes.c_size_t()
                            kernel.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
                            success = kernel.ReadProcessMemory(handle, info["sentinel_address"], buffer, len(buffer), ctypes.byref(count))
                            results["nonsecret_memory_read"] = {"allowed": bool(success),
                                "matches_synthetic_marker": buffer.value == b"issue54-NONSECRET-memory-probe",
                                "bytes_read": count.value, "winerror": ctypes.get_last_error() if not success else 0}
                if label == "writer_query_token":
                    for token_label, token_rights in (("duplicate", 2), ("impersonate", 4), ("assign_primary", 1)):
                        try:
                            other_token = win32security.OpenProcessToken(int(handle), token_rights)
                            results["writer_token_" + token_label] = {"allowed": True}
                            other_token.Close()
                        except win32api.error as exc:
                            results["writer_token_" + token_label] = {"allowed": False, "winerror": exc.winerror}
                    try:
                        other_token = win32security.OpenProcessToken(int(handle), 2 | 4 | 8)
                        try:
                            win32security.ImpersonateLoggedOnUser(other_token)
                            try:
                                attempt("impersonated_write", lambda: (root / "impersonated-bypass.txt").write_text("bypass"))
                                thread_token = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
                                results["impersonation_level"] = win32security.GetTokenInformation(thread_token, win32security.TokenImpersonationLevel)
                                thread_token.Close()
                                try:
                                    file_handle = win32file.CreateFile(str(root / "token-bypass.txt"), 0x40000000, 1,
                                                                       None, 1, 0x80, None)
                                    try:
                                        win32file.WriteFile(file_handle, b"bypass")
                                        results["impersonated_win32_write"] = {"allowed": True}
                                    finally:
                                        file_handle.Close()
                                except win32api.error as exc:
                                    results["impersonated_win32_write"] = {"allowed": False, "winerror": exc.winerror}
                            finally:
                                win32security.RevertToSelf()
                        finally:
                            other_token.Close()
                    except win32api.error as exc:
                        results["writer_impersonation"] = {"allowed": False, "winerror": exc.winerror}
                kernel.CloseHandle(handle)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

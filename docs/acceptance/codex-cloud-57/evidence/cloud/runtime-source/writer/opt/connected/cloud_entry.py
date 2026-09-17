import os
from pathlib import Path
import subprocess
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else 'normal'
assert mode in ('normal', 'malformed', 'timeout', 'lost')
subprocess.Popen(['socat', 'TCP4-LISTEN:18081,bind=127.0.0.1,reuseaddr,fork',
                  'UNIX-CONNECT:/cloud-transport/cloud.sock'])
Path('/ipc/mcp.sock').unlink(missing_ok=True)
# -I prevents workspace/PYTHONPATH import. Explicit trusted module directory only.
os.execvp('socat', ['socat', 'UNIX-LISTEN:/ipc/mcp.sock,mode=0666,fork',
    'EXEC:python -I /opt/connected/launch.py ' + mode])

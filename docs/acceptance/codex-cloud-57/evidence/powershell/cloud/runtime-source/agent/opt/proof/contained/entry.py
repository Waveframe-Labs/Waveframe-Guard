"""Fixed container roles; no role selection or launch control exposed to MCP."""
import os
from pathlib import Path
import subprocess
import sys
import time

role = sys.argv[1]
if role == 'agent':
    for name in ('codex', 'cache', 'output'):
        Path('/scratch', name).mkdir(exist_ok=True)
    subprocess.Popen(['socat', 'TCP4-LISTEN:18080,bind=127.0.0.1,reuseaddr,fork',
                      'UNIX-CONNECT:/egress/proxy.sock'])
    while True:
        time.sleep(60)
elif role == 'proxy':
    subprocess.Popen(['squid', '-N', '-f', '/opt/proof/contained/squid.conf'])
    os.execvp('socat', ['socat', 'UNIX-LISTEN:/egress/proxy.sock,mode=0666,fork',
                       'TCP4:127.0.0.1:3128'])
elif role == 'writer':
    path = Path('/ipc/mcp.sock')
    path.unlink(missing_ok=True)
    # Only the operator can choose fault mode; neither socket accepts launch args.
    mode = sys.argv[2] if len(sys.argv) > 2 else 'normal'
    assert mode in ('normal', 'malformed', 'timeout', 'lost')
    os.execvp('socat', ['socat', 'UNIX-LISTEN:/ipc/mcp.sock,mode=0666,fork',
                       'EXEC:python -I /opt/proof/contained/server.py ' + mode])
else:
    raise SystemExit('unknown fixed role')

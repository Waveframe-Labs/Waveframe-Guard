"""Private stdio MCP; faults selected by operator, never by model request."""
import ctypes
import json
import os
from pathlib import Path
import sys
import time

from mcp.server.mcpserver import MCPServer
from cloud_writer import Writer

mode = sys.argv[1]
wire_fd = os.dup(1)
credential = ctypes.create_string_buffer(Path('/secrets/cloud.json').read_bytes())
writer = Writer('/source', '/evidence', json.loads(credential.value))
with Path('/evidence/processes.jsonl').open('a') as stream:
    stream.write(json.dumps({'pid': os.getpid(), 'uid': os.getuid(),
                            'marker_address': ctypes.addressof(credential),
                            'marker_size': ctypes.sizeof(credential)}) + '\n')
server = MCPServer('waveframe-contained-cloud', instructions=(
    'Use connection_status for actually loaded policy and fixed operation identities. '
    'Only repository_write can mutate protected source. Never retry after a failed or lost response. '
    'A failed preservation/report does not mean no file changed. Ask the operator to reconcile '
    'request/run IDs, local evidence, source bytes and Cloud records.'))


@server.tool()
def connection_status() -> dict:
    """Loaded Cloud publication; current writer observation, not a Cloud health check."""
    if mode == 'malformed':
        os.write(wire_fd, b'not-json\n')
        os._exit(71)
    if mode == 'timeout':
        time.sleep(12)
    return writer.status()


@server.tool()
def repository_write(request: dict) -> dict:
    """Exactly action=create|modify, path (relative to /source, never absolute), content. Operator fixes identity/policy."""
    result = writer.write(request)
    if mode == 'lost':
        os._exit(72)
    return result


try:
    server.run(transport='stdio')
finally:
    writer.close()

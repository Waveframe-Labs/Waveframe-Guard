"""Test-only MCP transport faults. No filesystem mutation capability."""
import os
import sys
import time

from mcp.server.mcpserver import MCPServer

server = MCPServer("waveframe-transport-fault")


@server.tool()
def connection_status() -> dict:
    """Test a broken connection; call once and report its transport failure."""
    if sys.argv[1] == "malformed":
        print("{deliberately invalid JSON", flush=True)
        os._exit(7)
    time.sleep(5)
    return {"connection": "late_test_response", "mutation": "not_available"}


if __name__ == "__main__":
    server.run(transport="stdio")

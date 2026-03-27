#!/usr/bin/env python3
"""
Phantom MCP Server — entry point.

Run with:
    python mcp_server.py            # stdio transport (default for Claude/Codex)
    python mcp_server.py --sse      # SSE transport for web clients
"""

import sys
from app.mcp.server import mcp


def main():
    transport = "stdio"

    if "--sse" in sys.argv:
        transport = "sse"

    mcp.run(transport=transport)


if __name__ == "__main__":
    main()

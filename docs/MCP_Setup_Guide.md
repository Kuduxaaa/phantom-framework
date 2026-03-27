# Phantom MCP Server — Setup Guide

Phantom exposes its security scanning capabilities as an [MCP](https://modelcontextprotocol.io/) server, allowing AI agents (Claude, Codex, etc.) to use vulnerability scanning, web crawling, and template management tools directly.

## Prerequisites

```bash
cd phantom-framework
make install:backend
```

## Running the Server

```bash
# stdio transport (default — used by Claude, Codex, and most MCP clients)
cd backend && python3 mcp_server.py

# SSE transport (for web-based clients)
cd backend && python3 mcp_server.py --sse

# or via Makefile
make mcp
```

## Client Configuration

All MCP clients use the same server config — only the config file location differs.

### Claude Desktop

Edit `claude_desktop_config.json`:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "phantom": {
      "command": "python3",
      "args": ["/absolute/path/to/phantom-framework/backend/mcp_server.py"]
    }
  }
}
```

Restart Claude Desktop after saving.

### Claude Code (CLI / VS Code / JetBrains)

```bash
claude mcp add phantom -- python3 /absolute/path/to/phantom-framework/backend/mcp_server.py
```

Or add manually to `.claude/settings.json` (project) or `~/.claude/settings.json` (global):

```json
{
  "mcpServers": {
    "phantom": {
      "command": "python3",
      "args": ["mcp_server.py"],
      "cwd": "/absolute/path/to/phantom-framework/backend"
    }
  }
}
```

### OpenAI Codex

Edit `~/.codex/config.json` (or `%USERPROFILE%\.codex\config.json` on Windows):

```json
{
  "mcpServers": {
    "phantom": {
      "command": "python3",
      "args": ["/absolute/path/to/phantom-framework/backend/mcp_server.py"]
    }
  }
}
```

Or pass it inline:

```bash
codex --mcp-config config.json
```

## Available Tools

| Tool | Description |
|------|-------------|
| `scan` | Full vulnerability scan — connectivity check, crawling, template execution |
| `crawl_target` | Discover pages, URL parameters, and HTML forms on a target |
| `list_templates` | List detection templates with category/severity/tag filters |
| `get_template` | Get template metadata, YAML source, and validation status |
| `validate_templates` | Check template syntax and structure for errors |
| `http_request` | Send a manual HTTP request and inspect the response |

## Example Prompts

```
Scan https://example.com for SQL injection vulnerabilities

Crawl https://example.com and list all discovered endpoints and forms

Show me all high and critical severity templates

Get the YAML source for injection/sql/error-based.yaml

Validate all templates in the fuzzing category

Send a POST request to https://example.com/api/login with {"user":"admin","pass":"test"}
```

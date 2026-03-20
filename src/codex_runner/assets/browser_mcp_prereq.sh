browser_mcp_command=@@COMMAND_Q@@
if ! command -v "$browser_mcp_command" >/dev/null 2>&1; then
  echo "codex-runner-error: browser MCP requires $browser_mcp_command in the Codex image"
  exit 1
fi

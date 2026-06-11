wait_for_browser_mcp() {
  deadline=$((SECONDS + 30))
  probe_read_timeout_seconds=2
  last_probe="not attempted"
  while [ "$SECONDS" -lt "$deadline" ]; do
    if exec 3<>/dev/tcp/127.0.0.1/@@PORT@@ 2>/dev/null; then
      printf 'GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
      response="$(timeout "${probe_read_timeout_seconds}s" cat <&3 || true)"
      exec 3<&-
      exec 3>&-
      status_line="$(printf '%s\n' "$response" | sed -n '1p' | tr -d '\r')"
      if printf '%s' "$status_line" | grep -q ' 200 '; then
        if printf '%s' "$response" | grep -Eq 'webSocketDebuggerUrl|"Browser"'; then
          last_probe="DevTools response ready"
          return 0
        else
          last_probe="HTTP 200 without DevTools marker"
        fi
      else
        last_probe="HTTP status ${status_line:-<empty>}"
      fi
    else
      last_probe="connection failed"
    fi
    sleep 1
  done
  echo "codex-runner-error: browser MCP endpoint did not become ready at http://127.0.0.1:@@PORT@@/json/version (last probe: $last_probe)"
  exit 1
}
wait_for_browser_mcp

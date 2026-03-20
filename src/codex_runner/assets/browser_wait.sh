wait_for_browser_mcp() {
  deadline=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if exec 3<>/dev/tcp/127.0.0.1/@@PORT@@ 2>/dev/null; then
      printf 'GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
      if IFS= read -r status_line <&3 && printf '%s' "$status_line" | grep -q ' 200 '; then
        exec 3<&-
        exec 3>&-
        return 0
      fi
      exec 3<&-
      exec 3>&-
    fi
    sleep 1
  done
  echo "codex-runner-error: browser MCP endpoint did not become ready at http://127.0.0.1:@@PORT@@/json/version"
  exit 1
}
wait_for_browser_mcp

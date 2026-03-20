set +e
composer_home=""
if [ ! -f composer.json ]; then
  printf '@@SKIP_LINE@@
'
  exit @@SKIP_EXIT_CODE@@
fi
if ! command -v composer >/dev/null 2>&1; then
  echo "composer not found in PATH" >&2
  exit 127
fi
log_file="$(mktemp /tmp/codex-composer-install.XXXXXX)"
timeout_marker="$(mktemp /tmp/codex-composer-timeout.XXXXXX)"
cleanup() {
  rm -f "$log_file"
  rm -f "$timeout_marker"
  if [ -n "$composer_home" ]; then
    rm -rf "$composer_home"
  fi
}
trap cleanup EXIT
@@COMPOSER_HOME_SETUP@@@@COMPOSER_COMMAND@@ >"$log_file" 2>&1 &
run_pid="$!"
(
  sleep "@@TIMEOUT_SECONDS@@"
  if kill -0 "$run_pid" 2>/dev/null; then
    printf 'composer install timed out after @@TIMEOUT_SECONDS@@s
' >"$timeout_marker"
    kill "$run_pid" 2>/dev/null || true
    sleep 1
    kill -9 "$run_pid" 2>/dev/null || true
  fi
) &
watchdog_pid="$!"
wait "$run_pid"
status="$?"
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
if [ "$status" -eq 0 ]; then
  tail -n 100 "$log_file"
  exit 0
fi
if [ -s "$timeout_marker" ]; then
  cat "$timeout_marker"
  tail -n 100 "$log_file"
  exit 124
fi
tail -n 100 "$log_file"
exit "$status"

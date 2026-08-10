codex_install_log=@@CODEX_INSTALL_LOG_PATH_Q@@
if ! rm -f "$codex_install_log" "${codex_install_log}.tmp"; then
  echo "codex-runner-error: could not prepare codex install log"
  exit 1
fi
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-runner: codex not found, installing"
  if ! command -v npm >/dev/null 2>&1; then
    echo "codex-runner-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
  # Keep npm output out of service logs while retaining a live, bounded tail for diagnostics.
  capture_codex_install_log() {
    while :; do
      codex_install_chunk=""
      IFS= read -r -N @@CODEX_INSTALL_LOG_CHUNK_BYTES@@ -t 0.1 codex_install_chunk
      codex_install_read_status="$?"
      if [ -n "$codex_install_chunk" ]; then
        printf '%s' "$codex_install_chunk" | tail -c @@CODEX_INSTALL_LOG_CHUNK_BYTES@@ >>"$codex_install_log"
        codex_install_log_size="$(wc -c <"$codex_install_log")"
        if [ "$codex_install_log_size" -gt @@CODEX_INSTALL_LOG_MAX_BYTES@@ ]; then
          tail -c @@CODEX_INSTALL_LOG_MAX_BYTES@@ "$codex_install_log" >"${codex_install_log}.tmp"
          mv "${codex_install_log}.tmp" "$codex_install_log"
        fi
      fi
      if [ "$codex_install_read_status" -eq 0 ] || [ "$codex_install_read_status" -gt 128 ]; then
        continue
      fi
      break
    done
  }
  set +e
  npm install -g @openai/codex 2>&1 | capture_codex_install_log
  codex_install_status="${PIPESTATUS[0]}"
  set -e
  if [ "$codex_install_status" -ne 0 ]; then
    echo "codex-runner-error: codex install failed"
    exit 1
  fi
  echo "codex-runner: codex install completed"
fi
if ! codex_path="$(command -v codex 2>/dev/null)"; then
  echo "codex-runner-error: codex validation failed: executable not found"
  exit 1
fi
if ! codex_version="$("$codex_path" --version 2>&1)" || [ -z "$codex_version" ]; then
  echo "codex-runner-error: codex validation failed"
  if [ -n "$codex_version" ]; then
    printf '%s\n' "$codex_version" | sed 's/^/codex-runner-error: /'
  fi
  exit 1
fi
echo "codex-runner: using $codex_version at $codex_path"

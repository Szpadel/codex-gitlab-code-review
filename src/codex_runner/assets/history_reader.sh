set -eu
mkdir -p "@@AUTH_MOUNT_PATH@@"
export CODEX_HOME="@@AUTH_MOUNT_PATH@@"
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-runner: codex not found, installing"
  if command -v npm >/dev/null 2>&1; then
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      npm install -g @openai/codex
    else
      if ! npm install -g @openai/codex >/tmp/codex-install.log 2>&1; then
        echo "codex-runner-error: codex install failed"
        tail -n 50 /tmp/codex-install.log | sed 's/^/codex-runner-error: /'
        exit 1
      fi
    fi
  else
    echo "codex-runner-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
fi
exec codex app-server --listen stdio://

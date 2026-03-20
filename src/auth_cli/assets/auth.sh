set -eu
mkdir -p "@@AUTH_MOUNT_PATH@@"
export CODEX_HOME="@@AUTH_MOUNT_PATH@@"
# Ensure Codex CLI is available for auth flows.
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-auth: codex not found, installing"
  if command -v npm >/dev/null 2>&1; then
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      npm install -g @openai/codex
    else
      if ! npm install -g @openai/codex >/tmp/codex-auth-install.log 2>&1; then
        echo "codex-auth-error: codex install failed"
        tail -n 50 /tmp/codex-auth-install.log | sed 's/^/codex-auth-error: /'
        exit 1
      fi
    fi
  else
    echo "codex-auth-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
fi
exec codex -c cli_auth_credentials_store="file" @@ACTION_ARGS@@

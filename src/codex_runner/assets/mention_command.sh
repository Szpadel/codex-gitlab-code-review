set -eu
GITLAB_TOKEN=@@GITLAB_TOKEN_Q@@
repo_dir=@@REPO_DIR_Q@@
log_file="/tmp/codex-mention-git.log"
mkdir -p /work
mkdir -p "$(dirname "$repo_dir")"
run_git() {
  action="$1"
  shift
  if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
    "$@" || { echo "codex-runner-error: git ${action} failed"; exit 1; }
  else
    if ! "$@" >"$log_file" 2>&1; then
      echo "codex-runner-error: git ${action} failed"
      tail -n 50 "$log_file" | sed 's/^/codex-runner-error: /'
      exit 1
    fi
  fi
}
export GITLAB_TOKEN=@@GITLAB_TOKEN_Q@@
@@GIT_AUTH_SETUP_SCRIPT@@
run_git clone git clone --depth 1 --recurse-submodules "@@CLONE_URL_DQ@@" "$repo_dir"
cd "$repo_dir"
run_git fetch git fetch --depth 1 origin @@HEAD_SHA_Q@@
run_git checkout git checkout @@HEAD_SHA_Q@@
run_git submodule_update git submodule update --init --recursive
@@GIT_AUTH_CLEANUP_SCRIPT@@
origin_url="$(git remote get-url origin || true)"
if [ -n "$origin_url" ]; then
  sanitized_origin="$(printf '%s' "$origin_url" | sed -E 's#(https?://)oauth2:[^@]*@#\1#')"
  run_git set_url git remote set-url origin "$sanitized_origin"
fi
run_git set_pushurl git remote set-url --push origin "no_push://disabled"
mkdir -p @@AUTH_MOUNT_PATH_Q@@
export CODEX_HOME=@@AUTH_MOUNT_PATH_Q@@
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
@@BROWSER_PREREQ_SCRIPT@@@@BROWSER_WAIT_SCRIPT@@@@APP_SERVER_EXEC_CMD@@

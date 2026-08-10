set -eu
mkdir -p "@@AUTH_MOUNT_PATH@@"
export CODEX_HOME="@@AUTH_MOUNT_PATH@@"
@@CODEX_CLI_BOOTSTRAP_SCRIPT@@echo "codex-runner: starting codex app-server"
exec codex app-server --listen stdio://

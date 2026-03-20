prefetch_deps() (
  set +e
  deps_dir="$repo_dir/.codex_deps"
  log_file="/tmp/codex-deps.log"
  mkdir -p "$deps_dir"
  failures=0
  run_prefetch() {
    action="$1"
    shift
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      "$@" || { echo "codex-runner-warn: $action failed"; failures=$((failures+1)); }
    else
      if ! "$@" >"$log_file" 2>&1; then
        echo "codex-runner-warn: $action failed"
        tail -n 50 "$log_file" | sed 's/^/codex-runner-warn: /'
        failures=$((failures+1))
      fi
    fi
  }

  if [ -f "package.json" ]; then
    if [ -f "pnpm-lock.yaml" ] && command -v pnpm >/dev/null 2>&1; then
      run_prefetch "pnpm install" pnpm install --ignore-scripts
    elif [ -f "yarn.lock" ] && command -v yarn >/dev/null 2>&1; then
      run_prefetch "yarn install" yarn install --ignore-scripts
    elif [ -f "package-lock.json" ] || [ -f "npm-shrinkwrap.json" ]; then
      run_prefetch "npm ci" npm ci --ignore-scripts --no-audit --no-fund
    else
      run_prefetch "npm install" npm install --ignore-scripts --no-audit --no-fund
    fi
  fi

  if [ -f "Cargo.toml" ] && command -v cargo >/dev/null 2>&1; then
    mkdir -p "$deps_dir/cargo"
    if [ -f "Cargo.lock" ]; then
      CARGO_HOME="$deps_dir/cargo" run_prefetch "cargo fetch" cargo fetch --locked
    else
      echo "codex-runner-warn: Cargo.lock missing; skipping cargo fetch"
    fi
  fi

  if [ -f "go.mod" ] && command -v go >/dev/null 2>&1; then
    mkdir -p "$deps_dir/go/mod" "$deps_dir/go/cache"
    GOMODCACHE="$deps_dir/go/mod" GOCACHE="$deps_dir/go/cache" GOFLAGS="-mod=readonly" run_prefetch "go mod download" go mod download
  fi

  if [ -f "requirements.txt" ] && command -v pip >/dev/null 2>&1; then
    mkdir -p "$deps_dir/pip"
    run_prefetch "pip download requirements.txt" pip download -r requirements.txt -d "$deps_dir/pip"
  fi

  if [ -f "pyproject.toml" ] && [ -f "poetry.lock" ] && command -v poetry >/dev/null 2>&1 && command -v pip >/dev/null 2>&1; then
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      poetry export -f requirements.txt --without-hashes -o /tmp/poetry-reqs.txt || failures=$((failures+1))
    else
      if ! poetry export -f requirements.txt --without-hashes -o /tmp/poetry-reqs.txt >"$log_file" 2>&1; then
        echo "codex-runner-warn: poetry export failed"
        tail -n 50 "$log_file" | sed 's/^/codex-runner-warn: /'
        failures=$((failures+1))
      fi
    fi
    if [ -f /tmp/poetry-reqs.txt ]; then
      mkdir -p "$deps_dir/pip"
      run_prefetch "pip download poetry export" pip download -r /tmp/poetry-reqs.txt -d "$deps_dir/pip"
    fi
  fi

  if [ -f "pom.xml" ] && command -v mvn >/dev/null 2>&1; then
    mkdir -p "$deps_dir/m2"
    MAVEN_USER_HOME="$deps_dir/m2" run_prefetch "maven go-offline" mvn -q -DskipTests dependency:go-offline
  fi

  if [ "$failures" -ne 0 ]; then
    return 1
  fi
  return 0
)
prefetch_home="/tmp/codex-prefetch"
mkdir -p "$prefetch_home/.config" "$prefetch_home/.cache" "$prefetch_home/.state"
if ! HOME="$prefetch_home" XDG_CONFIG_HOME="$prefetch_home/.config" XDG_CACHE_HOME="$prefetch_home/.cache"   XDG_STATE_HOME="$prefetch_home/.state" GITLAB_TOKEN="" CODEX_HOME="" prefetch_deps; then
  echo "codex-runner-warn: dependency prefetch had failures; continuing"
fi
export CARGO_HOME="$repo_dir/.codex_deps/cargo"
export GOMODCACHE="$repo_dir/.codex_deps/go/mod"
export GOCACHE="$repo_dir/.codex_deps/go/cache"
export MAVEN_USER_HOME="$repo_dir/.codex_deps/m2"

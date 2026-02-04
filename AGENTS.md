# Repository Guidelines

## Project Overview
This service scans configured GitLab projects/groups for open merge requests, runs Codex reviews in a Docker container, and posts results back to GitLab (comments and emoji awards). It stores review state in SQLite and can run once or on a cron schedule, with dry-run support for safe testing.

## Project Structure & Module Organization
- `src/` contains Rust sources (CLI entrypoint, GitLab client, review orchestration, Docker runner, state).
- `tests/` holds integration tests; `tests/e2e_live.rs` exercises live GitLab and Docker.
- `migrations/` stores SQLx migrations for the SQLite state database.
- `charts/codex-gitlab-review/` contains the Helm chart for deployment.
- `config.example.yaml` is the reference config; `config.yaml` is the local default.

## Build, Test, and Development Commands
- `cargo build` compiles the binary.
- `cargo run -- --help` lists CLI options.
- `cargo run -- --once` runs a single scan and exits.
- `cargo run -- auth login` performs device-code login for Codex auth.
- `cargo test` runs the test suite.
- `docker build -t codex-gitlab-review .` builds the container image.

## Coding Style & Naming Conventions
- Rust 2024 edition; format with `cargo fmt` and lint with `cargo clippy`.
- Use standard Rust naming: `snake_case` for modules/functions, `CamelCase` for types, `SCREAMING_SNAKE_CASE` for constants.
- Prefer small, focused functions and attach context to errors via `anyhow::Context`.

## Testing Guidelines
- Unit tests live alongside modules under `src/` using `#[cfg(test)]`.
- Live E2E test `tests/e2e_live.rs` only runs when `E2E_LIVE=1`.
- Required env vars: `E2E_GITLAB_BASE_URL`, `E2E_GITLAB_REPO`, `E2E_GITLAB_TOKEN`.
- Optional env vars: `E2E_GITLAB_MR_IID`, `E2E_DOCKER_HOST`, `E2E_CODEX_AUTH_HOST_PATH`.
- Keep live runs in `dry_run` mode unless intentionally writing to GitLab.

## Configuration & Operations
- Default config path is `config.yaml`; override with `CONFIG_PATH`.
- Environment overrides use `CODEX_REVIEW__...` (double underscores map to nested keys).
- Runtime state is stored in SQLite at `database.path`.

## Commit & Pull Request Guidelines
- Commit messages are short, imperative, capitalized, and have no scope prefix. Examples: "Use device code login", "Configure proxy conditionally".
- PRs should include a summary of behavior/config changes, any new required env vars, and test results (or note if skipped).
- For Helm or config changes, call out chart/config diffs explicitly.

set -eu
clone_root=@@CLONE_ROOT@@
repo_path=@@REPO_PATH@@
clone_url="@@CLONE_URL@@"
mkdir -p "$clone_root"
safe_repo="$(printf '%s' "$repo_path" | tr '/:@' '____')"
dest="$(mktemp -d "$clone_root/${safe_repo}-XXXXXX")"
git clone "$clone_url" "$dest" >/tmp/gitlab-discovery-clone.log 2>&1 || {
  tail -n 100 /tmp/gitlab-discovery-clone.log >&2
  exit 1
}
cd "$dest"
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' >/tmp/gitlab-discovery-fetch.log 2>&1 || {
  tail -n 100 /tmp/gitlab-discovery-fetch.log >&2
  exit 1
}
git fetch --tags origin >/tmp/gitlab-discovery-tags.log 2>&1 || {
  tail -n 100 /tmp/gitlab-discovery-tags.log >&2
  exit 1
}
origin_url="$(git remote get-url origin || true)"
if [ -n "$origin_url" ]; then
  sanitized_origin="$(printf '%s' "$origin_url" | sed -E 's#(https?://)oauth2:[^@]*@#\1#')"
  git remote set-url origin "$sanitized_origin"
fi
git remote set-url --push origin "no_push://disabled"
printf '%s\n' "$dest"

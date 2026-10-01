set -eu
clone_root=@@CLONE_ROOT@@
repo_path=@@REPO_PATH@@
clone_url="@@CLONE_URL@@"
mkdir -p "$clone_root"
safe_repo="$(printf '%s' "$repo_path" | tr '/:@' '____')"
dest="$(mktemp -d "$clone_root/${safe_repo}-XXXXXX")"
trap 'rm -rf -- "$dest"' EXIT
trap 'exit 1' HUP INT TERM
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
git remote set-url --push origin "no_push://disabled"
printf '%s\n' "$dest"
trap - EXIT HUP INT TERM

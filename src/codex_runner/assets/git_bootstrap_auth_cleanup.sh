if [ -n "${GIT_CONFIG_COUNT:-}" ]; then
  git_config_count="$GIT_CONFIG_COUNT"
  unset GIT_CONFIG_COUNT
  i=0
  while [ "$i" -lt "$git_config_count" ]; do
    unset "GIT_CONFIG_KEY_$i" "GIT_CONFIG_VALUE_$i"
    i=$((i + 1))
  done
fi
unset GITLAB_TOKEN

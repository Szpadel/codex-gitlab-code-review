set -euo pipefail
dest=@@DESTINATION@@
url=@@URL@@
max_bytes=@@MAX_BYTES@@
too_large_exit_code=@@TOO_LARGE_EXIT_CODE@@
# curl/curl.h defines CURLE_FILESIZE_EXCEEDED as 63.
curl_filesize_exceeded_exit_code=63
trap 'status=$?; if [ "$status" -ne 0 ]; then rm -f "$dest"; fi' EXIT

if command -v curl >/dev/null 2>&1; then
  # The bounded reader also limits responses without a Content-Length header.
  set +e
  curl --fail --silent --show-error --location --max-filesize "$max_bytes" \
    --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$url" |
    head -c "$((max_bytes + 1))" >"$dest"
  statuses=("${PIPESTATUS[@]}")
  set -e
  if [ "$(wc -c <"$dest")" -gt "$max_bytes" ] || [ "${statuses[0]}" -eq "$curl_filesize_exceeded_exit_code" ]; then
    printf 'Image exceeds the download size limit.\n' >&2
    exit "$too_large_exit_code"
  fi
  if [ "${statuses[0]}" -ne 0 ] || [ "${statuses[1]}" -ne 0 ]; then
    exit 1
  fi
elif command -v python3 >/dev/null 2>&1; then
  DEST="$dest" URL="$url" MAX_BYTES="$max_bytes" TOO_LARGE_EXIT_CODE="$too_large_exit_code" python3 - <<'PY'
import os
import sys
import urllib.request

request = urllib.request.Request(
    os.environ['URL'],
    headers={'PRIVATE-TOKEN': os.environ['GITLAB_TOKEN']},
)
max_bytes = int(os.environ['MAX_BYTES'])
with urllib.request.urlopen(request) as response:
    payload = response.read(max_bytes + 1)
if len(payload) > max_bytes:
    print('Image exceeds the download size limit.', file=sys.stderr)
    sys.exit(int(os.environ['TOO_LARGE_EXIT_CODE']))
with open(os.environ['DEST'], 'wb') as handle:
    handle.write(payload)
PY
else
  printf 'Cannot find curl or python3.\n' >&2
  exit 127
fi

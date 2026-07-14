#!/usr/bin/env bash
set -euo pipefail

# Exact-commit, rollback-capable deployment for the isolated production worker.

SCREENER_ROOT="${SCREENER_ROOT:-/opt/ditto/screener}"
SCREENER_USER="${SCREENER_USER:-deploy}"
SCREENER_UNIT="${SCREENER_UNIT:-ditto-screener}"
SCREENER_EXPECTED_SHA="${SCREENER_EXPECTED_SHA:?missing SCREENER_EXPECTED_SHA}"
SCREENER_UV_BIN="${SCREENER_UV_BIN:-/usr/local/bin/uv}"
SCREENER_REPOSITORY_URL="${SCREENER_REPOSITORY_URL:-git@github.com:ditto-assistant/ditto-screener.git}"
SCREENER_CACHE_GC_INTERVAL_SECONDS="${SCREENER_CACHE_GC_INTERVAL_SECONDS:-21600}"
SCREENER_CACHE_KEEP_STORAGE="${SCREENER_CACHE_KEEP_STORAGE:-12GB}"

checkout="$SCREENER_ROOT/src"
venv="$checkout/.venv"
env_file="$SCREENER_ROOT/screener.env"
unit_source="$checkout/deploy/ditto-screener.service"
unit_file="/etc/systemd/system/${SCREENER_UNIT}.service"
gc_state_dir="$SCREENER_ROOT/state"
gc_marker="$gc_state_dir/last-cache-gc"

if [[ "${EUID}" -ne 0 ]]; then
  echo "update-screener.sh must run as root" >&2
  exit 1
fi

for path in "$checkout/.git" "$env_file" "$SCREENER_UV_BIN"; do
  if [[ ! -e "$path" ]]; then
    echo "required screener deployment path is missing: $path" >&2
    exit 1
  fi
done

env_value() {
  local key="$1"
  sed -n "s/^${key}=//p" "$env_file" | tail -n 1
}

probe_platform() {
  local platform_url api_token hotkey
  platform_url="$(env_value SCREENER_PLATFORM_API_URL)"
  api_token="$(env_value SCREENER_API_TOKEN)"
  hotkey="$(env_value SCREENER_HOTKEY)"
  : "${platform_url:?missing SCREENER_PLATFORM_API_URL}"
  : "${api_token:?missing SCREENER_API_TOKEN}"
  : "${hotkey:?missing SCREENER_HOTKEY}"

  curl --fail --silent --show-error --config - \
    "$platform_url/api/v1/screener/queue?limit=1" >/dev/null <<CURL_CONFIG
header = "Authorization: Bearer $api_token"
header = "X-Screener-Hotkey: $hotkey"
CURL_CONFIG
}

wait_for_health() {
  local consecutive_healthy=0
  for attempt in $(seq 1 30); do
    if systemctl is-active --quiet "$SCREENER_UNIT" && probe_platform; then
      consecutive_healthy=$((consecutive_healthy + 1))
      if [[ "$consecutive_healthy" -ge 3 ]]; then
        return 0
      fi
    else
      consecutive_healthy=0
    fi
    if [[ "$attempt" -eq 30 ]]; then
      return 1
    fi
    sleep 2
  done
}

maintain_cache() {
  mkdir -p "$gc_state_dir"
  local now last
  now="$(date +%s)"
  last=0
  if [[ -f "$gc_marker" ]]; then
    last="$(stat -c %Y "$gc_marker" 2>/dev/null || echo 0)"
  fi
  if (( now - last < SCREENER_CACHE_GC_INTERVAL_SECONDS )); then
    return 0
  fi
  docker builder prune --force --filter until=24h \
    --keep-storage "$SCREENER_CACHE_KEEP_STORAGE"
  docker image prune --force --filter until=168h
  touch "$gc_marker"
}

current_sha="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" rev-parse HEAD)"
current_origin="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" remote get-url origin)"
if [[ "$current_origin" != "$SCREENER_REPOSITORY_URL" ]]; then
  runuser -u "$SCREENER_USER" -- git -C "$checkout" remote set-url origin \
    "$SCREENER_REPOSITORY_URL"
fi

if [[ "$current_sha" == "$SCREENER_EXPECTED_SHA" ]] && \
  systemctl is-active --quiet "$SCREENER_UNIT"; then
  probe_platform
  maintain_cache
  echo "healthy: $SCREENER_UNIT already at $current_sha"
  exit 0
fi

echo "==> fetching $SCREENER_EXPECTED_SHA"
runuser -u "$SCREENER_USER" -- git -C "$checkout" fetch --prune origin \
  "$SCREENER_EXPECTED_SHA"
resolved_sha="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" rev-parse FETCH_HEAD)"
if [[ "$resolved_sha" != "$SCREENER_EXPECTED_SHA" ]]; then
  echo "$SCREENER_EXPECTED_SHA resolved to unexpected commit $resolved_sha" >&2
  exit 1
fi

runuser -u "$SCREENER_USER" -- git -C "$checkout" reset --hard "$resolved_sha"
runuser -u "$SCREENER_USER" -- env UV_PROJECT_ENVIRONMENT="$venv" \
  "$SCREENER_UV_BIN" sync --frozen --project "$checkout"

if [[ ! -f "$unit_source" ]]; then
  echo "required screener unit is missing: $unit_source" >&2
  runuser -u "$SCREENER_USER" -- git -C "$checkout" reset --hard "$current_sha"
  runuser -u "$SCREENER_USER" -- env UV_PROJECT_ENVIRONMENT="$venv" \
    "$SCREENER_UV_BIN" sync --frozen --project "$checkout"
  exit 1
fi

unit_backup="$(mktemp)"
unit_existed=false
if [[ -f "$unit_file" ]]; then
  cp "$unit_file" "$unit_backup"
  unit_existed=true
fi
cleanup() {
  rm -f "$unit_backup"
}
trap cleanup EXIT

install -o root -g root -m 0644 "$unit_source" "$unit_file"
systemctl daemon-reload

systemctl restart "$SCREENER_UNIT"
if ! wait_for_health; then
  echo "new screener failed health checks; rolling back to $current_sha" >&2
  runuser -u "$SCREENER_USER" -- git -C "$checkout" reset --hard "$current_sha"
  runuser -u "$SCREENER_USER" -- env UV_PROJECT_ENVIRONMENT="$venv" \
    "$SCREENER_UV_BIN" sync --frozen --project "$checkout"
  if [[ "$unit_existed" == true ]]; then
    install -o root -g root -m 0644 "$unit_backup" "$unit_file"
  else
    rm -f "$unit_file"
  fi
  systemctl daemon-reload
  systemctl restart "$SCREENER_UNIT"
  wait_for_health || systemctl status "$SCREENER_UNIT" --no-pager >&2 || true
  exit 1
fi

actual_sha="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" rev-parse HEAD)"
if [[ "$actual_sha" != "$SCREENER_EXPECTED_SHA" ]]; then
  echo "healthy process is at unexpected commit $actual_sha" >&2
  exit 1
fi
maintain_cache
echo "healthy: $SCREENER_UNIT active at $actual_sha; platform preflight accepted"

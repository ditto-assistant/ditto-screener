#!/usr/bin/env bash
set -euo pipefail

# Exact-commit, rollback-capable deployment for the isolated production worker.

SCREENER_ROOT="${SCREENER_ROOT:-/opt/ditto/screener}"
SCREENER_USER="${SCREENER_USER:-deploy}"
SCREENER_UNIT="${SCREENER_UNIT:-ditto-screener}"
SCREENER_EXPECTED_SHA="${SCREENER_EXPECTED_SHA:?missing SCREENER_EXPECTED_SHA}"
SCREENER_UV_BIN="${SCREENER_UV_BIN:-/usr/local/bin/uv}"
SCREENER_REPOSITORY_URL="${SCREENER_REPOSITORY_URL:-git@github.com:ditto-assistant/ditto-screener.git}"
SCREENER_CACHE_GC_INTERVAL_SECONDS="${SCREENER_CACHE_GC_INTERVAL_SECONDS:-3600}"
SCREENER_CACHE_KEEP_STORAGE="${SCREENER_CACHE_KEEP_STORAGE:-12GB}"
SCREENER_GCP_PROJECT="${SCREENER_GCP_PROJECT:-ditto-app-dev}"
SCREENER_SOURCE_REVIEW_SECRET_ID="${SCREENER_SOURCE_REVIEW_SECRET_ID:-validator-openrouter-key}"

checkout="$SCREENER_ROOT/src"
venv="$checkout/.venv"
env_file="$SCREENER_ROOT/screener.env"
unit_source="$checkout/deploy/ditto-screener.service"
unit_file="/etc/systemd/system/${SCREENER_UNIT}.service"
gc_state_dir="$SCREENER_ROOT/state"
gc_marker="$gc_state_dir/last-cache-gc"
# SHA the currently-active, health-verified process is running. Written ONLY
# after a restart passes health + the post-restart SHA check, so it is proof of
# what is RUNNING — unlike git HEAD, which a run interrupted between `reset` and
# a healthy restart leaves pointing at a not-yet-running commit.
deployed_marker="$gc_state_dir/deployed-sha"
secret_dir="$SCREENER_ROOT/secrets"
source_review_key="$secret_dir/source-review-openrouter.key"
lock_file="$(dirname "$SCREENER_ROOT")/.screener-deploy.lock"

if [[ "${EUID}" -ne 0 ]]; then
  echo "update-screener.sh must run as root" >&2
  exit 1
fi

# Serialize deploys against first-boot bootstrap and other deploy runs: both
# mutate the same checkout / env / unit. bootstrap-screener.sh holds this lock
# across its whole body and exports SCREENER_DEPLOY_LOCK_HELD=1 when it invokes
# this script, so we don't re-lock (and deadlock) inside it.
if [[ "${SCREENER_DEPLOY_LOCK_HELD:-}" != "1" ]]; then
  exec {lock_fd}>"$lock_file"
  if ! flock -w 2400 "$lock_fd"; then
    echo "could not acquire deploy lock ($lock_file) within 40m" >&2
    exit 1
  fi
fi

ensure_enabled() {
  # First boot restarts the unit but a reboot then short-circuits on the
  # bootstrap marker, so the unit must be ENABLED to come back after a reboot.
  systemctl is-enabled --quiet "$SCREENER_UNIT" 2>/dev/null \
    || systemctl enable "$SCREENER_UNIT" >/dev/null 2>&1 || true
}

record_deployed_sha() {
  mkdir -p "$gc_state_dir"
  printf '%s\n' "$1" >"$deployed_marker"
}

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
  local platform_url api_token hotkey response required supported
  platform_url="$(env_value SCREENER_PLATFORM_API_URL)"
  api_token="$(env_value SCREENER_API_TOKEN)"
  hotkey="$(env_value SCREENER_HOTKEY)"
  : "${platform_url:?missing SCREENER_PLATFORM_API_URL}"
  : "${api_token:?missing SCREENER_API_TOKEN}"
  : "${hotkey:?missing SCREENER_HOTKEY}"

  response="$(curl --fail --silent --show-error --config - \
    "$platform_url/api/v1/screener/queue?limit=1" <<CURL_CONFIG
header = "Authorization: Bearer $api_token"
header = "X-Screener-Hotkey: $hotkey"
CURL_CONFIG
  )"
  required="$(printf '%s' "$response" | "$venv/bin/python" -c \
    'import json,sys; print(json.load(sys.stdin)["required_policy_version"])')"
  supported="$(runuser -u "$SCREENER_USER" -- "$venv/bin/python" -c \
    'from ditto_screening_protocol import SCREENING_POLICY_VERSION; print(SCREENING_POLICY_VERSION)')"
  if [[ "$required" != "$supported" ]]; then
    echo "screening policy mismatch: platform requires $required, worker supports $supported" >&2
    return 1
  fi
}

upsert_env() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  grep -v "^${key}=" "$env_file" >"$tmp" || true
  printf '%s=%s\n' "$key" "$value" >>"$tmp"
  install -o root -g ditto -m 0640 "$tmp" "$env_file"
  rm -f "$tmp"
}

materialize_source_review_key() {
  local tmp
  command -v gcloud >/dev/null || {
    echo "gcloud is required to materialize the source review key" >&2
    return 1
  }
  install -d -o "$SCREENER_USER" -g ditto -m 0750 "$secret_dir"
  tmp="$(mktemp)"
  if ! gcloud secrets versions access latest \
    --project="$SCREENER_GCP_PROJECT" \
    --secret="$SCREENER_SOURCE_REVIEW_SECRET_ID" >"$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  install -o "$SCREENER_USER" -g ditto -m 0400 "$tmp" "$source_review_key"
  rm -f "$tmp"
  upsert_env SCREENER_SOURCE_REVIEW_API_KEY_FILE "$source_review_key"
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
  # keep-storage is the bound. No age filter: an age filter exempts cache
  # created during a heavy screening burst (a policy-rescreen wave rebuilds
  # every submission in one day), which is exactly when the cache blows past
  # the budget. BuildKit prunes least-recently-used first and skips in-use
  # records, so an active build is never disturbed. The Docker daemon's own
  # builder GC (deploy/daemon.json) enforces the same budget continuously;
  # this pass is the backstop.
  docker builder prune --force --keep-storage "$SCREENER_CACHE_KEEP_STORAGE"
  docker image prune --force --filter until=168h
  touch "$gc_marker"
}

build_in_flight() {
  # A screening build in progress under the worker. A restart of docker (or the
  # worker) aborts it; the killed build now requeues as retryable-infra rather
  # than terminally rejecting the miner, but a requeue still throws away a full
  # rebuild, so disruptive maintenance defers to an idle run.
  pgrep -f "build -t ditto-screen" >/dev/null 2>&1
}

maintain_daemon_config() {
  # Repository-owned Docker daemon config: BuildKit's own GC enforces the
  # cache budget continuously (per build), so the disk stays bounded even
  # between updater passes. Docker is only restarted when the config actually
  # changes; a killed in-flight build reports retryable-infra and the lease
  # requeues the submission.
  local source="$checkout/deploy/daemon.json"
  local target="/etc/docker/daemon.json"
  [[ -f "$source" ]] || return 0
  if cmp -s "$source" "$target" 2>/dev/null; then
    return 0
  fi
  if ! dockerd --validate --config-file "$source"; then
    echo "deploy/daemon.json failed dockerd validation; keeping current config" >&2
    return 1
  fi
  if build_in_flight; then
    echo "deferring daemon.json apply: a screening build is in flight" >&2
    return 0
  fi
  install -o root -g root -m 0644 "$source" "$target"
  systemctl restart docker
  # Requires=docker.service can propagate the stop to the worker; make sure
  # it is running again (no-op when the restart left it untouched).
  systemctl start "$SCREENER_UNIT"
}

maintain_logs() {
  # The unit appends to a plain log file forever; keep it bounded without
  # restarting the service (in-place truncation preserves the O_APPEND fd).
  local log_file="/opt/ditto/logs/${SCREENER_UNIT}.log"
  local max_bytes=$((64 * 1024 * 1024))
  [[ -f "$log_file" ]] || return 0
  local size
  size="$(stat -c %s "$log_file" 2>/dev/null || echo 0)"
  if (( size > max_bytes )); then
    local keep
    keep="$(tail -c $((max_bytes / 4)) "$log_file")"
    printf '%s\n' "$keep" >"$log_file"
  fi
}

current_sha="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" rev-parse HEAD)"
current_origin="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" remote get-url origin)"
if [[ "$current_origin" != "$SCREENER_REPOSITORY_URL" ]]; then
  runuser -u "$SCREENER_USER" -- git -C "$checkout" remote set-url origin \
    "$SCREENER_REPOSITORY_URL"
fi

# Refresh the protected key on every scheduled deployment run so Secret Manager
# rotation does not require an unrelated code change.
materialize_source_review_key

deployed_sha=""
[[ -f "$deployed_marker" ]] && deployed_sha="$(cat "$deployed_marker")"
# Fast path gates on the RUNNING-verified SHA (marker), not git HEAD: a prior
# run that reset HEAD to the new SHA but died before a healthy restart must not
# be reported as deployed just because HEAD matches and the OLD process is up.
if [[ -n "$deployed_sha" ]] && [[ "$deployed_sha" == "$SCREENER_EXPECTED_SHA" ]] && \
  [[ "$current_sha" == "$SCREENER_EXPECTED_SHA" ]] && \
  systemctl is-active --quiet "$SCREENER_UNIT"; then
  probe_platform
  ensure_enabled
  maintain_daemon_config
  maintain_cache
  maintain_logs
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
# git reset --hard leaves untracked files in place. Pre-extraction the worker
# shipped a ``ditto/screener`` namespace; a leftover ``ditto`` tree keeps
# shadowing the import path (``python -m ditto.screener`` half-resolves against
# it). Drop it so the checkout matches the commit. Scoped to ``ditto`` so the
# ignored ``.venv`` and sibling state/secret dirs are never touched.
runuser -u "$SCREENER_USER" -- git -C "$checkout" clean -fd -- ditto
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
ensure_enabled

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
# Only now is the new SHA proven running + healthy: record it so the next run's
# fast path can trust it (and so an interrupted future run cannot be misread).
record_deployed_sha "$actual_sha"
maintain_daemon_config
maintain_cache
maintain_logs
echo "healthy: $SCREENER_UNIT active at $actual_sha; platform preflight accepted"

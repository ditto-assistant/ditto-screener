#!/usr/bin/env bash
set -euo pipefail

# Zero-touch first-boot provisioning for an autoscaled screener fleet instance.
#
# Invoked by the GCE instance-template startup script (infra repo,
# terraform/envs/gcp-platform/files/screener-fleet-startup.sh.tpl), which has
# already cloned this repository (read-only deploy key from Secret Manager) and
# exports the configuration below. Runs as root, is idempotent (marker file),
# and finishes by handing off to scripts/update-screener.sh — the same
# exact-commit updater the deploy workflow uses — so the definition of
# "healthy worker" lives in exactly one place.
#
# Pet-VM parity: the layout it produces (/opt/ditto/screener, deploy:ditto,
# screener.env, systemd unit) is byte-compatible with the hand-provisioned
# ditto-screener-prod host, which is what makes the label-driven deploy
# workflow able to treat pet and fleet instances identically.

SCREENER_GCP_PROJECT="${SCREENER_GCP_PROJECT:?missing SCREENER_GCP_PROJECT}"
SCREENER_PLATFORM_API_URL="${SCREENER_PLATFORM_API_URL:?missing SCREENER_PLATFORM_API_URL}"
SCREENER_HOTKEY="${SCREENER_HOTKEY:?missing SCREENER_HOTKEY}"
NETUID="${NETUID:?missing NETUID}"
SCREENER_MNEMONIC_SECRET="${SCREENER_MNEMONIC_SECRET:?missing SCREENER_MNEMONIC_SECRET}"
SCREENER_API_TOKEN_SECRET="${SCREENER_API_TOKEN_SECRET:?missing SCREENER_API_TOKEN_SECRET}"
SCREENER_DEPLOY_KEY_FILE="${SCREENER_DEPLOY_KEY_FILE:?missing SCREENER_DEPLOY_KEY_FILE}"
SCREENER_REPOSITORY_URL="${SCREENER_REPOSITORY_URL:-git@github.com:ditto-assistant/ditto-screener.git}"
# Readiness port for MIG autohealing (0/unset disables the server). Threaded
# into screener.env below so the worker binds it.
SCREENER_READINESS_PORT="${SCREENER_READINESS_PORT:-0}"

SCREENER_ROOT=/opt/ditto/screener
SCREENER_USER=deploy
SCREENER_GROUP=ditto
LOGS_DIR=/opt/ditto/logs
SECRETS_DIR=/opt/ditto/secrets
MARKER=/opt/ditto/.screener-bootstrapped
LOCK_FILE=/opt/ditto/.screener-deploy.lock

checkout="$SCREENER_ROOT/src"
env_file="$SCREENER_ROOT/screener.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "bootstrap-screener.sh must run as root" >&2
  exit 1
fi

if [[ -f "$MARKER" ]]; then
  echo "already bootstrapped ($MARKER exists)"
  exit 0
fi

# Hold the deploy lock across the whole mutating body so a scheduled deploy
# (update-screener.sh over SSH) landing mid-bootstrap serializes behind it
# instead of racing the checkout / env / unit. We pass the held flag down to the
# updater we invoke so it does not try to re-acquire (and deadlock).
exec {lock_fd}>"$LOCK_FILE"
if ! flock -w 2400 "$lock_fd"; then
  echo "could not acquire deploy lock ($LOCK_FILE) within 40m" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# --- Base packages + Docker engine (the gate shells out to `docker`) ---------
apt-get update -qq
apt-get install -y -qq git curl ca-certificates gnupg

if ! command -v docker >/dev/null; then
  install -m 0644 /dev/null /usr/share/keyrings/docker.asc
  curl -fsSL https://download.docker.com/linux/debian/gpg >/usr/share/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io
fi
systemctl enable --now docker

# --- Metadata (IMDS) guard: block 169.254.169.254 from container/build networks
# A submission-controlled Dockerfile builds and runs with network access. Left
# open, a hostile RUN step reaches the GCE metadata server and mints the VM's
# attached-SA token (the shared platform runtime SA), which can read platform /
# validator secrets and administer agent objects. Docker container/build traffic
# to the metadata IP traverses the FORWARD path (the DOCKER-USER chain), while
# the host's own gcloud uses OUTPUT — so dropping metadata in DOCKER-USER blocks
# every container and build without touching the host's Secret Manager access.
# Installed as a oneshot that re-applies after docker/iptables restarts + reboot.
apt-get install -y -qq iptables
install -m 0755 /dev/stdin /usr/local/sbin/ditto-imds-guard <<'GUARD'
#!/usr/bin/env bash
set -euo pipefail
# DOCKER-USER is created by dockerd; ensure it exists before inserting.
iptables -N DOCKER-USER 2>/dev/null || true
# Idempotent: drop any prior copy, then insert at the top of the chain.
while iptables -D DOCKER-USER -d 169.254.169.254/32 -j DROP 2>/dev/null; do :; done
iptables -I DOCKER-USER 1 -d 169.254.169.254/32 -j DROP
GUARD
cat >/etc/systemd/system/ditto-imds-guard.service <<'UNIT'
[Unit]
Description=Block cloud metadata (IMDS) from Docker container/build networks
After=docker.service
Wants=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ditto-imds-guard

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now ditto-imds-guard.service

# gcloud ships on GCE Debian images; the updater needs it for Secret Manager.
command -v gcloud >/dev/null || {
  echo "gcloud is required (expected on GCE Debian images)" >&2
  exit 1
}

# --- uv (the worker runs from a uv-managed venv; updater expects this path) ---
if [[ ! -x /usr/local/bin/uv ]]; then
  curl -fsSL https://astral.sh/uv/install.sh -o /tmp/uv-install.sh
  UV_INSTALL_DIR=/usr/local/bin sh /tmp/uv-install.sh
  rm -f /tmp/uv-install.sh
fi

# --- Service user + directory layout (matches the pet VM / updater) ----------
getent group "$SCREENER_GROUP" >/dev/null || groupadd --system "$SCREENER_GROUP"
if ! id "$SCREENER_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash --gid "$SCREENER_GROUP" "$SCREENER_USER"
fi
usermod -aG docker "$SCREENER_USER"

install -d -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0755 "$SCREENER_ROOT"
install -d -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0750 "$LOGS_DIR"
install -d -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0750 "$SECRETS_DIR"

# --- Deploy key: the deploy user fetches from the private repo on updates ----
ssh_dir="/home/$SCREENER_USER/.ssh"
install -d -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0700 "$ssh_dir"
install -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0600 \
  "$SCREENER_DEPLOY_KEY_FILE" "$ssh_dir/id_ed25519"
ssh-keyscan -t ed25519,rsa github.com 2>/dev/null >>"$ssh_dir/known_hosts"
chown "$SCREENER_USER:$SCREENER_GROUP" "$ssh_dir/known_hosts"
chmod 0644 "$ssh_dir/known_hosts"

# --- Secrets -> protected files / env (values never touch logs) --------------
read_secret() {
  gcloud secrets versions access latest \
    --project="$SCREENER_GCP_PROJECT" --secret="$1"
}

mnemonic="$(read_secret "$SCREENER_MNEMONIC_SECRET")"
api_token="$(read_secret "$SCREENER_API_TOKEN_SECRET")"

# SCREENER_SOURCE_REVIEW_API_KEY_FILE is intentionally absent: the updater
# materializes the OpenRouter key and upserts that line on every run.
tmp="$(mktemp)"
cat >"$tmp" <<EOF
# Written by scripts/bootstrap-screener.sh at first boot — updater-managed
# afterwards (update-screener.sh upserts individual keys). Do not commit.
SCREENER_PLATFORM_API_URL=$SCREENER_PLATFORM_API_URL
NETUID=$NETUID
SCREENER_HOTKEY=$SCREENER_HOTKEY
SCREENER_POLL_SECONDS=30
SCREENER_QUEUE_LIMIT=20
# Per-stage caps. The worker additionally clamps EVERY stage (build, serve, and
# each source-review step) to the remaining platform lease and re-queues as
# retryable if the budget runs out, so these caps are upper bounds, not a floor
# that can overrun a 30-min lease into a rejected-because-late verdict.
SCREENER_BUILD_TIMEOUT_SECONDS=1200
SCREENER_RUN_TIMEOUT_SECONDS=120
SCREENER_BUILD_MEMORY=2g
SCREENER_PIDS_LIMIT=512
# MUST stay >= the platform upload cap (DITTO_MAX_TARBALL_SIZE_BYTES, 20 MiB).
SCREENER_MAX_TARBALL_BYTES=20971520
SCREENER_READINESS_PORT=$SCREENER_READINESS_PORT
SCREENER_MNEMONIC=$mnemonic
SCREENER_API_TOKEN=$api_token
EOF
install -o root -g "$SCREENER_GROUP" -m 0640 "$tmp" "$env_file"
rm -f "$tmp"
unset mnemonic api_token

# --- Checkout + hand off to the exact-commit updater --------------------------
if [[ ! -d "$checkout/.git" ]]; then
  runuser -u "$SCREENER_USER" -- git clone "$SCREENER_REPOSITORY_URL" "$checkout"
fi
target_sha="$(runuser -u "$SCREENER_USER" -- git -C "$checkout" rev-parse HEAD)"

SCREENER_EXPECTED_SHA="$target_sha" \
  SCREENER_GCP_PROJECT="$SCREENER_GCP_PROJECT" \
  SCREENER_REPOSITORY_URL="$SCREENER_REPOSITORY_URL" \
  SCREENER_DEPLOY_LOCK_HELD=1 \
  bash "$checkout/scripts/update-screener.sh"

touch "$MARKER"
echo "bootstrap complete: $(hostname) at $target_sha"

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
SCREENER_GH_TOKEN_SECRET="${SCREENER_GH_TOKEN_SECRET:?missing SCREENER_GH_TOKEN_SECRET}"
SCREENER_DEPLOY_KEY_FILE="${SCREENER_DEPLOY_KEY_FILE:?missing SCREENER_DEPLOY_KEY_FILE}"
SCREENER_REPOSITORY_URL="${SCREENER_REPOSITORY_URL:-git@github.com:ditto-assistant/ditto-screener.git}"

SCREENER_ROOT=/opt/ditto/screener
SCREENER_USER=deploy
SCREENER_GROUP=ditto
LOGS_DIR=/opt/ditto/logs
SECRETS_DIR=/opt/ditto/secrets
GH_TOKEN_FILE="$SECRETS_DIR/screener-gh-token"
MARKER=/opt/ditto/.screener-bootstrapped

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

tmp="$(mktemp)"
read_secret "$SCREENER_GH_TOKEN_SECRET" >"$tmp"
install -o "$SCREENER_USER" -g "$SCREENER_GROUP" -m 0600 "$tmp" "$GH_TOKEN_FILE"
rm -f "$tmp"

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
SCREENER_BUILD_TIMEOUT_SECONDS=1200
SCREENER_RUN_TIMEOUT_SECONDS=120
SCREENER_BUILD_MEMORY=2g
SCREENER_PIDS_LIMIT=512
# MUST stay >= the platform upload cap (DITTO_MAX_TARBALL_SIZE_BYTES, 20 MiB).
SCREENER_MAX_TARBALL_BYTES=20971520
SCREENER_GH_TOKEN_FILE=$GH_TOKEN_FILE
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
  bash "$checkout/scripts/update-screener.sh"

touch "$MARKER"
echo "bootstrap complete: $(hostname) at $target_sha"

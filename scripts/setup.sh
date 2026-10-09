#!/usr/bin/env bash
# AEGIS AI SOC - Linux Foundation Setup
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '\n\033[1;36m[AEGIS]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

[[ "$(uname -s)" == Linux ]] || die "This script supports Linux."
[[ -f /etc/os-release ]] || die "Cannot identify the Linux distribution."
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == "24.04" ]] ||
  die "Expected Ubuntu Server 24.04; detected ${PRETTY_NAME:-unknown}."

(( EUID != 0 )) || die "Run as your normal SSH user, not with sudo. The script uses sudo when required."
has sudo || die "sudo is required."
sudo -v

log "[1/6] Checking host resources"
CPU_COUNT="$(nproc)"
RAM_GIB="$(awk '/MemTotal:/ {printf "%d", $2/1048576}' /proc/meminfo)"
FREE_GIB="$(df -BG --output=avail / | tail -n 1 | tr -dc '0-9')"
printf 'CPU threads: %s\nRAM: %s GiB\nFree root disk: %s GiB\n' \
  "$CPU_COUNT" "$RAM_GIB" "$FREE_GIB"

(( CPU_COUNT >= 8 )) || die "At least 8 CPU threads are required by this foundation plan."
(( RAM_GIB >= 16 )) || die "At least 16 GiB RAM is required."
(( FREE_GIB >= 30 )) || die "At least 30 GiB free disk space is required."

log "[2/6] Checking Git and installing base prerequisites"
sudo apt-get update
sudo apt-get install -y ca-certificates curl git gnupg lsb-release \
  build-essential python3-venv python3-pip

git --version
git rev-parse --is-inside-work-tree >/dev/null ||
  die "Run this script from inside the cloned AEGIS repository."

log "[3/6] Preparing Python 3.11"
# Ubuntu 24.04 ships Python 3.12 by default. Use uv to install Python 3.11
# alongside the OS Python without replacing Ubuntu's system interpreter.
if ! has uv; then
  curl -LsSf https://astral.sh/uv/install.sh -o /tmp/aegis-uv-install.sh
  sh /tmp/aegis-uv-install.sh
  rm -f /tmp/aegis-uv-install.sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
has uv || die "uv installation did not provide a usable command."
uv python install 3.11
if [[ ! -x .venv/bin/python ]]; then
  uv venv --python 3.11 .venv
fi
.venv/bin/python --version
uv pip install --python .venv/bin/python pip
.venv/bin/python -m pip --version

log "[4/6] Preparing Node.js 20 LTS and npm"
if ! has node || [[ "$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" != "20" ]]; then
  # Use the official NodeSource Node.js 20 repository.
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | sudo gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
    | sudo tee /etc/apt/sources.list.d/nodesource.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y nodejs
fi
node --version
npm --version
[[ "$(node -p 'process.versions.node.split(".")[0]')" == "20" ]] ||
  die "Node.js 20 is required."

log "[5/6] Installing Docker Engine and Compose v2"
if has docker; then
  docker --version
  docker compose version || die "Existing Docker Compose v2 is unavailable; review the installation."
  systemctl cat docker.service >/dev/null 2>&1 || die "Docker CLI exists but docker.service is missing; review the installation."
else
  # Do not silently remove or replace an existing Ubuntu Docker installation.
  for package in docker.io docker-doc docker-compose podman-docker containerd runc; do
    if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
      die "Conflicting package '$package' is installed. Review it before installing Docker CE."
    fi
  done

  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg

  CODENAME="${VERSION_CODENAME:?Ubuntu codename unavailable}"
  ARCH="$(dpkg --print-architecture)"
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$ARCH" "$CODENAME" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
fi

sudo systemctl enable --now docker
sudo systemctl enable --now containerd
sudo docker --version
sudo docker compose version
sudo docker info >/dev/null || die "Docker daemon is not responding."
sudo docker run --rm hello-world

log "[6/6] Checking foundation"
bash "$ROOT/scripts/verify.sh"

log "FOUNDATION SETUP PASSED"
echo "Windows scripts were preserved. No AEGIS application stack was deployed."
echo "Use 'sudo docker' for now; this script deliberately does not add your user to the Docker group."

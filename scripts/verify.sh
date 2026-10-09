#!/usr/bin/env bash
# AEGIS AI SOC - Linux Foundation Verification
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAILED=0

pass() { printf '\033[1;32m[PASS]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
check_cmd() { command -v "$1" >/dev/null 2>&1 && pass "$2" || fail "$2 ($1 missing)"; }

echo "=== AEGIS AI SOC - FOUNDATION VERIFICATION ==="

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == "24.04" ]] &&
    pass "Ubuntu Server 24.04" || fail "Expected Ubuntu Server 24.04"
else
  fail "Cannot identify Linux distribution"
fi

CPU_COUNT="$(nproc)"
RAM_GIB="$(awk '/MemTotal:/ {printf "%d", $2/1048576}' /proc/meminfo)"
FREE_GIB="$(df -BG --output=avail / | tail -n 1 | tr -dc '0-9')"
(( CPU_COUNT >= 8 )) && pass "CPU threads >= 8 ($CPU_COUNT)" || fail "CPU threads < 8 ($CPU_COUNT)"
(( RAM_GIB >= 16 )) && pass "RAM >= 16 GiB ($RAM_GIB GiB)" || fail "RAM < 16 GiB ($RAM_GIB GiB)"
(( FREE_GIB >= 30 )) && pass "Free disk >= 30 GiB ($FREE_GIB GiB)" || fail "Free disk < 30 GiB ($FREE_GIB GiB)"

check_cmd git "Git installed"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  pass "Inside Git repository"
  [[ "$(git remote get-url origin 2>/dev/null || true)" == "https://github.com/ymak207/aegis-ai-soc.git" ]] &&
    pass "Expected GitHub origin configured" || warn "Git origin differs from expected HTTPS URL"
  [[ "$(git branch --show-current)" == main ]] && pass "Branch is main" || warn "Current branch is $(git branch --show-current)"
else
  fail "Not inside a Git repository"
fi

if [[ -x .venv/bin/python ]]; then
  PYVER="$(.venv/bin/python --version 2>&1)"
  [[ "$PYVER" =~ ^Python\ 3\.11\. ]] && pass "Project Python 3.11 venv ($PYVER)" || fail "Expected Python 3.11 venv; got $PYVER"
else
  fail "Python virtual environment .venv/bin/python missing"
fi

if command -v uv >/dev/null 2>&1 || [[ -x "$HOME/.local/bin/uv" ]]; then
  pass "uv Python manager available"
else
  fail "uv Python manager missing"
fi

if command -v node >/dev/null 2>&1; then
  NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [[ "$NODE_MAJOR" == 20 ]] && pass "Node.js 20 ($(node --version))" || fail "Expected Node.js 20; got $(node --version)"
else
  fail "Node.js missing"
fi
check_cmd npm "npm installed"

if command -v docker >/dev/null 2>&1; then
  docker --version
  if docker compose version; then pass "Docker Compose v2"; else fail "Docker Compose v2 unavailable"; fi
  if sudo docker info >/dev/null 2>&1; then
    pass "Docker daemon responds (sudo)"
  elif docker info >/dev/null 2>&1; then
    pass "Docker daemon responds for current user"
  else
    fail "Docker daemon unavailable (try sudo systemctl status docker)"
  fi
else
  fail "Docker CLI missing"
fi

[[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" == cgroup2fs ]] &&
  pass "cgroup v2 detected" || warn "cgroup v2 not detected"

if curl -fsSI --connect-timeout 5 https://download.docker.com/linux/ubuntu/ >/dev/null 2>&1; then
  pass "HTTPS access to Docker package host"
else
  warn "Cannot verify HTTPS access to Docker package host"
fi

if systemctl is-system-running 2>/dev/null | grep -qx running; then
  pass "systemd running"
else
  STATE="$(systemctl is-system-running 2>/dev/null || true)"
  warn "systemd state: ${STATE:-unknown}; inspect failed units if needed"
fi

if (( FAILED > 0 )); then
  echo "FOUNDATION VERIFICATION FAILED: $FAILED check(s) failed."
  exit 1
fi

echo "FOUNDATION VERIFICATION PASSED"

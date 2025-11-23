#!/usr/bin/env bash

set -euo pipefail

K6_VERSION="v1.4.1"

# ------------------------------------------------------
# Simple orchestration script:
# ------------------------------------------------------
# - checks docker + python3
# - downloads k6 binary (if missing)
# - prepares tools venv and generates tokens
# - starts backend + gateway via docker compose
# - runs all k6 load tests
# - cleans up containers (except k6 binary and venv/token files)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_BIN="${REPO_ROOT}/k6/k6"

# ------------------------------------------------------
# helpers
# ------------------------------------------------------

log() {
  printf '\n[%s] %s\n' "$(date +'%H:%M:%S')" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command '$1' not found in PATH"
}

# shellcheck disable=SC2015
cleanup() {
  log "Stopping Docker services (docker compose down)..."
  if command -v docker >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
      (cd "$REPO_ROOT" && docker compose down || true)
    elif command -v docker-compose >/dev/null 2>&1; then
      (cd "$REPO_ROOT" && docker-compose down || true)
    fi
  fi
}
trap cleanup EXIT

# ------------------------------------------------------
# 1. Preconditions
# ------------------------------------------------------

log "Checking prerequisites (docker, python3)..."
check_cmd docker
check_cmd python3
check_cmd curl

OS="$(uname -s)"
if [[ "$OS" == "Linux" ]]; then
  check_cmd tar
elif [[ "$OS" == "Darwin" ]]; then
  check_cmd unzip
fi

# ------------------------------------------------------
# 2. Download k6 (if missing)
# ------------------------------------------------------

download_k6() {
  if [[ -x "$K6_BIN" ]]; then
    log "k6 already present at ${K6_BIN}"
    return
  fi

  local os arch archive_type url
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}/${arch}" in
    Linux/x86_64)
      url="https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-linux-amd64.tar.gz"
      archive_type="tar"
      ;;
    Darwin/x86_64)
      url="https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-macos-amd64.zip"
      archive_type="zip"
      ;;
    Darwin/arm64)
      url="https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-macos-arm64.zip"
      archive_type="zip"
      ;;
    *)
      fail "Unsupported OS/ARCH combination for auto k6 download: ${os}/${arch}"
      ;;
  esac

  log "Downloading k6 from ${url}..."

  local tmpdir archive_file

  tmpdir="$(mktemp -d)"
  archive_file="${tmpdir}/k6-archive"

  curl -sSL "${url}" -o "${archive_file}"

  case "${archive_type}" in
    tar)
      tar -xzf "${archive_file}" -C "${tmpdir}"
      ;;
    zip)
      unzip -q "${archive_file}" -d "${tmpdir}"
      ;;
    *)
      fail "Unknown archive_type: ${archive_type}"
      ;;
  esac

  # find k6 binary inside extracted directory
  local k6_path
  k6_path="$(find "${tmpdir}" -type f -name k6 -perm -u+x | head -n1)"
  [[ -n "${k6_path}" ]] || fail "k6 binary not found in archive"

  mv "${k6_path}" "${K6_BIN}"
  chmod +x "${K6_BIN}"
  rm -rf "${tmpdir}"

  log "k6 installed to ${K6_BIN}"
}

download_k6

# ------------------------------------------------------
# 3. Generate tokens via tools/venv
# ------------------------------------------------------

log "Preparing Python venv and generating tokens..."

TOOLS_DIR="${REPO_ROOT}/tools"
VENV_DIR="${REPO_ROOT}/.venv"

if [[ ! -d "${VENV_DIR}" ]]; then
  log "Creating venv at ${VENV_DIR}..."
  python3 -m venv "${VENV_DIR}"
fi

source "${VENV_DIR}/bin/activate"

log "Installing Python requirements..."
pip install --upgrade pip >/dev/null
pip install -r "${REPO_ROOT}/requirements.txt" >/dev/null

log "Running token generator (generate-all.py)..."
python "${TOOLS_DIR}/generate-all.py" -n 100

deactivate || true

# ------------------------------------------------------
# 4. Start backend + gateway via docker compose
# ------------------------------------------------------

log "Starting backend + gateway (docker compose up -d)..."

cd "${REPO_ROOT}"

if docker compose version >/dev/null 2>&1; then
  docker compose up -d backend gateway
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose up -d backend gateway
else
  fail "Neither 'docker compose' nor 'docker-compose' available"
fi

# ------------------------------------------------------
# 5. Wait for health (actuator/health)
# ------------------------------------------------------

wait_for_health() {
  local service="$1" port="$2" timeout="${3:-120}"
  log "Waiting for ${service} to be healthy on port ${port} (timeout ${timeout}s)..."

  local start now
  start="$(date +%s)"

  while true; do
    if curl -fsS "http://localhost:${port}/actuator/health" >/dev/null 2>&1; then
      log "${service} is healthy"
      return 0
    fi
    now="$(date +%s)"
    if (( now - start > timeout )); then
      fail "Timeout waiting for ${service} health on port ${port}"
    fi
    sleep 3
  done
}

wait_for_health "backend" 9090 120
wait_for_health "gateway" 8080 120

# ------------------------------------------------------
# 6. Run all k6 tests
# ------------------------------------------------------

log "Running k6 load tests..."

RESULTS_DIR="${REPO_ROOT}/results"
mkdir -p "${RESULTS_DIR}"

cd "${REPO_ROOT}/k6"

# warmup (to avoid JVM cold start issues)
if [[ -f warmup.js ]]; then
  "${K6_BIN}" run warmup.js
else
  log "Skipping warmup (not found)"
fi

for script in load-plain.js load-hs256.js load-rs256.js load-es256.js load-jwe.js; do
  if [[ -f "${script}" ]]; then
    log "k6 run ${script}..."

    alg="${script#load-}"
    alg="${alg%.js}"
    out="${RESULTS_DIR}/${alg}.json"

    "${K6_BIN}" run "${script}" --summary-export "${out}"
  else
    log "Skipping ${script} (not found)"
  fi
done

log "All k6 tests finished."

# ------------------------------------------------------
# 7. Cleanup (handled by trap)
# ------------------------------------------------------

log "Benchmark run complete. Containers will be stopped by trap."

#!/usr/bin/env bash

set -euo pipefail

K6_VERSION="v1.4.1"
JWT_VERSION="v0.0.2-alpha"
JWT_REPO="danilkiff/jwt-token-generator"

TOKENS_COUNT=10000

# ------------------------------------------------------
# Simple orchestration script:
# ------------------------------------------------------
# - checks docker, curl, tar, python3 (only for k6 warmup deps, if any)
# - downloads k6 binary (if missing)
# - downloads jwt-tools (Go CLIs for JWT/JWE) and generates tokens
# - starts backend + gateway via docker compose
# - runs all k6 load tests
# - cleans up containers (except k6 binary, jwt-tools and token files)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
K6_BIN="${REPO_ROOT}/k6/k6"
JWT_BIN_DIR="${REPO_ROOT}/jwt-tools"

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

log "Checking prerequisites (docker, python3, curl, tar)..."
check_cmd docker
check_cmd python3
check_cmd curl
check_cmd tar

OS="$(uname -s)"
ARCH="$(uname -m)"

# ------------------------------------------------------
# 2. Download k6 (if missing)
# ------------------------------------------------------

download_k6() {
  if [[ -x "$K6_BIN" ]]; then
    log "k6 already present at ${K6_BIN}"
    return
  fi

  local os arch archive_type url
  os="$OS"
  arch="$ARCH"

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

  mkdir -p "$(dirname "${K6_BIN}")"
  mv "${k6_path}" "${K6_BIN}"
  chmod +x "${K6_BIN}"
  rm -rf "${tmpdir}"

  log "k6 installed to ${K6_BIN}"
}

download_k6

# ------------------------------------------------------
# 3. Download jwt-tools and generate tokens
# ------------------------------------------------------

download_jwt_tools() {
  if [[ -x "${JWT_BIN_DIR}/jwt-claims" ]]; then
    log "jwt-tools already present in ${JWT_BIN_DIR}"
    return
  fi

  local os arch archive url
  os="$OS"
  arch="$ARCH"

  case "${os}/${arch}" in
    Linux/x86_64)
      archive="jwt-tools-linux-amd64.tar.gz"
      ;;
    Linux/aarch64|Linux/arm64)
      archive="jwt-tools-linux-arm64.tar.gz"
      ;;
    Darwin/x86_64)
      archive="jwt-tools-darwin-amd64.tar.gz"
      ;;
    Darwin/arm64)
      archive="jwt-tools-darwin-arm64.tar.gz"
      ;;
    *)
      fail "Unsupported OS/ARCH combination for jwt-tools: ${os}/${arch}"
      ;;
  esac

  url="https://github.com/${JWT_REPO}/releases/download/${JWT_VERSION}/${archive}"

  log "Downloading jwt-tools from ${url}..."

  local tmpdir archive_file
  tmpdir="$(mktemp -d)"
  archive_file="${tmpdir}/${archive}"

  curl -sSL "${url}" -o "${archive_file}"
  mkdir -p "${JWT_BIN_DIR}"
  tar -xzf "${archive_file}" -C "${JWT_BIN_DIR}"

  # На macOS снимем quarantine, иначе Gatekeeper будет ругаться
  if [[ "$OS" == "Darwin" ]]; then
    log "Clearing quarantine attribute for jwt-tools on macOS..."
    xattr -d com.apple.quarantine "${JWT_BIN_DIR}/jwt-"* 2>/dev/null || true
  fi

  chmod +x "${JWT_BIN_DIR}/jwt-"*
  rm -rf "${tmpdir}"

  log "jwt-tools installed to ${JWT_BIN_DIR}"
}

download_jwt_tools

generate_tokens_with_jwt_tools() {
  log "Generating tokens via jwt-tools..."

  local claims_bin hs_bin rs_bin es_bin jwe_bin
  claims_bin="${JWT_BIN_DIR}/jwt-claims"
  hs_bin="${JWT_BIN_DIR}/jwt-sign-hs256"
  rs_bin="${JWT_BIN_DIR}/jwt-sign-rs256"
  es_bin="${JWT_BIN_DIR}/jwt-sign-es256"
  jwe_bin="${JWT_BIN_DIR}/jwe-encrypt-rsa-oaep-a256gcm"

  [[ -x "${claims_bin}" ]] || fail "jwt-claims not found or not executable"
  [[ -x "${hs_bin}" ]]     || fail "jwt-sign-hs256 not found or not executable"
  [[ -x "${rs_bin}" ]]     || fail "jwt-sign-rs256 not found or not executable"
  [[ -x "${es_bin}" ]]     || fail "jwt-sign-es256 not found or not executable"
  [[ -x "${jwe_bin}" ]]    || fail "jwe-encrypt-rsa-oaep-a256gcm not found or not executable"

  local secrets output
  secrets="${REPO_ROOT}/secrets"
  output="${REPO_ROOT}/output"
  mkdir -p "${output}"

  [[ -f "${secrets}/hs256-secret.txt" ]]    || fail "Missing ${secrets}/hs256-secret.txt"
  [[ -f "${secrets}/rs256-private.pem" ]]   || fail "Missing ${secrets}/rs256-private.pem"
  [[ -f "${secrets}/es256-private.pem" ]]   || fail "Missing ${secrets}/es256-private.pem"
  [[ -f "${secrets}/rsa-public.pem" ]]      || fail "Missing ${secrets}/rsa-public.pem"

  # HS256
  log "Generating HS256 tokens..."
  "${claims_bin}" -count=${TOKENS_COUNT} | \
    "${hs_bin}" --key-file "${secrets}/hs256-secret.txt" \
    > "${output}/hs256-tokens.txt"

  # RS256
  log "Generating RS256 tokens..."
  "${claims_bin}" -count=${TOKENS_COUNT} | \
    "${rs_bin}" --key-file "${secrets}/rs256-private.pem" \
    > "${output}/rs256-tokens.txt"

  # ES256
  log "Generating ES256 tokens..."
  "${claims_bin}" -count=${TOKENS_COUNT} | \
    "${es_bin}" --key-file "${secrets}/es256-private.pem" \
    > "${output}/es256-tokens.txt"

  # JWE
  log "Generating JWE tokens..."
  "${claims_bin}" -count=${TOKENS_COUNT} | \
    "${jwe_bin}" --pub-key-file "${secrets}/rsa-public.pem" \
    > "${output}/jwe-tokens.txt"

  log "Token generation complete. Files in ${output}"
}

generate_tokens_with_jwt_tools

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
  local service="$1" url="$2" timeout="${3:-120}"
  log "Waiting for ${service} to be healthy on ${url} (timeout ${timeout}s)..."

  local start now
  start="$(date +%s)"

  while true; do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      log "${service} is healthy"
      return 0
    fi
    now="$(date +%s)"
    if (( now - start > timeout )); then
      fail "Timeout waiting for ${service} health on ${url}"
    fi
    sleep 3
  done
}

wait_for_health "backend" "http://localhost:9090/api/ping" 120
wait_for_health "gateway" "http://localhost:8080/actuator/health" 120

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
log "Benchmark run complete. Containers will be stopped by trap."


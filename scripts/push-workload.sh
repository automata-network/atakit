#!/usr/bin/env bash
#
# Push a workload to a CVM agent via POST /init (HTTPS, port 1024).
#
# Usage:
#   ./push-workload.sh <host> <archive.atawl> [options]
#
# Options:
#   --unmeasured <dir>    Directory containing unmeasured-data files
#   --expire-offset <sec> Session expiry offset (default: 3600)
#   --port <port>         CVM agent port (default: 1024)
#   --wait <sec>          Wait for agent to become reachable (default: 300)
#
# Environment variables:
#   ATAKIT_RPC_URL              Ethereum RPC endpoint (required)
#   ATAKIT_SESSION_REGISTRY     Session registry contract address (required)
#   ATAKIT_OWNER_PRIVATE_KEY    Owner private key, 0x... (required)
#   ATAKIT_RELAY_PRIVATE_KEY    Relay private key, 0x... (required)
#
# Example:
#   export ATAKIT_RPC_URL=https://sepolia.infura.io/v3/KEY
#   export ATAKIT_SESSION_REGISTRY=0x1234...5678
#   export ATAKIT_OWNER_PRIVATE_KEY=0xabc...
#   export ATAKIT_RELAY_PRIVATE_KEY=0xdef...
#   ./push-workload.sh 34.126.100.42 my-workload-v0.0.1.atawl

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

# --- Parse arguments ---

HOST=""
ARCHIVE=""
UNMEASURED_DIR=""
RPC_URL="${ATAKIT_RPC_URL:-}"
SESSION_REGISTRY="${ATAKIT_SESSION_REGISTRY:-}"
OWNER_KEY="${ATAKIT_OWNER_PRIVATE_KEY:-}"
RELAY_KEY="${ATAKIT_RELAY_PRIVATE_KEY:-}"
EXPIRE_OFFSET=3600
PORT=1024
WAIT_TIMEOUT=300

while [[ $# -gt 0 ]]; do
    case "$1" in
        --unmeasured)      UNMEASURED_DIR="$2"; shift 2 ;;
        --rpc-url)         RPC_URL="$2"; shift 2 ;;
        --session-registry) SESSION_REGISTRY="$2"; shift 2 ;;
        --owner-key)       OWNER_KEY="$2"; shift 2 ;;
        --relay-key)       RELAY_KEY="$2"; shift 2 ;;
        --expire-offset)   EXPIRE_OFFSET="$2"; shift 2 ;;
        --port)            PORT="$2"; shift 2 ;;
        --wait)            WAIT_TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,/^$/{ s/^# \?//; p }' "$0"
            exit 0
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            if [[ -z "$HOST" ]]; then
                HOST="$1"
            elif [[ -z "$ARCHIVE" ]]; then
                ARCHIVE="$1"
            else
                die "unexpected argument: $1"
            fi
            shift
            ;;
    esac
done

[[ -n "$HOST" ]]              || die "missing required argument: <host>"
[[ -n "$ARCHIVE" ]]           || die "missing required argument: <archive.atawl>"
[[ -f "$ARCHIVE" ]]           || die "archive not found: $ARCHIVE"
[[ -n "$RPC_URL" ]]           || die "ATAKIT_RPC_URL / --rpc-url is required"
[[ -n "$SESSION_REGISTRY" ]]  || die "ATAKIT_SESSION_REGISTRY / --session-registry is required"
[[ -n "$OWNER_KEY" ]]         || die "ATAKIT_OWNER_PRIVATE_KEY / --owner-key is required"
[[ -n "$RELAY_KEY" ]]         || die "ATAKIT_RELAY_PRIVATE_KEY / --relay-key is required"

AGENT_URL="https://${HOST}:${PORT}"

# --- Wait for agent ---

echo "Waiting for CVM agent at ${HOST}:${PORT}..."

start_time=$(date +%s)
interval=5

while true; do
    elapsed=$(( $(date +%s) - start_time ))
    if [[ $elapsed -ge $WAIT_TIMEOUT ]]; then
        die "timed out after ${WAIT_TIMEOUT}s waiting for agent"
    fi

    if curl -sk --connect-timeout 5 --max-time 10 "${AGENT_URL}/platform-measurements" >/dev/null 2>&1; then
        echo "Agent reachable (${elapsed}s)"
        break
    fi

    echo "  Not ready yet (${elapsed}s elapsed, retrying in ${interval}s)..."
    sleep "$interval"

    # Exponential backoff, capped at 30s
    interval=$(( interval < 30 ? interval * 2 : 30 ))
    [[ $interval -gt 30 ]] && interval=30
done

# --- Build config JSON ---

config_file=$(mktemp /tmp/config-XXXXXX.json)
cat > "$config_file" <<EOF
{
  "agent_env": {
    "rpc_url": "${RPC_URL}",
    "session_registry": "${SESSION_REGISTRY}",
    "owner_private_key": "${OWNER_KEY}",
    "relay_private_key": "${RELAY_KEY}",
    "expire_offset": ${EXPIRE_OFFSET}
  }
}
EOF

# --- Package unmeasured-data (if provided) ---

unmeasured_tar=""
cleanup() {
    [[ -f "$config_file" ]] && rm -f "$config_file"
    [[ -n "$unmeasured_tar" && -f "$unmeasured_tar" ]] && rm -f "$unmeasured_tar"
}
trap cleanup EXIT

if [[ -n "$UNMEASURED_DIR" ]]; then
    [[ -d "$UNMEASURED_DIR" ]] || die "unmeasured-data directory not found: $UNMEASURED_DIR"

    file_count=$(find "$UNMEASURED_DIR" -type f | wc -l)
    if [[ $file_count -eq 0 ]]; then
        echo "Warning: unmeasured-data directory is empty, skipping"
        UNMEASURED_DIR=""
    else
        echo "Packaging unmeasured-data ($file_count files)..."
        unmeasured_tar=$(mktemp /tmp/unmeasured-XXXXXX.tar.gz)
        tar -czf "$unmeasured_tar" -C "$UNMEASURED_DIR" .
    fi
fi

# --- POST /init ---

archive_name=$(basename "$ARCHIVE")
archive_size=$(du -h "$ARCHIVE" | cut -f1)
echo "Uploading ${archive_name} (${archive_size})..."

curl_args=(
    -sk
    --max-time 600
    -X POST "${AGENT_URL}/init"
    -F "atawl=@${ARCHIVE}"
    -F "config=@${config_file};type=application/json"
)

if [[ -n "$UNMEASURED_DIR" && -n "$unmeasured_tar" ]]; then
    curl_args+=(-F "unmeasured-data=@${unmeasured_tar}")
fi

response=$(curl "${curl_args[@]}" -w "\n%{http_code}" 2>&1)
http_code=$(echo "$response" | tail -1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" == "200" ]] || [[ "$http_code" == "201" ]]; then
    echo "Workload initialized successfully."
    [[ -n "$body" ]] && echo "$body"
else
    echo "Init failed (HTTP $http_code):" >&2
    echo "$body" >&2
    exit 1
fi

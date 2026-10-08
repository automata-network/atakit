#!/usr/bin/env bash
# Build repository-owned mocks using the companion checkout's Solidity dependencies.
set -euo pipefail
unset CDPATH

if [[ $# != 2 || $1 != --contracts ]]; then
    echo "Usage: $0 --contracts /path/to/tee-workload-attestation" >&2
    exit 2
fi
contracts=$(cd "$2" && pwd -P)
emulator=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp -R "$emulator/contracts" "$work/src"
forge build --root "$work" --contracts "$work/src" --out "$work/out" \
    --use 0.8.27 --evm-version prague --optimize --optimizer-runs 200 --via-ir --offline \
    --remappings "@contracts/=$contracts/" \
    --remappings "@automata-network/automata-tpm-attestation/=$contracts/lib/automata-tpm-attestation/src/" \
    --remappings "@solady/=$contracts/lib/solady/src/" \
    --remappings "@openzeppelin/contracts/=$contracts/lib/openzeppelin-contracts/contracts/"
printf '{}\n' > "$work/manifest.json"
for name in EmulatorDcapAttestation EmulatorTpmAttestation; do
    artifact="$work/out/$name.sol/$name.json"
    jq -e '(.deployedBytecode.immutableReferences // {} | length) == 0 and (.deployedBytecode.linkReferences // {} | length) == 0' "$artifact" >/dev/null
    jq -er '.deployedBytecode.object | sub("^0x"; "") | select(test("^[0-9a-fA-F]+$") and (length % 2 == 0))' "$artifact" > "$work/$name.runtime.hex"
    source_hash=$(shasum -a 256 "$emulator/contracts/$name.sol" | awk '{print $1}')
    runtime_hash=$(xxd -r -p "$work/$name.runtime.hex" | shasum -a 256 | awk '{print $1}')
    jq --arg name "$name" --arg source "$source_hash" --arg runtime "$runtime_hash" \
        '.[$name] = {source_sha256: $source, runtime_sha256: $runtime}' \
        "$work/manifest.json" > "$work/next.json"
    mv "$work/next.json" "$work/manifest.json"
done
cp "$work/"*.runtime.hex "$emulator/assets/"
cp "$work/manifest.json" "$emulator/assets/mocks-manifest.json"

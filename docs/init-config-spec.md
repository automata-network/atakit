# `init-config` Specification

The init-config is the configuration contract that an operator hands to a CVM
at workload-initialization time. It is **produced** by the `atakit` CLI
(`atakit`) and **consumed** by the in-CVM portal (`atakit-portal`). It tells
the portal which chain to register against, which keys to use, and which secrets
unlock the workload's encrypted disks.

Remote ATAWL delivery does not add fields to this document. The URI, complete
archive SHA-256, archive size, and expected workload ID belong to the `atawl`
multipart part described by the portal API. Schema 4 supports `runtime_disks`
and optional `thp`; see [cloud disk configuration](cloud-disk-configuration.md)
and [runtime configuration](runtime-configuration.md).

This document is the authoritative schema reference for that contract. For the
HTTP mechanics of the endpoint that carries it (multipart layout, ports,
one-shot semantics, response body), see
[portal-api-spec.md](portal-api-spec.md) `POST /init`.

## Roles

| Side | Crate | Role |
|---|---|---|
| Producer | `atakit/crates/atakit-cloud` (`init.rs`), driven by `atakit-cli` | Assembles the JSON from operator TOML + CLI flags and POSTs it. |
| Consumer | `atakit-portal/crates/atakit-portal-state` (`init_config.rs`), `atakit-portal-api` (`init.rs`) | Parses, validates against the workload manifest, applies it, and persists a subset. |

The two sides are independent codebases. The wire JSON below is the only
coupling between them; keep both ends in sync with this spec.

## Two artifacts

The name "init-config" covers two related JSON artifacts:

1. **Wire form** — the `config` part of the `POST /init` multipart request. This
   is the full operator input. Modeled by `InitConfig` in
   `atakit-portal-state::init_config` (consumer) and built by
   `build_portal_config_json` in `atakit-cloud::init` (producer).

2. **Persisted form** — `init-config.json`, written to the RW partition
   (root-owned, mode `0600`) so the portal can re-initialize the workload on
   every subsequent reboot without re-running `/init`. Modeled by
   `PersistedInitConfig`. It is a **subset** of the wire form plus one
   manifest-derived field, and notably **excludes private keys** (those are
   persisted separately via the supervisor `PersistKey` RPC).

```
operator TOML + CLI flags                 RW partition
        │                                       ▲
        ▼  (atakit-cli)                          │  PersistInitConfig RPC
   InitConfig ──build_portal_config_json──▶ config.json
        │                                       │
        │   POST /init (multipart)              │
        ▼                                       │
   atakit-portal-api/init.rs ──validate──▶ PersistedInitConfig ──▶ init-config.json
                                                                       │
                                            reboot: read for platform  │
                                            cross-check + disk unlock ◀─┘
```

## Wire schema (`config.json`)

Canonical example (self-generated gas wallet, no disk encryption):

```json
{
  "format": 4,
  "platform": { "declared": "gcp" },
  "chain": {
    "registration": "required",
    "tee_backend": "auto",
    "rpc_url": "https://rpc.example.com",
    "contracts": {
      "session_registry": "0x...",
      "workload_registry": "0x...",
      "base_image_registry": "0x..."
    },
    "chain_id": 11155111
  },
  "owner_operations": {
    "op_expiry_seconds": 300,
    "challenge_expiry_seconds": 60,
    "max_request_body_bytes": 1048576,
    "max_waiting_requests": 64,
    "max_completed_request_statuses": 256,
    "request_status_retention_seconds": 3600
  },
  "prover": {
    "backend": "sp1",
    "execution": "network",
    "endpoint": "",
    "options": {}
  },
  "prover_credential": {
    "mode": "provisioned",
    "type": "es256k",
    "private_key": "0x..."
  },
  "pcr_policy": {
    "workloadId": "0x...",
    "baseImageId": "0x...",
    "platformProfileId": "0x...",
    "measurementVariantId": "0x...",
    "pcrBankSelection": "sha256-and-sha384",
    "invariantPcrPolicy": {
      "pcrSpecs256": [],
      "pcrSpecs384": []
    },
    "variantPcrPolicy": {
      "pcrSpecs256": [],
      "pcrSpecs384": []
    },
    "workloadPcrPolicy": {
      "pcrSpecs256": [],
      "pcrSpecs384": []
    }
  },
  "owner_key": {
    "mode": "provisioned",
    "type": "es256k",
    "private_key": "0x..."
  },
  "gas_wallet": {
    "mode": "self_generated",
    "type": "es256k"
  },
  "disk_setup": {
    "secrets": "create"
  }
}
```

### Top-level fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `format` | integer | yes | — | Schema version. Currently must be `4`; any other value is rejected (`format_unsupported`). |
| `platform` | object | no | `null` | `{ "declared": "<gcp\|azure\|aws\|qemu>" }`. Cross-checked against DMI auto-detect; required when DMI is inconclusive. See [Platform](#platform). |
| `chain` | object | no | section omitted ⇒ `registration = off` | On-chain registration config. See [Chain](#chain). |
| `owner_operations` | object | no | documented per-field defaults | Owner-authorized portal operation limits and retention. See [Owner operations](#owner-operations). |
| `owner_key` | object | yes | — | Operator-provisioned signing identity. See [Keys](#keys). |
| `gas_wallet` | object | yes | — | Gas-paying key held by atakit-portal. `null` and missing values are rejected. See [Keys](#keys). |
| `prover` | object | conditional | `null` | Resolved prover daemon and execution policy. Required when the effective TEE backend is ZK. |
| `prover_credential` | object | conditional | `null` | Backend-neutral delegated credential. Required when the selected daemon descriptor declares a signer scheme. |
| `pcr_policy` | object | no | `null` | Strict `ResolvedPcrPolicy` collection policy. See [PCR policy](#pcr-policy). |
| `runtime_disks` | object | no | `{}` | Owner-selected `encryption_workqueues` (`default` or `bypass`) by manifest disk name. See [cloud disk configuration](cloud-disk-configuration.md). |
| `thp` | string | no | `never` | Owner-selected automatic transparent huge page policy: `never` or `madvise`. See [runtime configuration](runtime-configuration.md). |
| `disk_setup` | object | no | `{}` | One-time operator permission to `create` or `overwrite` a named disk. See [Disks](#disks). |
| `local_ssd` | object | no | `null` | GCP or Azure local SSD selection: `{ "disk": "database", "count": 2 }`. Derived from the selected disk profile and VM type. The trusted cloud identity selects the device resolver. See [GCP grouping](cloud-disk-configuration.md#gcp-local-ssd-grouping) and [Azure grouping](cloud-disk-configuration.md#azure-local-ssd-grouping). |

### Platform

`platform.declared` is sent verbatim as the operator's claim about the cloud the
CVM is running on. Recognized values: `gcp`, `azure`, `aws`, `qemu`.

The supervisor creates one authoritative platform identity at boot. Automatic
detection reads DMI and performs bounded provider-specific metadata probes. It
retains the observed DMI strings, every attempted probe's non-secret raw result,
and each detector's inferred provider separately from the resolved `cloud`
value. AWS IMDSv2 tokens are transient secrets and are never retained.
`declared` is normally a cross-check and becomes the authority only when both
automatic detectors are inconclusive:

- DMI identifies GCP, Azure, or AWS → probe only that provider's metadata
  contract as a cross-check; DMI remains authoritative even if metadata is
  temporarily unavailable.
- DMI identifies QEMU → use DMI and perform no CSP metadata probe.
- DMI inconclusive and exactly one GCP/Azure/AWS metadata contract matches →
  use metadata detection as the authority.
- DMI inconclusive and multiple metadata contracts match → remain unresolved
  and reject `/init`; `declared` cannot override the ambiguity.
- Both automatic detectors inconclusive and `declared` present → use
  `declared` as the fallback authority.
- An automatic detector resolves a provider and `declared` disagrees → `/init`
  fails (`platform_mismatch`).
- All detectors inconclusive and `declared` absent → `/init` fails.

The identity records whether `cloud` is authorized by `dmi`, `metadata`, or
`user_provided`, or remains `unresolved`, plus the exact accepted declaration.
The metadata probes are CSP-specific: GCP `Metadata-Flavor`, Azure
`/metadata/versions`, and AWS IMDSv2 token plus metadata index. There is no
portable cross-CSP metadata endpoint; only the link-local IP is shared. The
supervisor is the only component that resolves this value. Workers obtain a
typed snapshot over IPC and submit `/init` declarations to the supervisor for
a non-mutating preflight; they must not independently combine observations with
configuration. The supervisor installs the result only when it persists the
accepted config. Because the persisted form retains `platform`, the supervisor
repeats the same resolution and cross-check on every reboot before exposing the
identity.

### Chain

```json
"chain": {
  "registration": "required",          // optional; see default resolution
  "rpc_url": "https://...",            // conditional
  "contracts": {
    "session_registry": "0x...",
    "workload_registry": "0x...",
    "base_image_registry": "0x..."
  },
  "chain_id": 11155111,                // optional; ignored when rpc_url is set
  "tee_backend": "auto"
}
```

| Field | Type | Notes |
|---|---|---|
| `registration` | enum string | `"required"` \| `"optional"` \| `"off"`. Portal-side registration policy. See table below. |
| `rpc_url` | string | Chain JSON-RPC endpoint. Required when `registration` is `required` or `optional`. |
| `contracts.session_registry` | string | SessionRegistry contract address. |
| `contracts.workload_registry` | string | WorkloadRegistry contract address. |
| `contracts.base_image_registry` | string | BaseImageRegistry contract address. |
| `chain_id` | integer | Optional configured EIP-155 chain id. The portal reads the effective value through `eth_chainId` and warns when this field is set. |
| `tee_backend` | enum string | `"auto"` \| `"solidity"` \| `"zk"`. `auto` selects ZK for SNP and Solidity for TDX. `solidity` is rejected for SNP. |
The current wire schema and operator configuration have no
`chain.proving_strategy` field. Both reject it as unknown.

### Owner operations

```json
"owner_operations": {
  "op_expiry_seconds": 300,
  "challenge_expiry_seconds": 60,
  "max_request_body_bytes": 1048576,
  "max_waiting_requests": 64,
  "max_completed_request_statuses": 256,
  "request_status_retention_seconds": 3600
}
```

This strict top-level object configures all owner-authorized session endpoints.
Unknown keys are rejected. `op_expiry_seconds` is the default validity window
for owner-signed contract operations and is unrelated to workload
`sessionTtl`. The remaining fields bound the preparation body, challenge
lifetime, waiting map, completed-status map, and completed-status retention.

### Prover

```json
"prover": {
  "backend": "sp1",
  "execution": "network",
  "endpoint": "",
  "options": { "dcap_rpc_url": "https://..." }
}
```

`backend` selects an installed descriptor, not an in-process portal feature.
`execution` is currently `network`, `local_cpu`, or `dev`; the selected daemon
must advertise it. `endpoint` and `options` are backend inputs and are validated
by that daemon. The normalized `prover` block is persisted for reboot.

The optional `prover_credential` uses the common `KeyConfig` shape. It is
required when the
installed descriptor declares a delegated signer scheme. The portal persists
the key only through its privileged key store and exposes delegated digest
signing to the daemon; private key bytes are not written into persisted
`init-config.json` or sent in a proof request.

The workload manifest is unchanged. Prover selection is deployment policy and
does not affect the workload ID. Program/vkey identities are governed by
[atakit-prover-artifact-spec.md](atakit-prover-artifact-spec.md).

### PCR policy

`pcr_policy` uses the exact JSON form of `ResolvedPcrPolicy`:

| Field | Type |
|---|---|
| `workloadId` | 32-byte `0x`-prefixed hex string |
| `baseImageId` | 32-byte `0x`-prefixed hex string |
| `platformProfileId` | 32-byte `0x`-prefixed hex string |
| `measurementVariantId` | 32-byte `0x`-prefixed hex string |
| `pcrBankSelection` | `sha256`, `sha384`, or `sha256-and-sha384` |
| `invariantPcrPolicy`, `variantPcrPolicy`, `workloadPcrPolicy` | named `PcrPolicyBlock` objects |

Each `PcrPolicyBlock` contains sorted `pcrSpecs256` and `pcrSpecs384` arrays.

Each rule has `pcrIndex` and `comparison`. `comparison` is one non-empty,
`0x`-prefixed opaque byte string. The portal preserves these bytes unchanged.
It reads only the first ABI word to decide whether selected SHA-384 policy
requires the ZK TPM Quote path. The selected verifier owns complete decoding,
canonical validation, and evaluation. The canonical encoding is defined by
[measurement-pack-spec.md](measurement-pack-spec.md#pcr-specs). Supported PCR
indexes are 0 through 16 and 23. Rule arrays must use strictly increasing PCR
indexes. The invariant and variant arrays for one bank must not overlap.

The four identifiers must equal the workload, base image, platform profile,
and measurement variant selected for this initialization. AWS rejects
`pcrBankSelection = "sha256"`. GCP rejects
`pcrBankSelection = "sha384"`.

`pcr_policy` controls Quote collection only. It does not replace trusted policy
verification. Before each Quote, atakit-portal uses this exact order:

1. With active registration, call `SessionRegistry.getPcrPolicy`.
2. Use the matching persisted `pcr_policy`.
3. Request SHA-256 and SHA-384 PCR0 through PCR16 and PCR23 as a fallback.

When registration is active, `atakit` does not send `--pcr-policy`. When
registration is off, `atakit` first tries the selected chain, then reads the
strict JSON file supplied by `--pcr-policy`, and otherwise omits the field.

#### Registration policy

| `registration` | Submits on-chain? | Gates manifest-declared inbound ports? | `rpc_url` | `session_registry` | `chain_id` |
|---|---|---|---|---|---|
| `required` | yes | yes — ports stay closed until `isSessionActive` confirms; workload processes have already started | **required** (verification polling) | **required** | ignored (read via `eth_chainId`) |
| `optional` | yes | no — ports open while registration proceeds in parallel | **required** | **required** | ignored (read via `eth_chainId`) |
| `off` | no | no — ports open for the local-bound session | ignored | ignored | ignored |

For `registration = "required"`, the portal launches the workload containers
before it submits or confirms registration. The post-launch TPM Quote must
include the applicable PCR10 and IMA launch measurements. The portal then
enters `Registering` with the workload processes running and the workload
manifest-declared inbound ports closed. It opens those ports and enters
`Running` only after `isSessionActive(sessionId)` is observed true. This policy
does not prevent outbound connections, filesystem writes, background jobs, or
other startup effects allowed by the container configuration.

The portal treats `rpc_url` as authoritative. It uses normal JSON-RPC calls and
does not verify a consensus proof, block-header chain, state proof, or agreement
among independent RPC endpoints. An actor that controls `rpc_url` can falsify
the chain ID, owner nonce, transaction or receipt results, and
`isSessionActive(sessionId)`. A false active result can cause the portal to open
the workload manifest-declared inbound ports and enter `Running`.

Under `off`, populated `rpc_url` / `contracts` / `chain_id` are tolerated (warned,
not rejected) so operators can template one config across environments and just
flip the policy. See [cloud deployment](cloud-deploy-design.md)
for the full deployment-shape rationale.

This policy controls whether atakit-portal submits a session and whether serving
is gated on chain verification. Registration policy does not disable client-side TLS
verifier reads from a configured Automata chain/collateral source; a verifier
may still use the chain RPC to fetch measurement policy, trust roots, and
collateral while sending `registration = "off"` to the portal.

#### `registration` default resolution

This is the one subtle part of the contract. The default depends on whether the
`chain` section exists at all:

| Wire JSON | Resolved `registration` |
|---|---|
| no `chain` section | `off` (pure off-chain) |
| `chain` present, no `registration` field | `required` (matches legacy `cvm-agent`) |
| `chain.registration = "required" \| "optional" \| "off"` | that value |
| `chain.registration` = anything else | parse error (`unknown variant`) |

The producer mirrors this: the CLI omits `registration` from the JSON when the
operator left it unset in `[chains.<name>]`, so a config that predates this field
keeps the portal's "section present, no field → required" default. The CLI always
emits a `chain` section (it always resolves a named chain), so the "no chain
section → off" branch is reached only by hand-rolled configs, not by `atakit`.

#### Transaction submission

atakit-portal is the only transaction owner. It fills gas fields, asks its
supervisor-held `gas_wallet` to sign, broadcasts the transaction, retries
failures, checks receipts, and polls `isSessionActive`. The strict schema rejects
`chain.transaction_submitter`.

### Keys

`owner_key` and `gas_wallet` share one shape, matching the on-chain
`PublicIdentity` model (`typeId` + key):

```json
{ "mode": "provisioned", "type": "es256k", "private_key": "0x..." }
```

| Field | Type | Notes |
|---|---|---|
| `mode` | enum string | `"provisioned"` (operator supplies the key) or `"self_generated"` (portal mints one at init). |
| `type` | enum string | Key algorithm = on-chain `PublicIdentity.typeId`: `"es256k"` (secp256k1, Ethereum-compatible), `"es256"` (P-256), `"rs256"` (RSA-2048/SHA-256). |
| `private_key` | string (hex) | Required when `mode = "provisioned"`; omitted for `"self_generated"`. |

Role differences:

- **`owner_key`** — signs `registerSession` authorization messages on-chain, and its
  fingerprint is bound into the TPM quote nonce (see
  [trust-chain-spec.md](trust-chain-spec.md)). Always `provisioned`; `/init`
  rejects a missing `private_key`.
- **`gas_wallet`** — the relayer key that signs the on-chain transaction and pays
  gas. It is required and non-null. It may be `self_generated` (the portal
  generates it at init) or `provisioned`. The supervisor derives and returns its
  address in the `/init` response.

`prover_credential` is always separate from `gas_wallet`. A selected network
prover requires a separately named `prover_credential`; producers must not use
the gas wallet as a fallback.

### Disks

`disk_setup` maps manifest disk names to one-time operator permissions:

```json
"disk_setup": { "secrets": "create", "appdata": "overwrite" }
```

`create` rejects detected disk metadata; it can still erase unrecognized raw
data. `overwrite` explicitly permits erasing existing data, including detected
formats. Without either permission, the portal only opens existing disks. The
portal consumes permission before the first destructive write; reboot never
repeats a completed overwrite.

`/init` rejects nonempty `disks` entries. Passphrases use the owner-signed `POST /disks/{name}/unlock` endpoint on port 2024 on first boot and every reboot. They are never stored in `init-config.json`. Passphrase-enabled workloads require a provisioned owner key. See [Disk unlock](disk-unlock-spec.md).

## Producer: how `atakit` assembles it

The CLI builds `InitConfig` (in `atakit-cloud::init`) from named TOML sections
plus per-deploy CLI flags, then `build_portal_config_json` renders the wire JSON.

| Wire field | Source |
|---|---|
| `format` | constant `4` |
| `platform.declared` | cloud deploy: `[cloud.providers.<name>].platform` of the target's provider. Local (`workload init`): `--platform` flag. |
| `chain.*` | `[chains.<name>]` — resolved name from `--chain`, else persisted deploy state, else `[cloud.targets.<t>].chain`, else `[cloud.defaults].chain`. |
| `owner_operations.*` | top-level `[owner_operations]` strict shared operator configuration. |
| `owner_key.*` | `[keys.<name>]` — resolved from `--owner-key` / target / `[cloud.defaults].owner_key`. `private_key` resolved from the key's `file` / `command` / `env` source. |
| `gas_wallet` | `[keys.<name>]` — resolved from `--gas-wallet` / target / defaults. `private_key` is included only when `mode = provisioned`. |
| `disk_setup.<name>` | Verified fresh AWS/Azure/GCP deployment disks receive conditional automatic `create` permission; otherwise `--disk-setup NAME=create` or `--disk-setup NAME=overwrite`. |

A saved cloud deployment remains bound to the effective
`[cloud.targets.<name>]` configuration used to produce this request. Operators
MUST NOT change that target, its inherited `[cloud.defaults]` values, or its
referenced provider, chain, key, and prover entries while the deployment
exists. A configuration change requires a new target name and a new instance.
Commands that operate on the saved deployment intentionally resolve the same
named configuration; configuration drift is unsupported and may fail closed.

Relevant TOML shapes (see `atakit-cli/src/config.rs`):

```toml
[chains.testnet]
rpc_url           = "https://..."
session_registry  = "0x..."
workload_registry = "0x..."   # optional; derivable from session_registry on-chain
base_image_registry = "0x..." # optional; derivable from session_registry on-chain
# registration    = "required" | "optional" | "off"   # optional; omitted → portal default
# chain_id        = 11155111                            # optional; portal reads rpc_url

[owner_operations]
op_expiry_seconds = 300
challenge_expiry_seconds = 60
max_request_body_bytes = 1048576
max_waiting_requests = 64
max_completed_request_statuses = 256
request_status_retention_seconds = 3600

[keys.owner]
type = "es256k"
mode = "provisioned"
file = "~/.config/atakit/owner.key"   # exactly one of file / command / env

[keys.gas]
type = "es256k"
mode = "self_generated"               # no source fields allowed

[cloud.providers.gcp]
platform = "gcp"
```

Producer-side validation happens **before** any upload, so the operator gets a
fast local error rather than a mid-boot `/init` failure:

- `--disk-setup` checks names, actions, and duplicate entries before upload. `--disk-passphrase` is rejected; secrets use the disk-unlock endpoint.
- `[keys.<name>]` source consistency: `provisioned` needs exactly one of
  `file`/`command`/`env`; `self_generated` must set none.
- `workload_registry` / `base_image_registry` must resolve for the chosen chain.

## Consumer: validation at `/init`

The portal (`atakit-portal-api/src/init.rs`) parses and validates in this order;
any failure transitions the CVM to terminal `Failed`. Validation errors are 400
(operator's fault) with a machine-readable `code`; infrastructure errors are 500.

1. **JSON parse.** Malformed JSON → `invalid_config`.
2. **Renamed-field guards.** Explicit rejection with a migration hint for:
   - `chain.session_ttl_seconds` → use workload `sessionTtl` policy.
   - `chain.register_cvm_expire_offset` or `chain.expire_offset` →
     `owner_operations.op_expiry_seconds`.
3. **Schema deserialize** into `InitConfig`. Unknown disk fields rejected.
4. **`format == 4`** else `format_unsupported`.
5. **Registration preconditions** per the [policy table](#registration-policy):
   `required` and `optional` need `rpc_url` + `session_registry`; `off` warns
   on populated chain fields.
6. **Disk validation:** `runtime_disks` must name declared disks and use supported queue modes; bypass requires encryption. `disk_setup` names must exist in the manifest and actions must be `create` or `overwrite`. Nonempty `disks` entries and passphrase-enabled workloads without a provisioned owner key fail with `invalid_config`.

### Error codes

`POST /init` returns these `code` values for init-config problems (full endpoint
error list in [portal-api-spec.md](portal-api-spec.md)):

| `code` | Meaning |
|---|---|
| `already_initialized` | A `/init` was already accepted this boot (409, one-shot). |
| `invalid_config` | Bad JSON, missing `config` part, renamed field, or a registration precondition not met. |
| `format_unsupported` | `format != 4`. |
| `disk_encryption_method_unsupported` | Manifest declares `keyfile` or `kms` unlock (not yet supported by the portal). |
| `platform_mismatch` | `platform.declared` contradicts DMI auto-detect. |

## Persisted form (`init-config.json`)

On success the portal sends `PersistInitConfig` to the supervisor, which writes
`init-config.json` to the RW partition root (`PortalPaths::init_config_json`).
`PersistedInitConfig` carries only what reboot needs:

| Persisted field | Source | Why it's kept |
|---|---|---|
| `platform` | wire `platform.declared` | Re-run the DMI cross-check on every boot. |
| `chain` | wire `chain` (full `ChainConfig`) | Drives the chain-submitter and `/status.chain` after reboot. |
| `owner_operations` | wire `owner_operations` | Restores owner-operation bounds and retention after reboot. |
| `prover` | wire `prover` | Restarts and negotiates the selected daemon before workload recovery. |
| `pcr_policy` | wire `pcr_policy` | Reuses the exact collection policy after reboot when no active chain policy is available. |
| `session_ttl_seconds` | **manifest** `config.session_ttl` (not the wire config) | Session validity window the portal enforces. |
| `disk_setup` | wire `disk_setup` | Pending one-time disk creation permissions; each entry is removed before formatting. |
| `local_ssd` | wire `local_ssd` | Workload disk name and expected Local SSD count. Portal uses this selection on reboot; array membership lives in disk metadata. |

What is **not** persisted here:

- **Private keys** (`owner_key.private_key`, `prover_credential.private_key`,
  and `gas_wallet.private_key`). These go through
  the separate `PersistKey` RPC and are stored by the supervisor outside
  init-config.json. The prover credential uses `prover-credential.key`.
  The wire `mode` / `type` are consumed at init and not needed verbatim on reboot.
- `format`, `owner_key`, `gas_wallet`, and `prover_credential` objects.

On reboot the portal reads `init-config.json` to resolve the cloud configuration. It tries TPM unlock and waits for passphrases through the persistent disk-unlock endpoint when needed.

The portal parses persisted configuration with the current strict field
definitions. It does not migrate old portal configuration. An old or unknown
field fails startup.

## Versioning

- `format` is the single version gate. Only `4` is accepted today.
- `GET /status` reports `init_schema_version = 4`. `atakit` checks this value
  before the one-shot `POST /init` and refuses portals that report another
  version or omit the field. It separately checks
  `init_timeout_mode = "portal-enforced-non-transfer-v1"` for the transport
  timeout behavior; this does not change the init configuration format.
- Field renames are handled with explicit rejection + migration hints rather than
  silent acceptance (see [validation](#consumer-validation-at-init) step 2). History:
  - `chain.session_ttl_seconds` is rejected; session lifetime belongs to the
    workload `sessionTtl` policy.
  - `chain.register_cvm_expire_offset` and `chain.expire_offset` are rejected;
    use top-level `owner_operations.op_expiry_seconds`.
  - `relay_private_key` → `gas_wallet` (unified key shape).
  - `owner_private_key` → `owner_key` (unified key shape).

## References

- [portal-api-spec.md](portal-api-spec.md) — `POST /init` endpoint mechanics (multipart, ports, response, one-shot).
- [cloud deployment](cloud-deploy-design.md) — registration-policy deployment shapes.
- [atakit-workload-toml-spec.md](atakit-workload-toml-spec.md) — disk declarations and `encryption.unlock_method`.
- [trust-chain-spec.md](trust-chain-spec.md) — how `owner_key` and the chain contracts bind into the TPM quote.

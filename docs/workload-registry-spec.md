# Workload Registry Service Specification

A workload registry is an HTTP service that stores and serves `.atawl` archives. It bridges workload providers (who build and publish) and operators (who deploy to CVMs).

The on-chain [WorkloadRegistry](cvm-registry/) is the authority for workload specs (name, version, PCR specs, owner). The workload registry is a content store for the actual `.atawl` archive blobs, with cached metadata for efficient queries.

## Concepts

**Workload ID.** `keccak256(abi.encode_params(keccak256("CVM_WORKLOAD_V1"), name, version))` - a deterministic bytes32 derived from name and version. Primary key for both the on-chain registry and the workload registry.

**Workload reference.** `name:version` (e.g. `secure-signer:v0.0.1`) - human-readable form, resolved to a workload ID by computing the hash.

**Archive.** An `.atawl` file (tar.zst) containing `manifest.toml`, `measured-data/`, and `images/`. See [atawl-archive-spec.md](atawl-archive-spec.md).

**Integrity model.** PCR23 = SHA-256 of `manifest.toml`, registered on-chain as STATIC matchData. The registry verifies that uploaded archives match the on-chain PCR23 before accepting them.

## Data Model

Per-workload stored data:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `workload_id` | bytes32 | Derived from name+version | Primary key |
| `name` | string | manifest.toml `[meta]` | Workload name |
| `version` | string | manifest.toml `[meta]` | Workload version |
| `owner` | bytes32 | On-chain query at upload | Owner public key fingerprint |
| `sha256` | bytes32 | SHA-256 of manifest.toml | Content integrity hash |
| `archive_size` | u64 | Computed | Size of .atawl in bytes |
| `archive_hash` | string | Computed | SHA-256 of entire .atawl file |
| `uploaded_at` | timestamp | Server time | When the archive was uploaded |

All fields except `uploaded_at` are independently verifiable. Metadata is immutable - once uploaded, it never changes (the on-chain spec for a given workload ID is immutable).

## HTTP API

### `PUT /v1/workloads/{workload_id}`

Upload an `.atawl` archive.

Request: `Content-Type: application/octet-stream`, body = raw `.atawl` bytes.

Registry verification steps:

1. Parse `workload_id` from URL (hex-encoded bytes32, with or without `0x` prefix)
2. Read archive, locate and extract `manifest.toml`
3. Compute PCR23 = SHA-256(manifest.toml)
4. Parse manifest: extract `name` and `version` from `[meta]`
5. Derive workload ID from name+version, verify it matches the URL parameter
6. Query on-chain: `get_workload_spec(workload_id)` - must exist
7. Verify on-chain spec's PCR23 matches computed PCR23 (the STATIC matchData for pcrIndex 23)
8. Query on-chain: `get_workload_owner(workload_id)` - store owner fingerprint as metadata
9. Compute archive hash (SHA-256 of entire file)
10. Store blob and metadata atomically

Responses:

| Status | Meaning |
|--------|---------|
| `201 Created` | Success; body = JSON metadata |
| `400 Bad Request` | Invalid workload ID, corrupt archive, manifest parse error, or ID mismatch |
| `404 Not Found` | Workload not registered on-chain |
| `409 Conflict` | Archive already exists for this workload ID |
| `413 Payload Too Large` | Archive exceeds size limit |
| `502 Bad Gateway` | Failed to query on-chain data |

### `GET /v1/workloads/{workload_id}`

Download the `.atawl` archive.

Response headers:
- `Content-Type: application/octet-stream`
- `Content-Disposition: attachment; filename="{name}-{version}.atawl"`

Also supports `Accept: application/json` to return metadata only (same as `/meta`).

| Status | Meaning |
|--------|---------|
| `200 OK` | Blob or metadata |
| `404 Not Found` | Workload not in registry |

### `GET /v1/workloads/{workload_id}/meta`

Get metadata for a single workload.

Response body:

```json
{
  "workloadId": "0x...",
  "name": "secure-signer",
  "version": "v0.0.1",
  "owner": "0x...",
  "sha256": "0x...",
  "archiveSize": 12345678,
  "archiveHash": "sha256:abcd...",
  "uploadedAt": "2025-03-21T12:00:00Z"
}
```

### `GET /v1/workloads`

List workloads with optional filters.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `owner=0x...` | Filter by owner fingerprint |
| `name=foo` | Filter by exact workload name |
| `name_prefix=foo` | Filter by name prefix |
| `limit=N` | Max results (default 50, max 200) |
| `offset=N` | Pagination offset |

Response body:

```json
{
  "workloads": [ ...metadata objects... ],
  "total": 42
}
```

### `DELETE /v1/workloads/{workload_id}`

Remove a workload from the registry. Optional - registries may choose to be append-only.

| Status | Meaning |
|--------|---------|
| `204 No Content` | Deleted |
| `404 Not Found` | Not in registry |

### `GET /v1/health`

Health check. Returns `200 OK` with `{"status": "ok"}`.

## Storage Layout

```
<data_dir>/
  workloads/
    <workload_id_hex>/
      archive.atawl
      meta.json
```

Each workload gets a directory named by its hex workload ID (without `0x` prefix). The directory contains the blob and a JSON metadata file. Listing is done by scanning directories and reading `meta.json` files (with optional in-memory index for performance).

## Error Handling

The registry returns structured JSON errors:

```json
{
  "error": "workload_not_found",
  "message": "no workload registered on-chain for ID 0x..."
}
```

Error codes:

| Code | Meaning |
|------|---------|
| `invalid_request` | Malformed workload ID or missing fields |
| `invalid_archive` | Corrupt archive, manifest parse error, ID mismatch |
| `workload_not_found` | Workload not registered on-chain |
| `workload_exists` | Archive already uploaded for this workload ID |
| `chain_error` | Failed to query on-chain state |
| `payload_too_large` | Archive exceeds size limit |

## Security Considerations

**No authentication required for uploads.** Security comes from on-chain verification: the archive must match the PCR23 registered on-chain by the workload owner. A malicious upload with wrong content is rejected at step 7 (PCR23 mismatch).

**Integrity verification.** Operators can independently verify a downloaded archive by computing PCR23 (SHA-256 of the extracted `manifest.toml`) and comparing with on-chain data. The CLI `pull` command does this automatically when `--verify` is passed and RPC is configured.

**Immutability.** A given workload ID maps to exactly one archive. The on-chain spec is immutable, and the registry rejects re-uploads (409 Conflict). To update a workload, publish a new version.

**Availability.** Multiple registry instances can serve the same workloads. Operators configure which registry to use. Since uploads are verified against the chain, any registry that passes verification is equally trustworthy.

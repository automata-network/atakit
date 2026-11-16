# v0.3.7 unmeasured-data updates

The instance owner can replace all declared unmeasured-data from a local folder.
The VM and persistent disks stay in place. The replacement activates on the next
kernel boot. Service, worker and supervisor restarts within the same boot do not
activate it. Services retain their existing read-only views.

This requires a Portal image containing the v0.3.7 implementation. The workload
manifest format and measurement do not change. Published workloads without a
deployed instance have no active or pending update state.

## CLI

```sh
atakit cloud unmeasured-data update my-aws/tool-node --check
atakit cloud unmeasured-data update my-aws/tool-node
atakit cloud reboot my-aws/tool-node
atakit cloud unmeasured-data status my-aws/tool-node
atakit cloud unmeasured-data discard my-aws/tool-node
```

`update` defaults to `./unmeasured-data`. Use `--unmeasured-data-root DIR` to
select another folder. Use `--target NAME` instead of the target prefix if desired.
`--check` is optional: `update` also previews its input. All commands support
`--json`. There is no separate apply command, automatic reboot, or extra staging
confirmation. `cloud reboot` currently supports AWS; other providers use their
normal reboot mechanism.

Both update modes fetch the exact manifest from verified Portal. The client
checks the saved workload identity and the manifest measurement when the
workload is bound. Failed startup resets PCR23; that case relies on the trusted
supervisor's stored manifest integrity check. A returned hash alone is not a
trust source. Manual TLS verification overrides are rejected.
Before connecting on AWS, Azure or GCP, the CLI reads the current public address
and VM identity together from the cloud provider and checks the saved VM identity.
This handles address changes after stop/start without contacting a stale address
or adopting a replacement VM. Missing identity, failed lookup or missing public
address stops the command. QEMU keeps its saved local port mappings.

The shared `--trusted-workload-pcr23-sha256` and
`--trusted-workload-pcr23-sha384` flags must be supplied together. In explicit
verification mode, all commands in this group compare both supplied values with
the measurements calculated from the exact fetched manifest before collecting
files or signing a request. This comparison also applies to `--check` and failed
startup recovery, and needs no local `.atawl`. Chain and signed trust-pack modes
reject these manual values, following the existing verification authority rules.
Portal checks the signed `manifest_hash` against its stored manifest; these flags
do not add fields to the API.

No local `.atawl` is required. Preview runs locally against the fetched manifest.
It lists only included local paths and their count. It makes no stored-data
comparison. `--check` needs a connection for metadata verification but no owner
key and uploads no data. The client captures local file bytes once per invocation;
preview, validation and upload use that capture. A prior `--check` does not freeze
a later command's input.

Example preview:

```text
Instance: my-aws/tool-node
Source: ./unmeasured-data
Mode: replace entire unmeasured-data directory
Only manifest-declared files are included. Other local files are ignored.

Files in replacement:
  secrets/monitoring.env
  config/monitoring.yml

Declared files absent from this folder will be absent after restart.
Any existing pending update will be replaced.
Local validation passed. 2 files in replacement.
Nothing saved.
```

Saving reports `Replacement saved. Waiting for VM restart.` Status reports only
`last_update` (`none`, `applied`, `discarded`), whether pending exists, and a
separate workload startup result. Applied means boot selected the replacement;
it does not mean values differed or services became ready.

## Shared collection and validation

Deployment, update and preview use `atakit_core::unmeasured_data` for collection,
env parsing, archive creation and validation. Portal uses the same content checks
and staging helpers at deployment and update. Runtime env parsing shares these
rules too. Portal always validates independently of the client.

| Input | Result |
|---|---|
| Present declared file | Include its complete exact bytes. |
| Declared file absent locally | The file is absent after activation. |
| Undeclared local file | Skip it without reading its contents. |
| Undeclared uploaded file | Reject the whole upload. |
| Existing folder containing zero declared files | Explicit empty replacement, including extras-only folders. |
| Missing source folder or unreadable selected file | Reject; preserve existing active and pending data. |

An empty replacement previews that all unmeasured-data files will disappear.
Missing or truncated request bodies never mean clear-all. Each accepted update
replaces the whole previous pending directory. There is no merge, `--delete`,
`--only`, or per-variable edit. Empty values, empty files and absent files differ.
Existing env precedence still applies; another source can supply an omitted key.

Reject unsafe paths, symlinks, hard links, special files, duplicate archive paths,
invalid env syntax, duplicate env keys, undeclared env names and reserved
`ATAKIT_*`/`VERIFIERD_*` names. Source reads traverse directory descriptors without
following child symlinks. Do not echo values in errors. Set fixed permissions;
never adopt archive ownership, modes or special bits.

Unmeasured archive bytes and file contents have no fixed size cap. Available
local storage and boot-partition space constrain uploads. CLI preparation writes
tar/gzip to a private file in the configured Atakit cache directory, then streams
that exact file to Portal. Private initialization records reference a durable
copy beside the existing initialization inputs instead of embedding archive
bytes in JSON. Resume checks the prepared file's exact length and SHA-256;
completion and deployment cleanup remove it.

Portal streams initial uploads to its existing boot-partition upload path and
extracts directly from the file into private disk staging. Updates pass through
the supervisor in chunks of at most 256 KiB; this is a transport frame size, not
a payload-size cap. The global 10 MiB supervisor-message limit stays in force.
The supervisor receives updates into an anonymous private file on the boot
partition, verifies the signed length/hash, then extracts it. Closing the file
removes it, including on abort or process exit. Stored-tree integrity and reboot
checks also stream contents instead of building full-content snapshots.

Existing metadata limits remain: 4,096 archive entries, 65,536 files plus unique
parent directories in the resulting tree (excluding its root), 1 MiB manifest
bytes and paths at most 4,096 bytes. Local collection, upload validation, staging
and activation use the same tree-entry limit. Empty archive directories are
omitted from the resulting tree. Verify the compression trailer, complete
entries, tar end markers and absence of unsupported trailing data. Preserve
accepted active and pending trees when storage fills or validation fails.

Initial deployment retains its existing source selection and explicit no-data
choice. Once selected, folder validation uses the shared rules. Deployment checks
local input before VM provisioning.

## API and owner authorization

All routes use the persistent Portal HTTPS listener and `Cache-Control: no-store`.

| Route | Authorization and result |
|---|---|
| `GET /workload/manifest` | No owner signature; supervisor-verified exact manifest bytes. |
| `GET /unmeasured-data/challenge` | No owner signature; short-lived challenge and kernel boot ID. |
| `POST /unmeasured-data/update` | Owner signature; raw complete tar.gz body; `{"state":"pending"}`. |
| `POST /unmeasured-data/status` | Owner signature; empty body; `{"last_update":"applied","pending":false}`. |
| `POST /unmeasured-data/discard` | Owner signature; empty body; `{"state":"discarded"}`. |

The owner key resolves from `--owner-key`, then the saved deployment key
reference, then the target key reference. The publisher, gas wallet, cloud
administrator and workload containers gain no update authority from those roles.
Cloud reboot permission is separate. Any later reboot can activate data that the
owner already authorized.

`atakit-data-authorization` contains the hex-encoded exact JSON envelope:

```json
{
  "manifest_hash": "lowercase SHA-256 of exact manifest bytes",
  "boot_id": "current kernel boot ID",
  "challenge": "current one-use challenge",
  "archive_length": 123,
  "archive_sha256": "lowercase SHA-256 of exact uploaded bytes"
}
```

For status/discard, length is zero and the digest covers the empty body.
Unknown/duplicate envelope fields are invalid. The envelope is at most 4 KiB.
`atakit-owner-signature` contains the 65-byte recoverable secp256k1 signature as
hex (optional `0x`), with recovery ID 0 or 1. The prehashed signed message is:

```text
SHA256(length_encode(
    "atakit/unmeasured-data/request/v1",
    lowercase Portal certificate SHA256 hex,
    operation,                 // update, status or discard
    exact authorization JSON bytes
))
```

`length_encode` prefixes each field with its unsigned 64-bit big-endian byte
length. The supervisor independently verifies the signature against its
provisioned owner key, expected manifest, boot, payload length/hash and challenge.
Challenges expire after 60 seconds and bind to the current private operation
counter. Authenticate and consume an update's challenge before receiving its
payload; it must be fresh when the transfer starts. An authorized transfer may
continue after that challenge expires, subject to a 300-second operation deadline
and a 60-second no-progress deadline. Validate the exact signed payload length
and hash before extraction/publication. Consumed, expired or stale challenges
cannot start another request. The counter is not a content revision and is never
returned. Serialize update, discard, recovery and activation; a mutation cannot
replace another update's in-progress upload.

The upload checksum is transient request authentication data. Do not log it,
return it, or use it as a public content identifier. No raw-value, stored-inventory,
content-ID or equality endpoint exists. Do not reveal these through JSON, headers,
debug logs, error details or content-derived ETags. Local submission paths/counts
and operation progress are allowed.

Portal already holds the owner secret for session operations. This feature keeps
that existing trust model; it does not prove external human approval against a
compromised Portal. It does not export another secret to the CLI or worker.

## Private content identity

```text
hmac_key = HKDF-SHA256(
    input = decoded 32-byte owner secret,
    salt = absent,
    info = length_encode("atakit/unmeasured-data/content-id/v1", manifest_hash),
    length = 32 bytes
)
content_id = HMAC-SHA256(hmac_key, canonical_data)
```

`manifest_hash` is the raw 32-byte SHA-256 of the exact deployed manifest.
Use HKDF extract and expand with its standard absent-salt behavior. Never use the
owner secret directly as the content HMAC key. Derive in supervisor memory and
clear the derived key on drop. Persist no separate HMAC secret.

`canonical_data` starts with length-encoded `atakit/unmeasured-data/directory/v1`
and raw manifest hash, then the 64-bit file count. Append sorted normalized
relative paths and exact file bytes, each with its 64-bit length. Ignore local
ownership, modes, timestamps, compression and empty directories. Retain full
256-bit IDs privately. A matching ID never bypasses validation.

Owner, manifest and contents determine identity; no deployment ID or instance
name enters it. `A -> B -> C -> B` returns to the same private ID. Signatures,
not content IDs, bind an operation to one Portal instance. Owner-key rotation is
outside this feature.

## Pending publication and reboot recovery

Default paths:

```text
/atakit-portal/workload/.unmeasured-data.tmp.<pid>/
/atakit-portal/workload/unmeasured-data.pending/
/atakit-portal/workload/unmeasured-data/
/atakit-portal/workload/unmeasured-views/<service>/
/atakit-portal/unmeasured-state.json
```

The last file is supervisor-owned, mode 0600, and outside uploaded data and
service views. It holds private content IDs, pending boot identity, operation
state and interrupted-operation recovery information. It is not an API response.
There is no request-ID directory, random snapshot directory, revision history or
receipt store. PID naming is safe because mutations have one supervisor lock.

Verify owner authorization and the entire upload before extraction. Prepare and
validate the complete temporary tree, fix permissions, calculate its private ID,
and flush files/directories. Journal publication intent before using the shared
backup/rename helper to replace pending. Commit pending state with a flushed
atomic metadata-file replacement. Return success only after the tree and state
are durable. Preserve the previous pending tree until that commit. Never receive
or extract directly into pending. Complete means every file in the signed upload,
not every optional path permitted by the manifest.

An uncommitted pending publication recovers the previously accepted pending
tree. Normal staging never modifies active data, env or service views.

On a different kernel boot, recover first, verify pending and its private ID,
journal activation, then move active to a temporary backup and rename pending to
active. Flush parent directories after each rename. Atomically commit the new
active state, pending removal and applied state together. Remove the backup only
after that commit. Rebuild the existing per-service views and resolve env from the
same active tree before starting services.

If a crash occurs between the renames or before the metadata commit, recovery
finishes that activation from the recorded directory locations. If pending has
already moved to active, finish the state commit without moving active aside
again. After commit, cleanup must not recreate pending or restore old credentials.
Views can be rebuilt again during recovery or normal boot.

```text
Before reboot:  active=A, pending=B
After reboot:   active=B, pending=absent
After reboot2:  active=B, pending=absent
```

Invalid pending data blocks startup. Owner update/discard can request another
startup on a later boot in supported failed states. A startup failure after data
activation does not undo activation. Discard only clears pending. Restoring old
contents requires a new full submission.

Every accepted submission follows the same pending/reboot path, even for identical
or empty contents. No equality-based skip or "no changes" response is allowed.
Latest accepted pending wins. On an ambiguous connection failure, the CLI reports
uncertainty and does not automatically replay with fresh authorization. Status
shows current state; it cannot identify which submission won after intervening
owner operations. Explicit retry is a new complete submission.

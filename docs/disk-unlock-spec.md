# Workload disk unlock

The same endpoint supplies workload-disk passphrases during first initialization
and after reboot. `/init` installs the workload once; it does not accept disk
passphrases. The supervisor does not save disk passphrases in `init-config.json`.
The portal's own RW partition must first unlock through its existing TPM path.

## Trust boundary

Before sending a disk passphrase, the provisioner MUST verify the current
recipient and workload against measurements from an independently trusted
source. Startup success or Portal's status is insufficient. See the
[secret provisioning security notice](secret-provisioning-security-notice.md).

The approved manifest selects each disk's allowed unlock methods. TPM enforces
the policy sealed with the existing key. A passphrase keyslot permits its holder
to decrypt independently of TPM measurements. Both methods mean either can
unlock; they are not two required factors. No new recovery authority or policy
override is introduced.

Passphrase disks require a provisioned owner key at initialization. The owner
signature authorizes a request; it does not replace the disk passphrase or enable
passphrase unlock on a TPM-only disk.

## Creation permission

The operator may include this separate, non-secret field in `/init`:

```json
{"disk_setup":{"database":"create","scratch":"overwrite"}}
```

Names must exist in the manifest. Omission means open existing only. `create`
formats a disk only when no filesystem, encryption, RAID, or partition metadata
is detected. The probe uses libblkid and bounded header checks, including backup
GPT headers. Detected or conflicting signatures and read/probe errors prevent
creation. It does not require zero-filled bytes: fresh AWS EBS disks may contain
pseudorandom filler. It does not scan the whole device.

Unrecognized raw data can look identical to blank-disk filler and may be erased.
`create` does not promise to preserve such data; CLI help and confirmation output
state this limitation. `overwrite` explicitly permits erasing detected formats
as well and prints an operator warning. AWS, Azure and GCP deployment conditionally grants `create` for verified newly created empty
disks. It checks provider identity and attachments before sending `/init`; a
planned disk name alone grants nothing. `overwrite` is always explicit. See
[cloud disk configuration](cloud-disk-configuration.md).
These workload permissions do not change the platform RW-partition checks.

CLI equivalents, repeated for each disk:

```sh
--disk-setup database=create
--disk-setup scratch=overwrite
```

Alternatively, use `--overwrite-all-disks` with `cloud deploy`, `cloud init`,
or `workload init` to authorize overwriting every disk declared by the workload.
The CLI warns for each disk and expands the flag into named `overwrite`
permissions. It never includes the boot disk or portal RW partition. The flag
cannot be combined with `--disk-setup`, `--image-only`, or a workload with no
disks. The same one-time permission rules apply.

Permission is consumed in saved configuration before the first destructive
write. An interrupted creation is not automatically repaired or reformatted.
Inspect the disk and supply fresh explicit permission through a new deployment
initialization before trying again. An unlock request alone cannot authorize
creation or overwrite.

## Startup

The supervisor verifies and binds the manifest before opening workload disks.
It selects owner queue settings for this kernel boot before unlock, then verifies
the active encryption flags before mounting. See
[cloud disk configuration](cloud-disk-configuration.md#portal-protocol-and-enforcement).
On reboot, the worker starts the persistent HTTPS listener before waiting for
workload disk unlock. It reports this boot's startup state, not the previous
boot's `Running` state. Listener failure stops startup instead of leaving it
waiting for requests that cannot arrive.
It tries TPM where configured. A new disk with a passphrase keyslot needs a
passphrase before creation starts, including when TPM is also configured.

If any required disk needs a passphrase, the portal enters `AwaitingDiskUnlock`.
No workload containers start until all required disks are mounted. `GET /status`
on the status/API port reports a `disks` object keyed by manifest disk name:

```json
{"state":"AwaitingDiskUnlock","disks":{
  "database":{"state":"awaiting_passphrase"},
  "uploads":{"state":"mounted"}
}}
```

While a disk operation runs, its entry also reports `operation` and
`elapsed_seconds` for the current operation. Operations are `resolving_device`,
`checking_disk`, `setting_up_encryption`, `formatting_filesystem`, `unlocking`,
`mounting`, `waiting_for_supervisor`, and `waiting_for_passphrase`. These public
fields contain no secrets and do not authorize disk actions. The supervisor
publishes progress separately from its blocking disk RPC, so `/status` remains
readable during formatting. The CLI shows a spinner and elapsed time on a
terminal, or periodic lines otherwise. These operations do not expose reliable
byte counters, so the CLI does not invent percentages. Reconnecting with resume
or live status reads the current operation without restarting it.

Per-disk states are `pending`, `awaiting_passphrase`, `unlocking`, `mounted`, and
`failed`. Status contains no passphrases, their hashes, or authorization signatures.

For passphrase workloads, `/init` returns after installation and startup
continues in the background. The portal pauses its remaining initialization
budget while waiting for disk unlock, then resumes it. The CLI's configured
wait limit still applies; a client exit does not resend `/init` or erase disks.
The portal can continue waiting for a later unlock command.

## Endpoint

Use the persistent status/API listener, port **2024** by default, not port 1024.

1. `GET /disks/{name}/unlock` obtains a challenge for a waiting disk.
2. `POST /disks/{name}/unlock` supplies the passphrase and owner authorization.

GET returns `challenge` (32 random bytes encoded as 64 lowercase hex characters)
and `expires_in_seconds`. Challenges last at most 60 seconds and exist only in
memory. GET reuses a still-valid challenge. Reboot invalidates all challenges.

POST body:

```json
{"passphrase":"operator-supplied secret"}
```

POST headers:

- `Content-Type: application/json`
- `Atakit-Disk-Challenge`: the challenge from GET.
- `Atakit-Owner-Signature`: `0x`-prefixed recoverable secp256k1 signature, 65 bytes
  (`r || s || v`; `v` is 0/1 or 27/28).

The signed digest is SHA-256 of these concatenated length-prefixed components:

1. UTF-8 `ATAKIT_DISK_UNLOCK_V1`.
2. Lowercase hex SHA-256 fingerprint of the attested TLS certificate, no `0x`.
3. UTF-8 manifest disk name.
4. UTF-8 challenge string.
5. Raw 32-byte SHA-256 digest of the exact POST body bytes.

Each length is an unsigned 64-bit big-endian byte count. Sign this digest
directly, without an Ethereum personal-message prefix. This binds authorization
to the certificate, disk, challenge, and exact secret-bearing request.

POST accepts at most 8 KiB of JSON and a nonempty passphrase of at most 4096 UTF-8
bytes. Unknown body fields are rejected. The challenge is consumed before an
unlock attempt. A retry must fetch a fresh challenge.

Successful requests return `200` with `{"state":"mounted"}` only after mounting.
An already mounted disk returns success for an authenticated request without
changing it. Wrong passphrases return `422` and leave the disk waiting. Invalid
authorization returns `401`; non-waiting or failed disks return `409`; unknown
disks return `404`. Malformed or oversized requests return `400` or `413`.
Errors do not echo the request body or raw supervisor errors.

Each disk has at most one accepted unlock in flight. Accepted operations finish
even if their HTTP client disconnects. Failure teardown disables new unlocks
and drains accepted operations before closing disk mappings. A failed format or
filesystem mount fails startup; it is not treated as another password prompt.

## CLI

```sh
atakit cloud disk unlock my-target/my-instance --disk database
atakit cloud disk unlock my-target/my-instance --disk uploads
atakit workload disk unlock 192.0.2.10 --disk database \
  --workload publisher/my-workload:v1 --owner-key my-key --chain test-chain
```

The command verifies portal TLS attestation, checks the workload identity, and
compares both PCR23 banks with the selected local archive. PCR23 is the TPM
measurement that binds the workload manifest. The CLI reads current measurements
through the pinned TLS connection and trusts the approved portal to report them;
this is not a separate signed workload quote. The saved archive must match the
deployment's recorded hash. The command prompts without echo and signs with the
configured provisioned owner key. `--owner-key` overrides the saved key name.
The disk-unlock command also accepts saved `Deploying` records, so a cancelled
deployment prompt can be resumed without resending `/init`. It still requires
an available portal address and verifies the portal and workload before sending
secrets. Session commands retain their existing `Deployed` requirement.
It does not accept passphrases in command arguments. Manual TLS overrides are
not allowed for delivering disk secrets.

`workload disk unlock HOST` works without a saved cloud deployment, including
after reboot or a cancelled `workload init` prompt. `--workload` selects a local
archive or a reference in the local workload store. Use `workload pull` first if
the archive is not available locally. The command uses the same portal
attestation, workload identity, PCR23 checks, and signed unlock request as
`cloud disk unlock`. It never resends `/init`. The default HTTPS port is 2024;
`--port` overrides it. Supply trust through `--chain` (or the cloud default)
or a signed `--measurements` pack and its trust inputs.

`cloud deploy`, `cloud init`, and `workload init` use the same endpoint to prompt
for waiting disks after `/init`. Without an interactive terminal, use a separate
interactive disk-unlock command. The old `--disk-passphrase` initialization flag
returns an error directing the operator to disk unlock.

Terminal input is cancellable. The CLI restores terminal settings on timeout
or cancellation, and serializes prompts when deploying to multiple targets.
Every prompt shows the destination host and port as well as the disk name.
Backspace removes a complete UTF-8 character.
Temporary status failures are retried within the existing initialization
deadline. Measurement responses have a separate 16 MiB bound because they
include firmware and IMA event logs; status and unlock responses retain their
64 KiB bound.

Application-owned passphrase buffers and IPC serialization buffers are erased
on release. No secret is written to disk or included in status/log summaries.
The outgoing HTTP body retains an erase-on-release owner without copying the
JSON into an ordinary buffer. The portal takes ownership of the raw request
body in an erase-on-release container before validation. This does not promise
erasure of internal TLS, HTTP-library, or operating-system buffers.

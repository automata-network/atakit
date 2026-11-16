# Authenticated initialization

`POST /init` requires a dedicated initialization key when the operator supplies
a public bootstrap at provisioning. Without a bootstrap, initialization accepts
unsigned requests. This key is
separate from `owner_key`, `gas_wallet`, and workload publisher keys. Workload
archive format 8 does not change.

## Initial trust

By default, `atakit cloud deploy` creates a random secp256k1 signing key on the operator's
machine. It stores the private credential in
`<data-dir>/cloud/init-keys/<deployment-id>.json`, with file mode 0600 and
directory mode 0700. The deployment state stores the file path, not the key.

`atakit cloud deploy --unauthenticated-init` omits both the credential and public
bootstrap. This choice also applies with `--skip-init` and `--image-only`.
Later, `atakit cloud init` uses the saved credential when present, or sends an
unsigned request when no credential was provisioned. A missing or unreadable
credential file referenced by deployment state is an error, not a fallback.

Only public initialization data goes to the new VM:

| Provider | Launch input | Portal reads |
|---|---|---|
| GCP | Instance metadata key `atakit-init-auth` | `/computeMetadata/v1/instance/attributes/atakit-init-auth`, with `Metadata-Flavor: Google` |
| Azure | Provisioning JSON through `az vm create --user-data` | `/metadata/instance/compute/userData?api-version=2021-02-01&format=text`, with `Metadata: true`; decode standard Base64, then read `atakit.init_auth` |
| AWS | Provisioning JSON through `aws ec2 run-instances --user-data` | `/latest/user-data`, after obtaining an IMDSv2 token; read `atakit.init_auth` |
| QEMU | SMBIOS type 11 string `atakit-init-auth=<JSON>` | The SMBIOS type 11 record in sysfs |

AWS and Azure user data use this extensible document:

```json
{
  "format": 1,
  "atakit": {
    "init_auth": {
      "format": 1,
      "scheme": "atakit-init-es256k-v1",
      "deployment_id": "<64 hexadecimal characters>",
      "public_key": "<compressed SEC1 public key in hexadecimal>"
    }
  }
}
```

The outer `format` versions the provisioning document. The inner `format`
belongs to the existing public bootstrap. Other fields at the document root
and inside `atakit` are allowed and ignored by initialization authentication.
Omitting `atakit` or `atakit.init_auth` allows unsigned initialization.
An explicit null or invalid `atakit`/`init_auth`, malformed JSON, unsupported
document format, or invalid public bootstrap stops startup. Duplicate known
fields are rejected. The decoded document limit remains 4096 bytes.
GCP, QEMU, and `--init-auth-file` still carry the public bootstrap directly.

Azure user data is not Azure resource tags or custom data. The Azure CLI accepts
a string or file and handles encoding. AWS `run-instances` also encodes its
user-data input. See the [Azure CLI input definition](https://github.com/Azure/azure-cli/blob/dev/src/azure-cli/azure/cli/command_modules/vm/_params.py)
and [AWS user-data documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html).

For an AWS VM that `atakit cloud deploy` creates with this bootstrap, the launch
request sets `HttpEndpoint=enabled,HttpTokens=required`. This makes metadata
reads require an IMDSv2 token. It does not authenticate `/init`. Atakit does not
change unrelated VMs or account-wide metadata settings.

The supervisor reads and validates the bootstrap before it starts the worker
or opens the initialization listener. It saves the accepted public document
in `<portal-state-dir>/init-auth/bootstrap.json`, inside a root-only directory.
On another `AwaitingInit` boot it reads that snapshot, not changed metadata.
An absent bootstrap is saved as JSON `null` in the same root-only snapshot, so
the choice also stays fixed across `AwaitingInit` reboots. Provider responses
that mean no bootstrap exists allow unsigned initialization: HTTP 404, empty
Azure user data, or no QEMU bootstrap string. Metadata request failures,
malformed data, or oversized bootstrap data stop startup. The limit is
4096 bytes. Metadata requests use fixed link-local URLs, short timeouts, no
HTTP redirects, and no environment proxy.

This design trusts the operator's machine, cloud account, cloud provider, and
VM launch settings to deliver the right public key. Someone who can replace
the bootstrap before the supervisor saves it can authorize their own init.
Metadata is not proof of ownership. TLS attestation proves the portal's
identity; the saved key fingerprint check ties that portal to this deployment.

## Request protocol

1. The client verifies and pins the portal's TLS certificate using the existing
   attestation flow. Cloud initialization rejects `--unsafe-skip-tls-attestation`.
2. The client requests `GET /init/challenge` on the status port. The response
   contains `scheme`, `deployment_id`, `key_fingerprint`, `tls_fingerprint`,
   `challenge`, and `expires_in_seconds`. It uses `Cache-Control: no-store`.
3. The client checks the deployment ID, public key fingerprint, and TLS
   fingerprint against its local credential and verified certificate.
4. The client signs the exact intent JSON described below. It sends that
   signature in `Atakit-Init-Authorization` with the multipart `POST /init`.
5. The worker verifies the signature, challenge, TLS fingerprint, and signed
   headers before multipart parsing and before claiming the one-shot gate.
6. The worker checks the uploaded bytes against the signed hashes before it
   uses the configuration, downloads a remote archive, or extracts data.

The bootstrap contains `format: 1`, `scheme: "atakit-init-es256k-v1"`,
`public_key` (33-byte compressed SEC1 key, hex), and `deployment_id` (32 random
bytes, hex). The key fingerprint is SHA-256 of the compressed public key.

The signed intent contains:

- `deployment_id`, `tls_fingerprint`, `challenge`, and `transfer_id`.
- `archive_sha256`, `archive_size`, and `workload_id`.
- `config_sha256`: SHA-256 of the exact `config` part bytes.
- `unmeasured_sha256`: SHA-256 of the exact `unmeasured-data` part, or null.
- `source_sha256`: SHA-256 of the exact remote archive descriptor, or null for
  a binary upload. This also commits to the download URL.
- `transfer_timeout` and `init_timeout`, in positive whole seconds.

Digests use plain hex, without `0x`. The authorization value is
`hex(intent-json).hex(signature)`. The signature uses ECDSA with secp256k1 and
SHA-256 over `ATAKIT_INIT_AUTH_V1` followed by a zero byte and the exact intent
JSON bytes. The signature uses the fixed 64-byte `r || s` representation.
The authorization header is limited to 8192 bytes. Unknown intent fields and
duplicate authorization or signed headers are rejected.

Challenges use a fresh random seed on each worker start and monotonic time,
which does not depend on the VM's wall clock. They last 60–120 seconds. Fetching
more challenges does not revoke an existing one. A challenge must be valid
when the request arrives; it need not remain valid throughout a long upload.
Challenges do not survive a worker restart.

Missing or invalid authorization returns HTTP 401 with `init_unauthorized`
and leaves the one-shot gate unchanged. A request with valid authorization
claims the existing one-shot gate. Concurrent or repeated accepted requests
return HTTP 409. A signed request with a bad body still fails initialization;
authentication does not make malformed workloads safe to retry.

`/status` adds an `init_auth` object while the worker holds the bootstrap. It
contains `required`, `scheme`, `key_fingerprint`, `deployment_id`, and
`accepted_transfer_id`. It never returns private key material.

## Delayed initialization and failures

`atakit cloud deploy --skip-init` and `--image-only` retain the private key in
the deployment state. `atakit cloud init` loads it later and obtains a fresh
challenge. There is no deployment-age expiry on the saved key.

If the HTTP response is lost, the client asks the same pinned portal whether
it accepted the exact transfer ID. If it did, the client continues checking
status. It never sends a second init automatically. If it cannot establish
the outcome, it reports uncertainty and retains the deployment and credential.
Check `atakit cloud status` before deciding what to do next. A portal restart
may remove the in-memory accepted transfer ID, so not every lost response can
be resolved automatically.

After the CLI confirms `Running`, it removes the managed private credential
and clears its deployment-state path. `atakit cloud destroy` also removes a
remaining managed credential after successful resource cleanup. Neither path
removes an arbitrary credential outside `cloud/init-keys`.

## Manual and local use

`atakit keys create-init` saves a private credential and prints only public
bootstrap JSON to stdout. It prints the private credential's file path to
stderr. For AWS and Azure, put that JSON inside `atakit.init_auth` in the
versioned provisioning document above. For GCP and QEMU, deliver the public
JSON directly through the provider input above, or give a
public JSON file to `atakit-portal --init-auth-file <file>` for local use.
Pass the private credential path to
`atakit workload init --init-auth-key-file <file>` on the operator's machine.
That command still requires verified TLS. It does not delete manually supplied
credentials after success.

Authentication is an operator choice, not a `baseimage.toml` setting. The same
image supports both modes. Legacy `enable` and `max-clock-drift` fields do not
control this protocol. Without a provisioned key, anyone who can reach `/init`
can attempt to initialize the VM first. TLS verification remains required before
sending secrets; it does not restrict who can initialize the VM.

## Release checks

Unit tests cover signed intent changes, challenge expiry and restart, invalid
requests before multipart parsing, the one-shot race, provider metadata reads,
and local credential storage. Command tests check provider launch arguments.
Before release, test a fresh image on GCP, Azure, AWS, and QEMU, including
`--skip-init`, reboot before init, bad signatures followed by a valid init,
and a dropped init response. Mocked metadata tests do not replace those VM
tests.

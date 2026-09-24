# Native workload emulator

`atakit emulator` runs workloads against a private Anvil fork and a native Portal
socket. Workload processes remain under your IDE, `cargo run`, Node or Python.
Docker is optional.

## Start

Run your development Anvil A first. It may already contain your deployed business
contracts and may itself fork Hoodi. Keep it running with historical states enabled:

```sh
anvil --fork-url https://ethereum-hoodi-rpc.publicnode.com \
  --port 8545 --preserve-historical-states
```

Use the existing atakit global configuration for `chains`, `publish.owner_key`
and signing sources under `keys`. The selected chain's SessionRegistry address is
used unchanged; its getters identify WorkloadRegistry, BaseImageRegistry and the
hardware verifiers. There are no Registry address overrides in the emulator CLI.
Chain selection is CLI/file `chain`, then the selected cloud target’s `chain`
(including `cloud.defaults.chain`), then `publish.chain`, then the sole configured chain.
B inherits A's actual chain ID, including when it differs from the public chain.

```sh
atakit emulator up --workload ./atakit-workload.toml
atakit emulator status --json
atakit emulator env --format dotenv
atakit emulator exec -- cargo run
atakit emulator stop  # save chain/session state for restart
```

`up` starts a managed background process. Use `--foreground` for terminal logs and
Ctrl-C shutdown. Its Anvil B defaults to `127.0.0.1:8546`; `--anvil-port` changes it.
The default Portal socket is created directly at `<runtime>/<instance>/root/run/atakit-portal.sock`.
Use `--output-socket /absolute/path/portal.sock` to override it. No socket alias is created; clients using an override must connect to that explicit path.
Add generated `portal.sock` and the private runtime directory to your project
ignore rules; the emulator does not edit `.gitignore`.

Multiple workloads are explicit at startup and each has its own session/key/socket:

```sh
atakit emulator up --workload signer=./signer --workload api=./api
atakit emulator env --workload signer --format json
atakit emulator exec --workload signer -- cargo run
atakit emulator session rotate --workload signer
atakit emulator session revoke --workload signer
atakit emulator refresh
```

A directory selects only its `atakit-workload.toml`. Without an alias, the TOML
workload name identifies the instance. Multiple instances require a name on
instance-specific commands. To change the list, stop and start with the new list.
Omitted instances retain their chain history; omission does not revoke them.

## Optional emulator TOML

```toml
fork-url = "http://127.0.0.1:8545"
anvil-port = 8546
runtime-dir = ".atakit-emulator"

[[workloads]]
file = "signer/atakit-workload.toml"
name = "signer"

[[workloads]]
file = "api/atakit-workload.toml"
name = "api"
output-socket = "api/custom-portal.sock"
```

```sh
atakit emulator up --config ./atakit-emulator.toml
```

Explicit CLI scalars override the file. Any CLI `--workload` list replaces the
file's entire workload list, including entry-specific overrides. File paths are
relative to the emulator config; CLI paths are relative to the invocation directory.
The file is loaded only when explicitly selected; there is no scanning or watching.

The publisher uses `publish.owner_key`. Session owners resolve from named CLI
`--owner-key NAME=ALIAS`, shared CLI `--owner-key ALIAS`, retained entry owner,
file owner, selected target owner, `cloud.defaults.owner_key`, then `publish.owner_key`. Values refer to
existing `keys` entries with `type = "es256k"` and provisioned file/env/command
sources. Private signing material stays in mode-0600 runtime files.

Use an existing `[cloud.targets.<name>]` from the atakit global config to select
the platform and machine measurements without specifying their Registry names:

```sh
atakit emulator up --workload ./atakit-workload.toml --target my-gcp-tdx
```

When no target is specified and platform/variant selection is incomplete, `up`
automatically checks configured cloud targets against every workload's real Registry
PCR policy. Exactly one compatible target is selected and printed to stderr; multiple
matches list `--target` choices; no matches report a reason for each rejected target.
Multiple workloads must all support the same target, with exactly one usable base-image
policy per workload. Unsupported/revoked policies are not treated as compatible.

Checks run on a temporary fork of your development Anvil, at the requested fork block
(or its current block). Unpublished workloads are registered only on that temporary
fork so the normal Registry policy checks can run. No sessions or Portal sockets are
created there, and the fork is stopped after discovery. Actual startup revalidates the
chosen policies. This checks emulator compatibility, not cloud quotas or availability.
If there are no configured cloud targets, or all workloads already specify both
profile and variant, the existing direct-selection behavior is retained.

Alternatively put `target = "my-gcp-tdx"` at the top level of the emulator TOML.
CLI `--target` overrides that value. One target applies to all workloads in the
launch. Its provider and `vmtype` select `gcp-tdx` and the machine variant
(e.g. `c3-standard-4`). The target's chain and owner are defaults; explicit
emulator chain/owner settings win. An explicit profile or variant must agree
with the target, otherwise startup reports a conflict. Unknown targets/providers
and unsupported platforms fail before starting Anvil. Currently only GCP/TDX
is supported; using a target does not enable other hardware verifiers.

This reads configuration only: it does not create cloud VMs, load cloud credentials,
or use the target's image/registration/gas-wallet settings. Base images still come
from the workload's allowed policy and are validated against the forked Registry.
The upstream RPC remains `--fork-url` / emulator TOML / localhost:8545, not the
public chain RPC. Resolved selections are saved for restart and refresh; changing
the target's effective measurements requires `down` then `up`, or a new runtime.

When a registered base image has several permitted machine variants, select one
without editing the workload's published policy:

```sh
atakit emulator up --workload ./atakit-workload.toml \
  --platform-profile gcp-tdx --measurement-variant c3-standard-4
```

The optional `platform-profile` and `measurement-variant` fields also belong to
individual `[[workloads]]` entries. For multiple instances use CLI `NAME=VALUE`.
CLI selections override retained file entries; replacing the CLI workload list
also drops their file selections. Selection never bypasses Registry constraints;
zero or multiple matches produce a candidate error. A selection change requires
a new runtime directory. The current Hoodi `automata-linux:v0.3.0-debug` image has
four GCP machine variants, so the example needs an explicit measurement variant.

## Native development and persistence

`env` and `exec` preserve the workload's application environment and add these
native-development exports:

- `EMULATOR_RPC_URL`: the emulator's fork RPC endpoint.
- `EMULATOR_ROOTFS`: a per-workload native filesystem root. Each declared storage
  mount-path resolves below it, e.g. `${EMULATOR_ROOTFS}/data` and
  `${EMULATOR_ROOTFS}/data2`; measured and unmeasured data resolve below
  `${EMULATOR_ROOTFS}/atakit-portal/`. Native mappings use symlinks, not kernel
  mounts: read-only restrictions are not enforced. Overlapping mount paths are
  rejected. For Portal-enabled main services,
  `${EMULATOR_ROOTFS}/run/atakit-portal.sock` is the listening socket itself, not a symlink (unless an explicit output-socket override selects another location).
  Compose uses actual container mounts without this prefix.


There is no automatic `DATA_DIR` or `EMULATOR_DATA_DIR`. Application variables
are never overwritten; a collision with a generated export is an error. Map
these host values explicitly, or let the app prefer emulator connection variables
and prepend `EMULATOR_ROOTFS` to its ordinary absolute container paths. Compose
continues to mount storage at its declared container paths, without injecting
these native-development variables. Restart a running emulator with the updated
binary (`stop`, then `up` with the same configuration) to update its exports.

## Runtime directory layout

The default runtime directory is `.atakit-emulator` in the project directory.
Each instance's `EMULATOR_ROOTFS` points to `<runtime>/<instance>/root`, for example
`.atakit-emulator/secure-signer/root`. Frozen configuration, measured data, and env
allowlists are stored alongside `root`. Persistent disks remain under
`<runtime>/data`; `down` removes recorded workload directories without following
root filesystem links into those disks. `stop` retains all state.

Existing `.atakit/emulator` directories are not moved or deleted automatically.
To stop an old instance, use `atakit emulator stop --runtime-dir .atakit/emulator`.
To continue using its checkpoint and disks, also supply
`--runtime-dir .atakit/emulator` to `up` and subsequent commands. A normal `up`
uses the new default and starts an independent environment with new local disks.

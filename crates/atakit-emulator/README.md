# Native workload emulator

`atakit emulator` runs workloads against a private Anvil fork and a native Portal
socket. Workload processes remain under your IDE, `cargo run`, Node or Python.
Native development does not require a container engine. To run workloads in
containers, use Docker or Podman with a compatible Compose provider.
`emulator up` starts the emulator and registers its sessions; it does not start
your application or build its container image.

The currently supported development workflow requires a local
`atakit-workload.toml` whose main workload image includes `build`, for example
`image = { build = ".", containerfile = "Dockerfile" }`. Workloads without
`image.build` are not yet supported as a standalone emulator workflow. This
includes published `.atawl` packages downloaded with `atakit workload pull`;
the emulator does not yet resolve and run packages from the local workload store.
Use the workload's source project for local emulation.


- [Architecture](#architecture) and [prerequisites](#prerequisites)
- [Commands](#command-overview) and [configuration](#optional-emulator-toml)
- [Native development](#native-development-and-persistence) and [Compose](#compose)
- [Business contracts](#business-contracts-and-verification), [cleanup](#editing-restarting-and-cleanup), and [troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Mock boundaries](#contract-boundary), [measurements](#identity-and-measurements), and [implementation](#implementation-map-and-verification)

## Architecture

```text
                  Public chain (e.g. Hoodi)
                              |
                              | fork
                              v
+----------------------------------------------------------+
| User-managed Anvil A                         :8545        |
|                                                          |
| SessionRegistry / WorkloadRegistry / BaseImageRegistry    |
| Business contracts deployed by the developer             |
| State persistence controlled by the developer            |
+----------------------------------------------------------+
                              |
                              | fork at a pinned block
                              | upstream reads only
                              v
+------------------------ atakit emulator ------------------+
|                                                          |
|  +----------------------------------------------------+  |
|  | Emulator-managed Anvil B                  :8546    |  |
|  |                                                    |  |
|  | Inherited registries and business contracts        |  |
|  | Mock DCAP / TPM attestation backends               |  |
|  | Local workload registrations and sessions          |  |
|  +----------------------------------------------------+  |
|             ^                          ^                 |
|             | register / check         | register / check|
|             |                          |                 |
|  +----------------------+  +--------------------------+  |
|  | Portal instance A    |  | Portal instance B        |  |
|  | Workload A session   |  | Workload B session       |  |
|  | Signing / evidence   |  | Signing / evidence       |  |
|  +----------------------+  +--------------------------+  |
|             ^                          ^                 |
|             | Unix socket A            | Unix socket B   |
|                                                          |
|  Runtime: .atakit-emulator/                               |
|    checkpoint + keys + frozen inputs + persistent data   |
+----------------------------------------------------------+
              |                          |
              |                          |
+-------------+------------+ +-----------+-----------------+
| Workload A               | | Workload B                  |
|                          | |                             |
| cargo run / IDE debugger | | Docker / Podman Compose     |
|                          | |                             |
| EMULATOR_ROOTFS paths    | | Container mount paths       |
| Native Portal socket    | | /run/atakit-portal.sock      |
+--------------------------+ +-----------------------------+
              |                          |
              +------------+-------------+
                           |
                           | RPC: verify signatures
                           v
                Business contracts on Anvil B
```

Each workload has its own session and a Portal socket when its main service or
a dependency requests `atakit-portal`, while all workloads in an
emulator share Anvil B. Application processes run separately from the emulator.
Mock installation, local registration, and emulator transactions affect B only;
the developer retains control of A. The diagram shows the default native socket
transport and example ports. Forking A from a public chain is optional when A
already contains the required contracts.

## Prerequisites

- Build/install the current `atakit` CLI and put Foundry's `anvil` on `PATH`.
- Run your own development Anvil with the desired Registry contracts. A public
  RPC alone cannot serve as the emulator's upstream; the upstream must be Anvil.
- Configure `[chains]`, `[publish]`, and ES256K signing keys in the normal atakit
  operator config. The emulator needs the publisher/owner signing material, but
  no funded public-chain gas wallet or cloud credentials for local registration.
- Provide each workload's `atakit-workload.toml` and declared measured/unmeasured
  files. A prebuilt `.atawl` or published container image is not required for
  native development. Compose needs a supported image reference or build source.
- For container execution, install Docker or Podman and a compatible Compose
  provider. `workload-compose` defaults to native socket mounts.

## Command overview

| Command | Purpose |
| --- | --- |
| `up` | Start or resume the emulator daemon, Anvil B, Portal sockets, and sessions |
| `status --json` | Inspect runtime state, registries, RPC, and per-workload results; also list configured chains without a runtime |
| `env --workload NAME --format dotenv` | Print the selected workload's application env and native emulator exports |
| `exec --workload NAME -- cargo run` | Run in the workload directory; external env takes precedence over exported defaults |
| `logs` | Print saved emulator and Anvil logs; `--workload NAME` filters emulator messages, not app output |
| `session rotate --workload NAME` | Rotate the selected session key on B |
| `session revoke --workload NAME` | Revoke the selected session on B and stop serving signatures |
| `refresh` | Re-fork the latest upstream state and create fresh sessions from frozen launch inputs |
| `stop` | Stop the emulator and retain its checkpoint/data |
| `down` | Stop and remove recognized runtime state, retaining data disks |
| `down --purge-data` | Also remove emulator-managed data disks |
| `workload-compose up --build` | Regenerate YAML, then build/start workload containers |
| `workload-compose logs / ps / down` | Forward to Compose using the existing YAML |

Use `--runtime-dir PATH` consistently when managing a nondefault runtime.
`emulator logs` is a snapshot, not a following log stream. Use
`tail -f .atakit-emulator/emulator.log` for the daemon, or
`workload-compose logs -f` for container logs.

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
atakit emulator status
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

Save the configuration as `atakit-emulator.toml` in your project directory:

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

From that directory, `--config` is optional: `up` automatically reads
`./atakit-emulator.toml` when it exists. Start with:

```sh
atakit emulator up
```

Use `--config PATH` only to select a different configuration file:

```sh
atakit emulator up --config ./config/local-emulator.toml
```

Explicit CLI scalars override the file. Any CLI `--workload` list replaces the
file's entire workload list, including entry-specific overrides. File paths are
relative to the emulator config; CLI paths are relative to the invocation directory.
No parent directories are searched and workloads are not auto-discovered. A missing default file is
allowed when workloads are supplied on the CLI; an unreadable or malformed
configuration is an error, including when loaded by default.

Like `atakit workload build`, Emulator uses the invocation directory as the
workload working directory, even when the workload TOML is in a subdirectory.
Build contexts, container build files, environment files, and measured/unmeasured
data are resolved from that working directory. Run `up` from the project root:

```sh
atakit emulator up --workload container/guardian/atakit-workload.toml
```

All selected workloads share this working directory. Its absolute path is saved
at startup; `workload-compose`, `exec`, and `refresh` reuse it even when invoked
elsewhere (with the appropriate `--runtime-dir`). Existing runtimes retain their recorded
paths; use `down` then `up` from the project root to adopt this behavior.


The publisher uses `publish.owner_key`. Session owners resolve from named CLI
`--owner-key NAME=ALIAS`, shared CLI `--owner-key ALIAS`, retained entry owner,
file owner, selected target owner, then `cloud.defaults.owner_key`. A missing owner
is an error, matching cloud deployment with session registration enabled; the
publisher is never implicitly used as the session owner. Values refer to
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
a fresh runtime (`down` then `up`) or a different runtime directory. Available
variants depend on the forked Registry state; use the reported target/candidate
list rather than assuming a fixed set of machine types.

## Native development and persistence

`env` exports the workload's application environment and adds these
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


`exec` fills in only variables absent from the calling environment. External values,
including empty strings, take precedence. When values differ it warns on stderr
with variable names only, never values. This also applies to `EMULATOR_*`; unset
stale exports when switching workloads so each app uses its own root and RPC.
Overrides affect only that process, not TOML, registry measurements, `env` output,
or Compose. For example:

```sh
VALIDATOR_PORT=9002 atakit emulator exec --workload validator -- cargo run --bin validator
```

With no external overrides, `exec` passes the exported defaults to its child; starting an app independently
does not inject them automatically.

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

## Portal API

Portal-enabled services can use these routes on their workload's socket:

- `GET /portal-external-api/status`
- `POST /sign-message`
- `GET /portal-external-api/session/evidence-bundle`

Signing supports Keccak256 and SHA-256; revoked or unready sessions cannot sign.
Other Portal APIs, including baby-container management, are not implemented.
`ip-env` is rejected because the emulator has no VM public/internal network identity.

## Compose

### Native socket mounts

`emulator workload-compose up` binds the host Portal socket directly
to `/run/atakit-portal.sock` for each Portal-enabled service using a read-only,
long-syntax bind mount. It omits `bind.create_host_path: false`, which prevents
socket forwarding setup in the tested Docker Desktop environment. It does not request a
TCP bridge or generate a sidecar, bridge credentials, or socket volume. The source
must exist and be a Unix socket. Socket sharing depends on the selected container
engine and its host or VM setup; Docker Desktop cross-VM connectivity is not
guaranteed.
Native is the default, so no transport option is needed. If socket mounting or
connectivity fails with your container engine, try `--portal-transport bridge`.

```sh
atakit emulator workload-compose --workload secure-signer up --build --remove-orphans
```

For example, regenerate the same file using bridge mode:

```sh
atakit emulator workload-compose --workload secure-signer --portal-transport bridge up --force-recreate --remove-orphans
```

When switching an existing Compose project to native mode, `--remove-orphans`
removes its old bridge container. Recreate the application container after the
emulator replaces its socket (for example, after a restart).

### Run workload containers

Run `up` in the foreground to see application logs directly. Use another terminal
for commands such as `ps`, `exec`, or `down`.

`workload-compose up` regenerates `<runtime>/<workload>/compose.yaml` from the running
emulator before invoking the selected engine's Compose provider. Generation
failures abort the command, including when an older Compose file exists. Other commands reuse that file and
can run while the emulator is stopped. `down` removes workload containers, not
the emulator process or its persistent state.

```sh
atakit emulator workload-compose up --build
atakit emulator workload-compose logs -f --tail 100
atakit emulator workload-compose ps
atakit emulator workload-compose exec secure-signer sh
atakit emulator workload-compose down
```

To select a platform for Docker or a compatible Podman Compose provider, place `--platform` before `up`:

```sh
atakit emulator workload-compose --workload guardian --platform linux/amd64 up --build
```

This writes `platform` on every generated service, including dependencies and
Portal bridges.
Without the option, platform selection is left to the container engine.
The selection is saved in the generated file for subsequent commands; another
`up` regenerates the file, so repeat the option to retain it. Running a foreign
architecture requires support from the container engine. Unlike this local
Compose flow, `atakit workload build` explicitly targets `linux/amd64` for CVM
deployment.

Generation reads the current TOML, image/build context, and application env, while
measured-data mounts use the emulator's saved snapshot. Regenerating YAML does not
update session measurements. Recreate the emulator after TOML or measured-data
changes before generating Compose again.

The Compose provider controls image reuse and building. Use `up --build` after
container source changes; generating YAML alone does not rebuild an image.
Dependency ordering uses `service_started`, not application readiness checks.
Linux uses host networking and rejects host/container port remapping; other hosts
use Compose port publishing. Baby-container requirements are rejected by the
Compose adapter.

Disk encryption settings, including TPM unlock and platform/base-image/workload
bindings, do not prevent local execution. The emulator uses host directories and
does not encrypt, seal, or unlock them. The source TOML and its encryption policy
remain unchanged. Compose preserves `base-path`, `mount-path`, and `read-only` on
the bind mounts; native mappings remain symlinks without read-only enforcement.
Local success does not validate production disk encryption or recovery.

Place Atakit options before the Compose subcommand. The subcommand and its
arguments are forwarded to the selected engine's Compose provider, preserving
argument boundaries, terminal interaction, and exit status. `log` is an alias for
`logs`.

```sh
atakit emulator workload-compose --workload secure-signer up --build
atakit emulator workload-compose --portal-transport bridge up
atakit emulator workload-compose --output .atakit-emulator/custom.yaml up
atakit emulator workload-compose --output .atakit-emulator/custom.yaml logs -f
```

Use `--workload` repeatedly to select multiple workloads when generating the file;
a multi-workload emulator requires explicit selection. Repeat generation options
on subsequent `up` calls. In a multi-workload environment, pass the same workload
selection to `logs`, `ps`, and `down` to locate its existing file. Use the
same `--runtime-dir` and `--output` when accessing a custom Compose file.
To remove a bridge container left from an earlier setup, pass `--remove-orphans`
to `up`.

Each single workload has a separate default file and Compose project identity:

```text
.atakit-emulator/
  signer/compose.yaml
  api/compose.yaml
  compose/<selection-hash>/compose.yaml  # explicitly selected workload group
```

```sh
atakit emulator workload-compose --workload signer up --build
atakit emulator workload-compose --workload api up --build
atakit emulator workload-compose --workload signer logs -f
atakit emulator workload-compose --workload api down

# A combined project; repeat the same set of names for later operations.
atakit emulator workload-compose --workload signer --workload api up
atakit emulator workload-compose --workload api --workload signer down
```

Compose project names use `aemu-<project-directory>-<6-digit-hash>`,
for example `aemu-validator-guardian-82ad61`. The project directory
comes from the saved workload working directory; the hash distinguishes runtime
paths and workload selections. Directory names are normalized to lowercase
Compose-compatible characters. Before upgrading from the previous naming format,
run `workload-compose down` using the existing YAML so old containers are removed.

Group paths and project names are independent of argument order. Separate
workload selections do not overwrite each other's files or share a Compose
project name. Do not run the same workload concurrently in both an individual
project and a group: its ports and data are still the same workload resources.
Application host ports must also remain unique across separately started projects.

When selection is omitted, a single workload is inferred from live status for
`up` or saved endpoint metadata for other commands; several workloads require
`--workload`. Explicit selection works without a running daemon. `--output`
continues to override the path; use distinct custom outputs to avoid overwriting
them yourself.

Older versions used `<runtime>/compose.yaml` and a shared project name. Those
containers are not automatically migrated. Before starting the new scoped
projects, remove the old containers using the original file, for example
`docker compose -f .atakit-emulator/compose.yaml down` (or `podman compose`).
The new wrapper can also access it with `--output .atakit-emulator/compose.yaml`.

`workload-compose` uses the existing `[build].container_engine` setting:

```toml
[build]
container_engine = "auto" # auto, docker, or podman
```

An explicit engine runs `docker compose` or `podman compose` without falling back
to another engine. `auto` reuses the build command's detection: try Podman first,
then Docker. The selected engine must have Compose support installed. The existing
`ATAKIT_CONTAINER_ENGINE` environment override also applies. Use the same engine
for `up`, `logs`, and `down` to manage the same containers.

Run `atakit emulator workload-compose` or add `--help` to see Atakit's wrapper
options followed by live help from the configured engine's `compose --help`.
This lists the commands supported by the installed Compose provider. Neither
an active emulator nor a generated Compose file is needed to view help.
`atakit emulator workload-compose up --help` also forwards directly to the
provider without generating a file or starting containers.

## Business contracts and verification

There are two local chains: your Anvil A (usually port 8545), and the emulator's
Anvil B (usually port 8546). Deploy business contracts to A if you want to retain
and reuse them independently of emulator resets. Use the configured chain's
SessionRegistry address as the constructor argument when your verifier needs it.
Obtain that address from `atakit emulator status`; with no running emulator,
inspect the selected entry in `chains`, and with a running emulator inspect
`session_registry`.

Deploy before `emulator up`, or run `emulator refresh` after deploying to A.
The application must verify session-backed signatures through **B**, because the
emulated workload/session registrations exist there. A contract deployed only on
B is lost by `refresh` or `down`. The emulator has no application-specific contract
deploy script and does not set `SIGNATURE_VERIFIER` for you.

A typical development sequence is:

1. Start A and deploy your business contract on it.
2. Set the contract address in the workload's appropriate measured configuration.
3. Start the emulator and inspect `status`; check the selected workload is `ready`
   and has a `workload_id` and `session_id`.
4. Start the app with `emulator exec`, or `workload-compose up --build`.
5. Call the app's signing API and verify the result against its business contract
   on B. `ready` alone does not prove that your application or business contract works.

Apps can select `EMULATOR_RPC_URL` in both native and Compose runs. Compose injects
it into workload and dependency services, using the fork's port with `127.0.0.1`
on Linux host networking and `host.docker.internal` on other hosts. The container
engine must provide access to host services through that gateway. Do not declare
this reserved variable in the workload environment.
The emulator does not rewrite arbitrary application `RPC_URL` values. Neither
Portal nor emulator invents application-specific expected-owner/workload env keys.

## Editing, restarting, and cleanup

Application source edits can be tested by restarting the native app, or rebuilding
its container with `workload-compose up --build`. Native emulation does not measure
the compiled executable or container image. The TOML and declared measured data
are frozen when the daemon starts. Changing these requires a fresh runtime;
`refresh` does not reload them. If the new specification conflicts with an already
published workload under the same publisher/name/version, choose a new version.

`stop` followed by `up` with the same launch inputs resumes saved chain/session
state. It is not a reset. A checkpoint mismatch reports what changed; restore the
old inputs to resume, or use `down` then `up` to start fresh while keeping disks.
The upstream Anvil instance and historical anchor must still be available.

Stop containers **before** removing emulator state, because `emulator down`
removes the default generated Compose file and does not stop containers:

```sh
atakit emulator workload-compose down
atakit emulator down
# Use this instead of the previous command only to also delete local data disks:
# atakit emulator down --purge-data
```

Native app processes also have their own lifecycle; stop them in your terminal or
IDE. `down` preserves unknown top-level files and lifecycle lock files. Recorded
workload directories and managed `compose/` and `bridges/` directories are removed
recursively, including extra files placed inside them. Custom Compose outputs
outside those managed paths are retained. Cleanup does not follow native data
symlinks into persistent disks or remove your workload source or upstream Anvil state.

Separate projects can have separate runtime directories, but they still need
unique internal Anvil ports, Portal socket paths, and app listening ports:

```sh
atakit emulator up --workload ./atakit-workload.toml \
  --runtime-dir .atakit-emulator-other --anvil-port 8547
```

## Troubleshooting

| Symptom | Check or action |
| --- | --- |
| `web3_clientVersion` / upstream RPC connection failure | Start A first; check `--fork-url`; do not point it directly at a public RPC |
| No compatible target, or several compatible targets | Read candidate reasons; select an existing compatible `--target`; emulator currently supports GCP/TDX |
| Published workload conflicts with TOML | Change the workload version for a different registered specification |
| Cannot resume checkpoint | Restore original config/owner/inputs, or `down` then `up`; `stop` deliberately retains the checkpoint |
| Upstream unavailable / historical state errors | Keep A running with historical states; after an upstream reset use `refresh` to anchor to its current state |
| `degraded` or a failed workload | Inspect each workload's `error` in `status` and the daemon log; a live daemon is not necessarily ready |
| Socket path too long | Shorten the project/runtime path or use `--output-socket`; override clients must connect to the explicit path |
| Native Compose mount fails | Check the host socket exists and sharing works in your engine; use explicit `--portal-transport bridge` when needed |
| App missing env / verifier errors | Configure the app's own env/contract address; use B for emulated signature verification |
| Old env or command behavior after rebuilding CLI | Check which binary you run and restart the daemon; rebuilding a binary does not update an existing process |

Before a real `cloud deploy`, build/publish the intended workload to the real
chain, use a business contract deployed on that chain, and replace local-only RPC
URLs. Local fork registration does not publish anything to Hoodi or prove TEE
attestation will pass on a real VM.

## Contract boundary


The emulator owns Anvil B, forked from the developer's Anvil A. Registry addresses
come from operator chain configuration and contract getters. A is read-only to the
emulator; hardware patches and registration transactions occur only on B.

| Component | Local behavior |
| --- | --- |
| SessionRegistry, WorkloadRegistry, BaseImageRegistry | Existing bytecode and addresses retained on B |
| TEE, TPM, AK collateral, signature, security-policy verifier contracts | Retained; their dependency graph is inspected |
| DCAP attestation and TPM attestation backend dependencies | Runtime bytecode replaced using `anvil_setCode` on B |
| Evidence | Software-generated evidence and PCR witnesses, with real local signing keys |
| PCR policies | Satisfiable witnesses synthesized for the selected registered policy; unsupported/conflicting policies fail |
| Publisher whitelist | If workload publication is paused and the publisher is not whitelisted, impersonate the Registry owner on B to add it |
| Transaction funding | Local Anvil balances/impersonation; no real-chain payment |
| Business contract and signature verification | Execute against inherited/deployed contracts on B |

Patching rejects missing contracts and unsupported dependency aliasing. It does
not blanket-replace the Registry with an always-success implementation. The
whitelist adjustment and all registration transactions affect only the local fork.
The embedded mock artifacts and their source revision are documented in
[assets/README.md](assets/README.md).

This is a functional signing/contract test environment. Success does not establish
hardware authenticity, secrecy of a native process, or deployability on a real CVM.

## Identity and measurements

`emulator status` includes `workloads.<instance>.version`, captured from the workload
TOML at startup. Editing the TOML does not change the running instance's reported
version. Older daemons without this field report `null`; restart with the updated
binary to populate it.


An instance alias is a local routing name. The workload identity is derived from
publisher fingerprint, TOML workload name, and version. Publisher and session
owner are separate roles and may use different configured signing keys. Every
instance gets its own session key and, when requested, Portal socket. The socket
determines which workload a request belongs to; no app-supplied workload selector is needed.

The native input fingerprint hashes a domain separator, canonicalized TOML, and
sorted declared measured-file paths and bytes. It does not build or hash a running
native executable/container. It is not the production `.atawl` measurement.
Files referenced only through `env-file` are not included in that input hash;
the current hash covers TOML and declared measured-data files.
Unpublished development workloads receive a local PCR23 policy based on this
fingerprint. For an existing registered workload, compatible metadata is required
and PCR witnesses are synthesized from the registered policy; the emulator does
not prove the edited native code matches its published container image.

## FAQ

### Does the emulator register a workload before registering its session?

Yes, when the workload ID does not already exist on Anvil B. The emulator derives
that ID from the publisher fingerprint selected by `[publish].owner_key` and the
`[workload].name` and `version` in the local TOML. It does not append a development
suffix or change the version. An instance alias such as `--workload guardian=...`
only selects a local instance; it does not change the on-chain identity.

For a new ID, the emulator calls the real WorkloadRegistry's `registerWorkload`
on B with a publisher-signed request. Name, version, base-image allowlist,
attributes, and session TTL come from the TOML. The development PCR23 policy is
based on the local input fingerprint described in [Identity and measurements](#identity-and-measurements).
It then registers a session bound to that workload ID. Nothing is published to
upstream Anvil A or the public chain.

### What if that workload ID is already registered?

The emulator reuses the existing registration without overwriting it. It checks
name, version, base-image mode and allowlist, attributes, and session TTL against
the TOML. Conflicting metadata fails with
`published workload … conflicts with this TOML; choose a new version`.
Compatible metadata allows session registration against the existing policy.

### Can edited local code pass the published workload's measurement policy?

Yes. For an existing registration, the emulator synthesizes PCR witnesses that
satisfy the registered policy, where supported, and supplies software-generated
evidence through mocked hardware attestation backends on B. It does not measure
the running application or require its code to match the published container.
Unsupported or conflicting policies still fail. Local verification success tests
the application and contract flow; it does not prove production code identity or
hardware attestation. Checkpoint consistency checks still apply when restarting
with changed local inputs.

### Does a business contract's workload ID allowlist still apply?

Yes. The emulator does not modify the business contract or bypass its allowlist.
The registered session carries the derived workload ID, so an allowed ID can pass
that check and an unlisted ID is still rejected. Changing the publisher, workload
name, or version changes the ID and may require updating the business allowlist
on your test chain.

This is separate from the WorkloadRegistry's publisher whitelist, which the
emulator may adjust on B to permit local workload registration. Reusing an allowed
ID with simulated evidence tests the allowlist logic, but does not prove that the
local code is the trusted production workload.

## Checkpoint consistency

Runtime locks prevent two daemons from owning the same directory. Socket ownership
records allow stale listeners to be cleaned up without deleting unrelated sockets.
The private checkpoint pairs an Anvil state dump with session keys, resolved launch
configuration, input hashes, and the upstream block and Anvil instance identity.
Resume validates these together before restoring usable sessions. Private runtime
files contain signing material and must not be committed to version control.

Signing checks session activity on B. Loss of the upstream anchor disables signing
rather than continuing with evidence tied to an unknown fork. Individual instances
can fail while other instances remain usable; daemon liveness is not application
readiness.

Refresh disables signing, retains the previous checkpoint, creates a new fork of A,
reapplies hardware mocks, and registers fresh sessions using frozen inputs. It does
not merge B's changes into A. A failed refresh is reported as `refresh_failed` and
session operations remain gated until refresh succeeds. For the user-visible
stop/down/data-retention rules, see
[editing and cleanup](#editing-restarting-and-cleanup).

## Implementation map and verification

| Source | Responsibility |
| --- | --- |
| `crates/atakit-cli/src/commands/emulator.rs` | Operator config, target selection, CLI presentation, native exec and Compose forwarding |
| `crates/atakit-emulator/src/cli.rs`, `config.rs` | CLI/config input and instance resolution |
| `fork.rs`, `rpc.rs` | Anvil ownership, anchor identity, local writes/read-only upstream |
| `chain.rs`, `pcr.rs`, `evidence.rs` | Contract graph, registration, policy witnesses and software evidence |
| `runtime.rs`, `lifecycle.rs` | Daemon, control socket, checkpoints, health and cleanup |
| `portal.rs` | Workload-facing socket routes |
| `inputs.rs`, `environment.rs` | Frozen input hashing, env and native filesystem projection |
| `compose.rs` | Compose YAML projection and optional bridge |

The default Emulator tests require Foundry's `anvil` on `PATH`; CI installs
Foundry v1.4.4. These tests start local Anvil processes without a public RPC.
Check `anvil --version` before running them.

Focused checks:

```sh
cargo test -p atakit-emulator --locked
cargo test -p atakit-cli --test workload_compose --test emulator_status --locked
```

Some live fork/registration tests are ignored by default and require their own
fixtures; passing the default suite is not a claim that public-chain registration
or a cloud deployment was exercised.

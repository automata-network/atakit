# Cloud Deploy Design - Option C+A (Stateful Shell-Out)

Decision: stateful deploy with plan files, executing via cloud CLI tools (`gcloud`, `az`).

## Background

See the old atakit analysis in `~/work/atakit/cloud-deploy-details.md` (pipeline overview), `cloud-deploy-gcp-commands.md` (exact GCP commands), and `cloud-deploy-azure-commands.md` (exact Azure commands).

### What We Keep

- Sequential pipeline with clear phases
- Idempotent check-before-create for every resource
- Version-based image skip logic (if cloud image exists for this version, skip upload)
- Blob cleanup after image registration
- Selective destroy with preserve flags
- Deterministic resource naming
- Metadata injection (workload identity, custom key-value pairs)
- Structured JSON output parsing (`--format=json` / `--output json`)

### What We Discard

- Monolithic 600-1400 line provider files (split by phase)
- No state tracking (add persistent state file)
- No rollback on failure (state enables resume/cleanup)
- Random bucket names (fully deterministic)
- Per-command y/N prompts (show full plan upfront, confirm once)
- Hardcoded port 8000 (port 1024 for CVM agent, workload ports auto-derived from manifest)
- `[deployments]` in workload config (moved to operator config)

---

## Key Design Decisions

### Separation of What vs Where

**Workload config** (`atakit-workload.toml`) defines WHAT: containers, data, firewall rules, disks. Portable - same `.atawl` archive deploys to any cloud target.

**Cloud config** (`config.toml` `[cloud]` section) defines WHERE: cloud provider, project, zone, VM type. Operator config - different operators deploy the same workload to different targets.

`[deployments]` is removed from `atakit-workload.toml`. Deployment targets live exclusively in the operator's `config.toml`.

### Region Naming

GCP requires a zone (`asia-southeast1-b`), Azure requires a region (`eastus`). The config uses `region` for both. GCP users put a zone in the `region` field. Documented clearly, backward-compatible, simple.

---

## Config Changes

### `atakit-workload.toml`: Remove `[deployments]`

The `[deployments]` section is removed entirely. Fields that remain workload-scoped:

- `[firewall]` - stays. Firewall rules are the workload's security contract.
- `[disks]` - stays. Disk definitions are the workload's storage contract.

### `config.toml`: Add `[cloud]` Section

Targets use a flat `[cloud.targets.<name>]` layout with an explicit `platform` field, rather than nesting by deployment name and platform. Each target is a self-contained cloud deployment configuration, optionally with per-target agent env overrides.

```toml
[cloud]
# Default expire offset for CVM agent sessions (seconds).
# expire_offset = 3600
# RPC URL (falls back to [publish] rpc_url if not set here).
# rpc_url = "https://..."
# Session registry (falls back to [publish] session_registry).
# session_registry = "0x..."
# Default key files (falls back to [publish] equivalents).
# owner_key_file = "~/.config/atakit/owner_key"
# relay_key_file = "~/.config/atakit/relay_key"

[cloud.targets.prod-gcp]
platform = "gcp"
cc_type = "SEV_SNP"                # or "TDX". Default: SEV_SNP
project = "my-gcp-project"
region = "asia-southeast1-b"       # GCP zone
vmtype = "c3-standard-4"
# Per-target key overrides:
# owner_key_file = "~/.config/atakit/my_owner_key"

[cloud.targets.staging-gcp]
platform = "gcp"
cc_type = "TDX"
project = "my-gcp-project"
region = "us-central1-a"
vmtype = "c3-standard-4"
```

Per-target fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `platform` | string | yes | `"gcp"` or `"azure"` |
| `cc_type` | string | no | `"SEV_SNP"` (default) or `"TDX"` |
| `project` | string | yes (GCP) | GCP project ID |
| `subscription` | string | yes (Azure) | Azure subscription ID |
| `region` | string | yes | GCP zone or Azure region |
| `vmtype` | string | yes | Machine type / VM size |
| `name` | string | no | Instance name prefix override |
| `metadata` | table | no | Extra key-value pairs |
| `rpc_url` | string | no | Per-target RPC URL override |
| `session_registry` | string | no | Per-target session registry override |
| `owner_key_file` | string | no | Per-target owner key file override |
| `relay_key_file` | string | no | Per-target relay key file override |

Agent env resolution: CLI args > per-target config > `[cloud]` section > `[publish]` section > error.

Precedence for other fields: CLI args > config.toml > (error if missing).

---

## CLI Surface

```
atakit cloud deploy [SOURCE] --target <name> --image <ref>
                    [--force-image] [--name <override>] [--image-only]
                    [--metadata KEY=VALUE]... [--skip-init] [-k] [-y]
                    [-d <workload-dir>]
                    [--owner-key <path>] [--relay-key <path>]
                    [--rpc-url <url>] [--session-registry <addr>]

atakit cloud destroy <instance> [--target <name>]
                     [--preserve <image,disks,firewall>] [-y]

atakit cloud status <instance> [--target <name>] [--live]

atakit cloud ls [--target <name>]

atakit cloud ssh <instance> [--target <name>]
atakit cloud serial <instance> [--target <name>]
```

### Argument Resolution

- `SOURCE` (positional, optional): workload source for deploy. Three forms: `name:version` (store ref), path to `.atawl` file, or omit for dir mode (reads `atakit-workload.toml` in cwd or `-d` dir).
- `--target` selects from `[cloud.targets.<name>]` in config. Required for deploy.
- `--image` specifies the base CVM image. Three forms: `repository:tag` (resolved from ImageStore), path to `.atabi` file (imported then deployed), or bare GCE image name (skip upload, verify existence). **Required** for deploy.
- `--name` overrides the VM instance name. Default: `{workload-name}-{target-name}`.
- `--image-only` deploys a bare image VM without any workload (for platform measurement collection). Requires `--name`.
- `--metadata KEY=VALUE` appends custom metadata. Can be repeated.
- `--force-image` deletes and re-uploads the GCE image even if it already exists. Required when changing `cc_type` for a previously uploaded image.
- `-k` / `--keep-going` continues on non-fatal errors instead of stopping.
- `--skip-init` provisions infrastructure but does not initialize the workload (steps 1-5 only, skip steps 6-7).
- `-y` / `--yes` skips plan confirmation.
- `-d` specifies workload directory (conflicts with positional `SOURCE`). Defaults to cwd.
- `<instance>` (positional) on destroy/status/ssh/serial: instance name. Scanned across all targets unless `--target` disambiguates.
- `--live` on status queries live state from cloud provider.
- `--preserve` on destroy: comma-separated resources to keep (`image`, `disks`, `firewall`).
- `--delete-image` on destroy: defaults to `true`. Use `--preserve image` to keep the GCE image.

### `cloud list`

```
Deployment   Platform   Status          Instance              IP
prod         gcp        deployed        secure-signer-prod    34.126.100.42
staging      azure      deploy-failed   (step 5: instance)    -
```

### `cloud ssh` / `cloud serial`

`ssh` execs the provider's SSH command directly (`ssh_command()` returns full command args). `serial` retrieves serial output via `provider.get_serial_output()` and prints it.

- GCP ssh: `gcloud compute ssh {instance} --project {project} --zone {zone}`
- GCP serial: `gcloud compute instances get-serial-port-output` (output printed, not interactive)
- Azure: similar patterns via `az` CLI

---

## Deploy Pipeline

7 phases. Old atakit had 5 (check_deps through create_instance). We add **wait for agent** and **initialize workload**.

```
1. check_deps           -- verify CLI tools on PATH
2. upload_image         -- upload base CVM disk image, register as bootable
3. open_ports           -- configure cloud firewall / NSG
4. create_disks         -- provision persistent data disks
5. create_instance      -- launch the CVM
6. wait_for_agent       -- poll CVM agent on port 1024 until reachable
7. initialize_workload  -- POST /init with .atawl + unmeasured-data + config
```

### Phase 6: Wait for Agent

After the VM is created, wait for the CVM agent HTTPS server to become reachable:

```
1. Fetch public IP from cloud (recorded in state)
2. Poll https://{ip}:1024/ with exponential backoff
   - Start: 5s interval
   - Max: 30s interval
   - Timeout: 5 minutes (configurable)
3. Accept self-signed certs (always, or with -k flag)
```

Display:
```
Waiting for CVM agent at 34.126.100.42:1024... ready (47s)
```

### Phase 7: Initialize Workload

The CVM agent exposes `POST /init` (HTTPS, port 1024). One-shot endpoint - only accepts a single call on a fresh VM. If the CVM already has a workload on disk, `/init` is never exposed.

Multipart form:

| Field | Required | Content |
|---|---|---|
| `atawl` | yes | The `.atawl` archive file |
| `unmeasured-data` | no | Tar archive of unmeasured-data files (see below) |
| `config` | yes | JSON containing `agent_env` for CVM agent on-chain operations (see below) |

**Auth: deferred to v2.** For v1, no auth on `/init`. Security relies on:
- `/init` is one-shot: closes after first successful call, never exposed if workload exists on disk
- The deployer hits it within seconds of VM creation
- Ephemeral public IPs are unpredictable
- HTTPS encrypts the payload (even with self-signed certs)

Display:
```
Initializing workload on 34.126.100.42:1024...
  Uploading secure-signer-v0.0.1.atawl (4.2 MB)
  Uploading unmeasured-data (2 files, 1.1 KB)
  Sending agent config
  Workload initialized successfully.
```

### Agent Config (`config` field)

The `config` JSON contains `agent_env` - configuration the CVM agent needs for on-chain session management:

```json
{
  "agent_env": {
    "relay_private_key": "0x...",
    "rpc_url": "https://sepolia.infura.io/v3/...",
    "session_registry": "0x1234...5678",
    "owner_private_key": "0x...",
    "expire_offset": 3600
  }
}
```

| Field | Source | Description |
|---|---|---|
| `rpc_url` | `[publish] rpc_url` / `ATAKIT_RPC_URL` | Ethereum RPC endpoint |
| `session_registry` | `[publish] session_registry` / `ATAKIT_SESSION_REGISTRY` | Session registry contract address |
| `owner_private_key` | `[publish] owner_key_file` (read from file) | Owner key for on-chain identity |
| `relay_private_key` | `[publish] relay_key_file` (read from file) | Relay key for gas payment |
| `expire_offset` | `[cloud] expire_offset` (default: 3600) | Session expiry offset in seconds |

Deploy assembles this from the existing `[publish]` config section (which already has rpc_url, session_registry, owner_key_file, relay_key_file) plus `expire_offset` from `[cloud]`. No new secrets config needed - the same keys used for `workload publish` are passed to the CVM agent.

**Note:** This sends private keys to the CVM. This is intentional - the CVM agent needs them for on-chain session registration. HTTPS encrypts the payload in transit.

**Temporary:** `agent_env` is a workaround for the current CVM agent implementation. After the agent rewrite, the agent will handle on-chain operations differently and `agent_env` will be removed from the init flow. Design the code so this is easy to rip out.

---

## Unmeasured Data Delivery

### Current State

During `workload build`:
- `unmeasured-data` paths listed in `atakit-workload.toml` are validated (must start with `./`, no traversal)
- Files are NOT required to exist at build time
- Paths are written to `manifest.json` so the CVM agent knows what to expect
- Files are NOT included in the `.atawl` archive

Gap: no mechanism delivers the actual files to the CVM.

### Solution

Deploy collects the unmeasured-data files and includes them in the init POST. The declared path set is read from the **manifest** (the `unmeasured-data` array), not the source TOML, so it is available in every deploy mode (dir, store-ref, file). The file *contents* come from the source directory or an explicit `--unmeasured-data-dir`.

**During deploy (atakit-ng side):**

1. Read the declared `unmeasured-data` paths from `manifest.json` (strip the `unmeasured-data/` prefix to get deploy-relative paths).
2. Resolve them under the `--unmeasured-data-dir` (or the workload directory in dir mode).
3. Verify the directory contains **exactly** that set — error on any missing or extra file. Then tar the declared files into an in-memory archive preserving directory structure (same layout as measured-data in the `.atawl`).
4. Add as the `unmeasured-data` multipart field in the `POST /init` request.

**Portal side:**

1. Accept the optional `unmeasured-data` multipart field in `POST /init`.
2. Extract to `<WorkloadTempDir>/unmeasured-data/` (bind-mounted into the container at `/atakit-portal/unmeasured-data/`).
3. Verify the extracted file set equals the manifest's `unmeasured-data` array exactly (no missing, no extra) before the workload runs. Contents are not hashed — only the path set is, via PCR23.

### Validation at Deploy Time

The path set is committed to PCR23, so it must match exactly on both the CLI and portal sides:

```
- manifest declares unmeasured-data: ["unmeasured-data/runtime-data/key.pem", "unmeasured-data/runtime-data/config.json"]
- --unmeasured-data-dir has:
  - runtime-data/key.pem       -> included in POST
  - runtime-data/config.json   -> MISSING => deploy errors (must match the manifest exactly)
  - runtime-data/extra.txt     -> EXTRA   => deploy errors (not declared in the manifest)
```

### `--unmeasured-data-dir`

For cases where unmeasured-data lives outside the workload directory (e.g., secrets from a vault):

```
atakit cloud deploy --image automata-linux:v0.1.6 --unmeasured-data-dir /path/to/secrets/
```

The `--unmeasured-data-dir` must contain exactly the files the manifest's unmeasured-data paths declare — no more, no less.

---

## Image Sharing Across Deployments

Cloud compute images (the base CVM boot disk) are scoped to the cloud project, not to a specific workload.

### How It Works

- Image name derived from image ref: `automata-linux:v0.1.6` -> `automata-linux-v0-1-6`
- Two workloads in the same GCP project with the same base image version share the compute image
- Plan phase checks if image exists; if yes, upload is skipped

### Trade-offs

**Good:**
- No redundant uploads. A 2 GB disk image is uploaded once.
- Faster subsequent deploys within the same project.

**Tricky:**
- `--force-image` replaces the image project-wide. But since the image content is version-pinned, replacing it with the same version is idempotent.
- Destroy must NOT delete shared images by default.

### Implemented Behavior

- Images are deleted on destroy by default. Use `--preserve image` to keep the GCE image and its GCS bucket.
- `--force-image` on deploy deletes the existing GCE image and bucket before re-uploading. Required when changing `cc_type` on a previously uploaded image (SEV_SNP vs TDX require different guest OS features).
- State file records the image name as a plain string (no `shared` flag).

### Image Validation

Deploy validates the chosen `--image` against the workload's `base-image-mode` and `base-image` list when the image is specified as a `repository:tag` reference (not a bare cloud image name):

```
base-image-mode = "whitelist"
base-image = ["automata-linux:v0.1.5", "automata-linux:v0.1.6"]

--image automata-linux:v0.1.6   -> OK
--image automata-linux:v0.1.4   -> error: image not in whitelist

base-image-mode = "blacklist"
base-image = ["automata-linux:v0.1.0-debug"]

--image automata-linux:v0.1.6   -> OK
--image automata-linux:v0.1.0-debug -> error: image is blacklisted
```

---

## Re-deploy (Resource Reuse)

Always full VM recreation. No in-place workload updates. `/init` is one-shot and there is no update endpoint. Re-deploy destroys the instance and creates a new one, reusing shared infrastructure. The expensive resources (image, firewall, disks) are preserved - only the instance is recycled.

### Scenarios

| Change | Steps |
|---|---|
| New workload version (new `.atawl`, same image) | Destroy instance -> create instance -> initialize with new archive |
| New base image version | Destroy instance -> upload new image -> create instance -> initialize |
| Config change (VM type, zone) | Destroy instance -> create instance with new config -> initialize |
| Firewall change | Update firewall rules -> (instance unchanged, no restart needed) |
| New disk added | Create new disk -> destroy instance -> create instance with new disk attached -> initialize |

### Plan Display for Re-deploy

```
Re-deploy plan for secure-signer / prod / gcp:

  Reusing:
  - Compute image: automata-linux-v0-1-6 (unchanged)
  - Firewall rule: secure-signer-prod-ingress (unchanged)
  - Persistent disk: secure-signer-prod-data (unchanged)

  Actions:
  1. Delete instance: secure-signer-prod
  2. Create instance: secure-signer-prod (c3-standard-4, asia-southeast1-b)
  3. Wait for CVM agent
  4. Initialize workload: secure-signer-v0.0.2.atawl

Proceed? [y/N]
```

---

## Verification

### What Attestation Proves

A CVM's attestation report (from TPM/TEE hardware) contains PCR measurements:
- **PCR 0-19:** Platform measurements - boot chain, firmware, kernel, initrd, platform config. Generated by `image generate-platform-profile`.
- **PCR 23:** Workload measurement - SHA-256 of `manifest.json` (RFC 8785 canonical JSON). Generated by `workload info` / `workload inspect`.

Verification compares actual measurements from a running CVM against expected values.

### When Verification Matters

1. **First deploy to a new machine type.** You've never seen this platform's measurements before. Fetch + profile them for future comparison: `image fetch-platform-measurements`, then `image generate-platform-profile`.

2. **Routine deploy to a known machine type.** Platform profile already exists. After deploy, verify the CVM matches expectations. This catches:
   - Wrong image loaded (version mismatch)
   - Secure boot chain broken
   - Unexpected firmware/platform changes (cloud provider updated hardware)
   - Workload archive tampered

3. **Before sending secrets to the CVM.** An external party wants to verify the CVM before trusting it with sensitive data. They fetch measurements and compare against a published profile.

4. **Periodic re-verification.** Cron job that checks CVMs are still running expected software.

### Existing Tools

- `image fetch-platform-measurements` - fetches PCRs + event logs from a running CVM (port 1024)
- `image generate-platform-profile` - generates expected profiles from collected measurements
- `image platform-profile` - displays saved profiles
- `workload info` / `workload inspect` - shows expected PCR23

### Proposed: `cloud verify`

```
atakit cloud verify [--deployment <name>] [--platform <gcp|azure>] [-d <workload-dir>]
```

1. Read CVM IP from state
2. Fetch platform measurements from CVM agent (port 1024)
3. Load expected platform profile (from `image generate-platform-profile` output)
4. Load expected PCR23 (from `.atawl` manifest hash)
5. Compare and report:

```
Verifying secure-signer-prod (34.126.100.42)...

  Platform (PCR 0-19):
    Profile: gcp-tdx (automata-linux:v0.1.6)
    PCR 0:  match
    PCR 1:  match (3 variant events excluded)
    PCR 2:  match
    ...
    PCR 14: match

  Workload (PCR 23):
    Expected: 0xabcd...1234 (secure-signer-v0.0.1.atawl)
    Actual:   0xabcd...1234
    Status:   match

  Result: VERIFIED
```

**Requires:** Platform profile already generated for this image + machine type combo. If not available, suggest running `image fetch-platform-measurements` + `image generate-platform-profile` first.

**Optional flag on deploy:** `--verify` runs verification automatically after initialization completes.

### Bootstrapping Problem

For the FIRST deploy to a new machine type, you don't have a platform profile yet. The flow is:

1. Deploy the workload (no verification possible yet)
2. `image fetch-platform-measurements -k <image:tag> <ip>` to collect measurements
3. Repeat on other machines of the same type for confidence
4. `image generate-platform-profile <image:tag>` to generate the profile
5. Now future deploys can use `--verify`

This is inherently manual for the first run. We can streamline it: deploy with `--collect-measurements` auto-runs step 2 after init.

---

## Crate: `atakit-cloud`

```
crates/atakit-cloud/
  Cargo.toml
  src/
    lib.rs              -- public API, re-exports
    error.rs            -- CloudError (thiserror)
    cli.rs              -- clap arg structs (behind `cli` feature)
    config.rs           -- PlatformKind, CcType, CloudConfig, CloudTarget
    state.rs            -- DeployState, DeployStatus, ResourceSet, GcpResources, AzureResources, PersistedAgentEnv
    plan.rs             -- DeployPlan, DeployStep, DestroyPlan, DestroyStep, StepResult, ResourceUpdates
    naming.rs           -- ResourceNames (GCP), AzureResourceNames (Azure), resource_labels(), sanitize()
    exec.rs             -- CommandRunner trait + ProcessRunner impl
    provider.rs         -- CloudProvider trait, DeployOptions, DestroyOptions
    init.rs             -- AgentConfig, wait_for_agent, post_init
    gcp/
      mod.rs            -- GcpProvider (plan_deploy, execute_step, plan_destroy, execute_destroy_step, ssh/serial)
      deps.rs           -- check_gcloud
      destroy.rs        -- destroy documentation (logic lives in GcpProvider methods and per-resource modules)
      image.rs          -- ensure_bucket, upload_image, register_image, check/delete_image, delete_bucket
      firewall.rs       -- create/check/delete_firewall
      disk.rs           -- create/check/delete_disk
      instance.rs       -- create/delete_instance, get_instance_ip, get_serial_output
```

```
crates/atakit-cloud/
  src/
    azure/
      mod.rs            -- AzureProvider (plan_deploy, execute_step, plan_destroy, execute_destroy_step, ssh/serial)
      deps.rs           -- check_az
      image.rs          -- ensure_resource_group, ensure_storage_account, ensure_gallery, ensure_image_definition, create/check/delete_image_version, upload_vhd
      firewall.rs       -- create_nsg, add_nsg_rules, check/delete_nsg
      disk.rs           -- create/check/delete_disk
      instance.rs       -- create/delete_instance, get_instance_ip, get_boot_log, delete_resource_group
```

Both `GcpProvider` and `AzureProvider` implement the `CloudProvider` trait.

### Dependencies

- `tokio` (process, async)
- `serde`, `serde_json` (state, JSON parsing)
- `thiserror`, `tracing`
- `chrono` (timestamps)
- `async-trait`
- `reqwest` (CVM agent client)
- `clap` (behind `cli` feature)
- `atakit-core` (Env, ProgressReporter)

---

## Core Types

### CloudProvider Trait

```rust
#[async_trait]
pub trait CloudProvider: Send + Sync {
    fn check_deps(&self) -> Result<(), CloudError>;

    async fn plan_deploy(&self, opts: &DeployOptions) -> Result<DeployPlan, CloudError>;

    async fn execute_step(
        &self,
        step: &DeployStep,
        runner: &dyn CommandRunner,
        verbose: bool,
    ) -> Result<StepResult, CloudError>;

    fn plan_destroy(
        &self,
        state: &DeployState,
        opts: &DestroyOptions,
    ) -> Result<DestroyPlan, CloudError>;

    async fn execute_destroy_step(
        &self,
        step: &DestroyStep,
        runner: &dyn CommandRunner,
        verbose: bool,
    ) -> Result<(), CloudError>;

    async fn get_instance_ip(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<Option<String>, CloudError>;

    async fn get_serial_output(
        &self,
        state: &DeployState,
        runner: &dyn CommandRunner,
    ) -> Result<String, CloudError>;

    fn ssh_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError>;
    fn serial_command(&self, state: &DeployState) -> Result<Vec<String>, CloudError>;
}
```

### DeployOptions

Cloud target details (project, zone, vmtype, cc_type) are accessed via the embedded `CloudTarget` struct rather than being flattened into `DeployOptions`.

```rust
pub struct DeployOptions {
    pub instance_name: String,
    pub target_name: String,
    pub target: CloudTarget,         // full target config (platform, cc_type, project, region, vmtype, metadata, ...)
    pub image_ref: String,
    /// Local disk image file path for upload. `None` means the image is
    /// assumed to already exist in GCE (e.g. a bare GCE image name was passed).
    pub source_image_path: Option<String>,
    pub archive_path: String,
    pub archive_hash: String,
    pub workload_name: String,
    pub workload_version: String,
    pub agent_env: PersistedAgentEnv,
    pub metadata: BTreeMap<String, String>,
    pub force_image: bool,
    pub skip_init: bool,
    /// Host ports from the workload manifest (format: "host:container[/proto]").
    /// Used to derive firewall rules. No protocol = both tcp+udp.
    pub workload_ports: Vec<String>,
    /// Disks from the workload manifest: (disk_name, index, size_gb).
    pub workload_disks: Vec<(String, u32, u64)>,
    /// Minimum boot/OS disk size in GB. Cloud default if None.
    pub boot_disk_size_gb: Option<u64>,
}

pub struct DestroyOptions {
    /// Resources to preserve: "image", "disks", "firewall".
    pub preserve: Vec<String>,
}
```

### CommandRunner

No `ProgressReporter` trait - cloud commands use direct stderr output.

```rust
#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run_capture(
        &self,
        program: &str,
        args: &[&str],
    ) -> Result<CommandOutput, CloudError>;

    async fn run_stream(
        &self,
        program: &str,
        args: &[&str],
        verbose: bool,     // controls stderr streaming (upload progress)
    ) -> Result<CommandOutput, CloudError>;
}

#[derive(Default)]
pub struct ProcessRunner {
    pub verbose: bool,     // when true, prints "$ program args..." before each command
}
```

`ProcessRunner::new(verbose)` creates a runner that logs commands to stderr. The `verbose` field controls command display for both `run_capture` and `run_stream`. The `run_stream` method additionally takes its own `verbose` parameter to control whether subprocess stderr is inherited (for upload progress).

---

## State File

### Location

`<data_dir>/deployments/<target>/<instance>.state.json`

State lives in the XDG data directory (not the workload directory). This is global to the operator, not per-workload.

### Schema

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployState {
    pub format: u32,                   // 1
    pub instance_name: String,
    pub workload_name: String,
    pub workload_version: String,
    pub target_name: String,
    pub platform: PlatformKind,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub status: DeployStatus,
    pub image_ref: String,
    pub archive_path: String,
    pub archive_hash: String,          // SHA-256 of .atawl
    pub agent_env: PersistedAgentEnv,
    pub resources: ResourceSet,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeployStatus {
    Deploying { step: u32, total: u32 },
    Deployed { ip: String },
    Failed { step: String, message: String },
    Destroying,
    Destroyed,
}

/// Agent env persisted for reference (key file paths, not raw keys).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PersistedAgentEnv {
    pub rpc_url: Option<String>,
    pub session_registry: Option<String>,
    pub owner_key_file: Option<String>,
    pub relay_key_file: Option<String>,
    pub expire_offset: Option<u64>,
}

/// Flat struct with optional platform-specific sections.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResourceSet {
    pub gcp: Option<GcpResources>,
    pub azure: Option<AzureResources>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GcpResources {
    pub project: String,
    pub zone: String,
    pub bucket: Option<String>,
    pub image: Option<String>,
    pub firewall_rule: Option<String>,
    pub disks: Vec<String>,
    pub instance: Option<String>,
    pub external_ip: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AzureResources {
    pub subscription: String,
    pub region: String,
    pub resource_group: Option<String>,
    pub storage_account: Option<String>,
    pub gallery_rg: Option<String>,
    pub gallery: Option<String>,
    pub image_definition: Option<String>,
    pub image_version: Option<String>,
    pub nsg: Option<String>,
    pub disks: Vec<String>,
    pub instance: Option<String>,
    pub external_ip: Option<String>,
}
```

Note: `GcpResources` stores plain resource name strings, not rich record types. The `external_ip` is tracked here (set during instance creation).

### Lifecycle

```
  (no state) --deploy--> Deploying --> Deployed
                             |             |
                             | fail        | destroy
                             v             v
                          Failed      Destroying --> (state file deleted)
                             |
                             | destroy
                             v
                        (same flow)
```

State saved after every step (crash-safe via temp file + rename). On destroy completion, the **state file is deleted** rather than being left in "Destroyed" status. Empty target directories are cleaned up.

---

## Resource Naming

All deterministic. No random suffixes.

### GCP

Resource names are derived from `instance_name` (which defaults to `{workload}-{target}`):

| Resource | Pattern | Example |
|---|---|---|
| Bucket | `atakit-{instance}` | `atakit-secure-signer-prod-gcp` |
| Compute Image | `{sanitized-image-ref}` | `automata-linux-v0-1-6` |
| Firewall Rule | `{instance}-ingress` | `secure-signer-prod-gcp-ingress` |
| Persistent Disk | `{instance}-{disk-name}` | `secure-signer-prod-gcp-data` |
| VM Instance | `{instance}` (sanitized) | `secure-signer-prod-gcp` |

### Azure

Resource names are derived via `AzureResourceNames::for_azure(instance, image_ref, region)`. Storage account, gallery, image definition, and image version are scoped to `(region, image_ref)` so concurrent deploys of the same image share the same uploaded VHD and gallery image version. Only per-instance resources (RG, NSG, VM) include the instance name.

| Resource | Pattern | Example | Scope |
|---|---|---|---|
| Resource Group | `{instance}-rg` | `secure-signer-prod-rg` | per-instance |
| Storage Account | `atakit{6-hex-of-image-hash}{region}` (max 24, lowercase alphanum) | `atakit3a7f8beastus` | shared per `(region, image_ref)` |
| Gallery RG | `atakit-images-{region}` | `atakit-images-eastus` | shared per region |
| Gallery | `atakit_{region}_gallery` | `atakit_eastus_gallery` | shared per region |
| Image Definition | `{sanitized-image-ref}` | `automata-linux-v0-1-6` | shared per `(region, image_ref)` |
| Image Version | `1.0.0` (fixed) | `1.0.0` | shared per `(region, image_ref)` |
| NSG | `{instance}-nsg` | `secure-signer-prod-nsg` | per-instance |
| Managed Disk | `{instance}-{disk-name}` | `secure-signer-prod-data` | per-instance |
| VM Instance | `{instance}` (sanitized, max 64) | `secure-signer-prod` | per-instance |

**Implications for `cloud destroy`**: per-instance RG deletion only removes per-instance resources. The shared storage account (in `atakit-images-{region}`), gallery image version, and image definition are NOT touched — they remain available for subsequent deploys of the same image. The `--preserve image` flag is a no-op (kept for backwards compat); shared image artifacts are always preserved. Use `atakit image rm` (or manual `az` commands) to clean up shared artifacts.

**Region IDs**: Azure region values are lowercase ARM IDs (`eastus`, `westus`, `westus3`, `westeurope`, …) as accepted by `az --location`. Display names with spaces (`East US`) are not accepted.

### Resource Tags/Labels

All cloud resources get these labels (via `resource_labels()` in `naming.rs`). All values are sanitized for GCP label rules (lowercase, non-alphanumeric replaced with hyphens, max 63 chars).

| Label | Value | Example |
|---|---|---|
| `managed-by` | `atakit` | |
| `atakit-instance` | instance name (sanitized) | `secure-signer-prod-gcp` |
| `atakit-workload` | workload name (sanitized) | `secure-signer` |
| `atakit-version` | workload version (sanitized) | `v0-0-1` |
| `atakit-image` | base image ref (sanitized) | `automata-linux-v0-1-6` |

GCP: `--labels`. Azure: `--tags`.

---

## Firewall Rule Derivation

Port format: `host:container[/protocol]`. No protocol suffix = both TCP and UDP.
Firewall entries use the same format without the container port: `port[/protocol]`.

```
1. Auto-derive from workload ports:
   "3000:3000"      -> tcp:3000, udp:3000   (no proto = both)
   "8080:8080/tcp"  -> tcp:8080             (tcp only)
   "5353:5353/udp"  -> udp:5353             (udp only)
2. Auto-derive from dependency ports (same logic)
3. Apply [firewall] overrides:
   allow[] adds rules    -- "4000/tcp", "5000", 6000, { port = 7000, protocol = "udp" }
   deny[] removes rules  -- "3000/udp", 8080, { port = 9000, protocol = "tcp" }
   (bare int or string without /proto = both tcp+udp)
4. Always include: tcp:1024 (CVM agent - init + platform-measurements)
```

The manifest stores the resolved flat list as `firewall-ports` (auto-derived + allow - deny),
not the raw allow/deny config. Sorted by port then protocol for determinism.

---

## Secure Boot Certificates

From ImageStore per image version:

```
image_dir/<repo>/<tag>/certs/
  PK.crt, KEK.crt, db.crt, kernel.crt, livepatch.crt (optional)
```

If present: pass to image registration step.
If absent: use platform defaults (GCP: no secure boot flags; Azure: `MicrosoftUefiCertificateAuthorityTemplate`).

---

## Metadata Injection

### Auto-injected

| Key | Value | Source |
|---|---|---|
| `workload-name` | `secure-signer` | `atakit-workload.toml` |
| `workload-version` | `v0.0.1` | `atakit-workload.toml` |
| `archive-hash` | SHA-256 of `.atawl` | computed |

### User-provided

Via `--metadata KEY=VALUE` CLI flags or `metadata` table in target config.

---

## Post-Deploy Output

After all steps complete, deploy prints a summary with VM details and convenience commands:

```
==> Deployment complete!

    VM:         my-instance
    IP:         34.126.100.42
    Zone:       asia-southeast1-b
    Project:    my-gcp-project
    Image:      automata-linux-v0-1-6
    CC type:    SEV_SNP

    Serial console:
      gcloud compute connect-to-serial-port my-instance --zone=asia-southeast1-b --project=my-gcp-project

    SSH:
      gcloud compute ssh my-instance --zone=asia-southeast1-b --project=my-gcp-project

    Cleanup:
      atakit cloud destroy my-instance
```

---

## Error Types

See `crates/atakit-cloud/src/error.rs` for the full enum. Key variants:

```rust
#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    Config { message },
    TargetNotFound { name },
    State { message },
    StateNotFound { instance },
    AmbiguousInstance { instance, matches },
    AlreadyExists { instance },
    CommandFailed { program, args, stderr, code },
    CommandNotFound { program },
    DependencyMissing { tool, install_hint },
    ImageUploadFailed { message },
    FirewallError { message },
    DiskError { message },
    InstanceError { message },
    AgentTimeout { address, timeout_secs },
    AgentInitFailed { message },
    DeployFailed { step, message },
    DestroyFailed { resource, message },
    InvalidName { name, message },
    ArchiveNotFound { path },
    WorkloadError { message },
    Http { message },
    IoPath { path, source },
    Io(std::io::Error),
    Json(serde_json::Error),
}
```

---

## Brainstorm: Additional Considerations

### 1. Operator Auth (Deferred to v2)

For v1, `/init` has no authentication. The security model:
- `/init` is one-shot: only works on a fresh VM with no workload on disk. After successful init, the endpoint is gone.
- The deployer creates the VM and hits `/init` within seconds. The time window for an attacker is near zero.
- HTTPS encrypts the payload even with self-signed certs.

For v2, the CVM agent can add `OperatorAuthMiddleware` with a Bearer token scheme. At that point, we'd add `operator_token_file` to `[cloud]` config.

### 2. Stop / Start (Without Destroy)

`atakit cloud stop` / `atakit cloud start` to stop/start the VM without deleting resources. Saves costs during dev/test.

- GCP: `gcloud compute instances stop/start`
- Azure: `az vm stop/start`

Low effort, high utility for development. State file tracks `stopped` / `running` status.

### 3. Image Pull Integration

If `--image automata-linux:v0.1.6` isn't in ImageStore, should deploy offer to pull it?

Option A: Error with hint: "image not found locally. Run: atakit image pull automata-linux:v0.1.6 --platform gcp"
Option B: Auto-pull if missing (convenient but implicit network + download).

I lean toward **A** (explicit) for v1. Pulling a 2 GB image is a big side effect to do implicitly.

### 4. Destroy Safety

Destroy is destructive. Safety measures:
- **Require state file.** Never guess what to delete based on naming conventions.
- **Plan display.** Show exactly what will be deleted, including any data disks with data.
- **No `--yes` by default for data disk deletion.** Even with `--yes`, prompt for disks that contain data (size > 0). Or require explicit `--preserve disks` omission.
- **Warn on shared image deletion.** `--delete-image` checks for other state files referencing the same image.

### 5. Concurrent Deploy Guard

Two terminals running `cloud deploy` for the same deployment simultaneously could conflict.

Simple solution: advisory lock file at `.atakit/deploy/<deployment>-<platform>.lock`. Check on start, create with PID, delete on exit. If lock exists and PID is alive, error with "another deploy is in progress (PID {pid})."

### 6. Config JSON in Init POST

The `config` field contains `agent_env` with on-chain config (RPC URL, session registry, keys, expire offset). Assembled from existing `[publish]` config. Always sent on deploy. See "Agent Config" section above.

### 7. Deployment State Recovery

If the operator loses their state file (e.g., reformatted laptop), they've lost the mapping of deployment name to cloud resources. Recovery options:
- **`cloud refresh --project <id> --zone <zone>`** - scan cloud resources by `managed-by=atakit` tag, reconstruct state file. This is why tags matter.
- **Manual cleanup** using cloud console or CLI (list resources by tag).

Tags make recovery possible. Another reason to include them in v1.

### 8. Multi-Machine / Team Workflows

State files are local. For teams:
- Operator A deploys to prod. State is on A's machine.
- Operator B needs to destroy or re-deploy prod.

Options:
- B runs `cloud refresh` to reconstruct state from cloud tags.
- State files stored in a shared location (git repo, S3, shared drive). Adds complexity.
- Convention: one operator "owns" a deployment. Others use `cloud refresh`.

For v1, `cloud refresh` with tag-based recovery is sufficient.

### 9. `cloud plan` (Dry Run)

```
atakit cloud plan [same flags as deploy]
```

Generates and displays the plan without executing. Useful for:
- CI/CD review gates
- Cost estimation (future)
- What-if analysis

Trivial to implement: plan generation is already a separate phase.

### 10. Workload Status Endpoint

No agent status endpoint exists currently. `cloud status --live` is limited to a TCP connect check on port 1024.

For v1:
```
Deployment: prod / gcp
Instance:   secure-signer-prod (34.126.100.42)
VM Status:  running (from state)
Agent:      reachable (port 1024)
```

A future agent `/status` endpoint would enable richer output (workload running/failed, uptime, resource usage). This is a CVM agent feature request, not an atakit-ng concern for now.

### 11. QEMU (Implemented)

Local functional harness reusing the `CloudProvider` trait, exposed as the
`qemu` platform under `[cloud.providers.<name>]` / `[cloud.targets.<name>]`.
Not a real TEE — boot is measured into swtpm vTPM, not a genuine TDX/SEV
quote — so this is for offline `workload build → deploy → init → destroy`
iteration, not attestation testing.

Concrete shape of the implementation:

- **No cloud CLI dependency** — shells out to `qemu-system-x86_64`,
  `qemu-img`, `swtpm`. `/dev/kvm` is required.
- **No image upload** — `atakit image pull <ref> qemu` drops
  `qemu_disk.qcow2` into the local image store; `StartLocalVm` creates a
  per-instance qcow2 overlay backed by it (sized to `boot_disk_size`).
- **No firewall** — qemu user-mode networking with `hostfwd`. Portal
  status/init ports are forwarded to ephemeral host ports allocated at
  boot; workload-declared TCP ports are forwarded guest→same host port for
  predictable `curl`. A best-effort guest-22→host-port forward backs
  `cloud ssh`.
- **Data disks** — each workload-manifest disk becomes a per-instance
  qcow2 file attached via virtio-blk with `serial=<device_name>`, matching
  the cloud agent's `/dev/disk/by-id/virtio-<name>` discovery convention.
- **Metadata** via SMBIOS `type=11` OEM strings (`-smbios
  type=11,value=<k>=<v>`). Whether the portal reads these on the qemu
  platform is a portal-side concern; passing them is a no-op if unused.
- **State** tracks `instance_dir`, `pid`, the host-port mapping, base disk
  and overlay paths. `cloud serial` is `tail -f
  <instance_dir>/serial.log`; `cloud destroy` SIGTERMs the pid then removes
  the instance dir.
- **swtpm** is launched with `--terminate` so it exits when qemu
  disconnects.
- **Init via localhost:<ephemeral>** — `deploy.rs`'s `WaitForPortal` /
  `InitializeWorkload` arms read endpoints from
  `portal_endpoints(state)`: cloud platforms keep using the deployment's
  external IP + `2024`/`1024`; qemu uses `127.0.0.1` + the recorded host
  ports.
- **Zero-config chain/keys** — when a qemu target has no `chain`
  configured, an implicit local chain is synthesized at `/init` time with
  placeholder registry addresses and `registration = "off"`; unset
  `owner_key` / `gas_wallet` fall back to `self_generated` so the portal
  never needs a private key for a registration-off deploy.
- **Firmware (OVMF)** is path-driven, not bundled: `ATAKIT_QEMU_UEFI` >
  `[cloud.targets.<n>] uefi` > `[cloud.providers.<n>] uefi`. Stock distro
  OVMF lacks the TPM-measuring build; it needs to be separately built.

Open items (functional harness limits, not blockers): portal handling of
SMBIOS metadata on the qemu platform, and whether `/init` accepts
`self_generated` owner/gas under `registration="off"` (the deploy falls
back to requiring real keys if not).

---

## Implementation Order

1. **Config changes:** Add `[cloud]` to `Config`; remove `[deployments]` from `WorkloadConfig` and spec
2. **Crate skeleton:** `atakit-cloud` with error types, config types, state types, CommandRunner, CloudProvider trait
3. **State manager:** load/save/lifecycle, advisory lock
4. **Plan types and display**
5. **GCP provider:** check_deps, plan_deploy, all execute_step variants
6. **GCP destroy**
7. **CVM agent client:** wait_for_agent, POST /init with atawl + unmeasured-data
8. **CLI integration:** `cloud deploy`, `cloud destroy`, `cloud status`, `cloud list`
9. **Resource tagging** (labels/tags on all resources)
10. **`cloud ssh` / `cloud serial`** (thin wrappers)
11. **Azure provider** (same sequence as GCP) -- done
12. **Image validation** (check --image against workload's base-image allow/deny list)
13. **`cloud verify`** (fetch measurements, compare against profile + PCR23)
14. **`cloud plan`** (dry run)
15. **Integration tests** with mock CommandRunner

---

## Resolved Questions

1. **Auth on `/init`.** Deferred to v2. For v1, no auth. `/init` is one-shot (never exposed if workload on disk), HTTPS encrypted, time window near zero.
2. **CVM agent endpoints.** Only `/init` (POST, one-shot) and `/platform-measurements` (GET). No status/health endpoint currently.
3. **Port.** Single port 1024 for the CVM agent. No separate port 8000.
4. **Unmeasured-data in CVM agent.** We own the agent, change approved. Add `unmeasured` multipart field to `POST /init`.
5. **Unmeasured-data tar layout.** Strip `./` prefix, preserve relative directory structure. `./runtime-data/key.pem` becomes `runtime-data/key.pem` in the tar. Agent extracts into `<WorkloadTempDir>/unmeasured-data/`, so it ends up at `<WorkloadTempDir>/unmeasured-data/runtime-data/key.pem` (bind-mounted into the container at `/atakit-portal/unmeasured-data/runtime-data/key.pem`). Same convention as measured-data staging in `.atawl`.
6. **`agent_env` in config JSON.** Required. Contains on-chain config (rpc_url, session_registry, owner_private_key, relay_private_key, expire_offset). Assembled from `[publish]` config + `[cloud] expire_offset`. Always sent.
7. **`cloud status --live`.** TCP connect to port 1024. No richer status until agent adds a `/status` endpoint.

## Open Questions

(None remaining. All questions resolved.)

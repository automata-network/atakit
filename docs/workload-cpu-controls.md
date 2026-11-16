# Workload CPU controls (v0.3.6 and later)

## Ownership

The base-image publisher selects the kernel, drivers, boot parameters, and
Portal implementation. The workload publisher fixes runtime CPU settings or
explicitly limits the choices it delegates to the operator in the signed workload
manifest. Containers receive no host root or sysfs write
access. Runtime settings cannot undo image boot limits or enable idle states
that were already disabled.

The v0.3.6 and v0.3.7 images require source and compiled manifest **format 16** for every
workload, even when CPU settings are omitted. Formats 14 and 15 are rejected
at initial startup and reboot recovery. Earlier images
reject format 16 instead of silently ignoring its CPU requirements. No change
to registry contracts or base-image profile attributes is needed.

## Workload configuration

The following fields can be added to an otherwise complete workload source:

```toml
format = 16

[workload]
# Other workload fields go here.
cpuset = "0-1"

[workload.cpu-idle]
driver = "intel_idle"
governor = "menu"                  # Optional; keep current governor if omitted.
disabled-states = ["C6"]            # Optional if governor is set.
required = true                    # Default. Unsupported settings stop startup.

[workload.cpu-frequency]
governor = "performance"
required = true                    # Default. Unsupported controls stop startup.

[dependencies.logger]
image = "example/logger:latest"
cpuset = "0"

[baby-container.slots.tools]
parent-service = "app"              # Must match the actual parent service name.
cpuset = "2-7"                     # Signed allowance; babies inherit it by default.
```

`cpuset` is a nonempty string of guest CPU numbers and inclusive ranges,
separated by commas. Examples: `"0"`, `"0-3"`, `"0-3,6"`. Portal checks the
actual online CPU IDs and the CPUs available to its delegated cgroup (the
kernel's container resource-control group). An unavailable CPU, missing
controller, or runtime enforcement failure stops the affected container.
Startup checks all declared service and baby-slot sets before launching the
first container. An omitted field retains the runtime's default CPU placement.
Overlapping sets are allowed. CPU placement does not reserve CPUs exclusively,
set a CPU usage quota, or select physical host cores.

The builder expands ranges, sorts CPU IDs numerically and removes duplicates
before generating JSON. For example, `"0-3"` and `"3,1,0,2,2"` both produce
`"0,1,2,3"`, with identical manifest bytes when other inputs match. This applies
to the main workload, dependencies and baby slots. The builder also sorts
`disabled-states`; their source order does not change the measured policy.

CPU idle policy applies to the **whole VM**, once before any workload container
starts and again after a VM reboot. Dependencies and babies cannot declare
separate idle policies. An explicit driver name such as `intel_idle` or
`acpi_idle` must match the active guest driver. Starting with v0.3.7,
`driver = "auto"` authorizes use of the active guest driver. It does not load or
switch drivers, and a guest with no active driver reports an unsupported policy
(or fails startup when required). Idle state
names must match that driver's exposed names on every online CPU. Numeric
state indices are not accepted as a portable C-state cap. State names must be
unique, and the policy must leave at least one enabled state on each CPU.

Portal checks the entire policy before writing anything. It only disables
states; it never enables a previously disabled state. It checks each write by
reading the setting back. A write or readback failure stops startup and triggers
rollback. Teardown restores the values Portal changed, preserving preexisting
image restrictions. A reboot starts from image defaults and reapplies the
signed policy.

With `required = false`, an unsupported driver, governor, or state skips the
**entire** idle policy and reports `unsupported`. Write/readback failures still
fail startup. Omit `cpu-idle` to keep defaults. This controls the CPU idle
governor, not the CPU frequency governor. Boot parameters such as
`intel_idle.max_cstate` still require a rebuilt and signed base image.

## CPU frequency governor

`workload.cpu-frequency` selects a frequency governor for the whole VM. It is
separate from `workload.cpu-idle.governor`, which controls idle-state selection.
The frequency policy requires format 16 and is covered by the signed manifest.
These CPU fields do not belong to formats below 16 and are absent there.
Format 16 always emits `config.cpu-frequency`, including `null` when no
frequency policy is requested.

Before starting containers, the supervisor verifies the measured manifest,
reads every active Linux CPUFreq `policyN` directory, checks that the policies
cover all online CPUs, and checks that each policy supports the requested
governor. It then writes `scaling_governor` only where needed, reads every change
back, and verifies that the policy membership, drivers, governors and online
CPUs remain consistent. CPUs sharing a frequency policy are handled together.
Containers receive no sysfs write access.

If any policy lacks the requested governor or the VM exposes no CPUFreq
controls, `required = true` fails startup. `required = false` skips the entire
frequency policy without changing any governor and reports `unsupported`.
Malformed policy values always fail validation. Write/readback errors and CPU
membership changes during application always fail startup, even for an optional
policy, and trigger rollback. Failure teardown and supervisor shutdown restore
the original governors. Repeated application retains the original values for
restoration. VM reboot reapplies the signed workload policy from image defaults.

An omitted frequency policy leaves settings unchanged and reports a read-only
snapshot. Portal does not load kernel modules or change frequency minimums,
maximums, boost, host settings, or boot parameters. Selecting `performance`
does not guarantee a fixed clock speed or throughput. The kernel and VM must
expose the requested control.

## Baby-container API

The parent may narrow its slot's allowance when it creates a baby:

```json
{"slot":"tools", "cpuset":"2-3"}
```

An omitted request inherits the complete slot allowance. An explicit request
requires a signed allowance and must be a subset of it. Invalid requests fail
before runtime execution. Portal saves the selected set in the instance record
and in the writable-root inventory. Stop/start and reboot recovery reuse the
selection and recheck it against the signed allowance. Both read-only and
writable baby roots use the same Podman CPU-set enforcement.

## Reporting and trust

The `cpu_idle` field of `GET /status` reports the startup attempt's requested policy, result
(`defaults`, `applied`, `unsupported`, or `failed`), error detail, driver,
governor, available governors, and per-CPU state disable flags. It is a startup
snapshot, not continuous monitoring. `atakit cloud status --live --json` and
`--verify --json` include this information under `live.portal.cpu_idle`; text
output summarizes the result.

The `cpu_frequency` field of `GET /status` reports the requested policy, result, error detail,
and per-policy driver, governor, available governors, and affected online CPUs.
The CLI includes it under `live.portal.cpu_frequency` and prints a text summary.
Like CPU idle reporting, it is a startup snapshot, not continuous monitoring or
independent evidence of hardware behavior.

The `containers.services[].cpuset` field of `GET /status` reports Podman's configured CPU set
for each parent/sidecar; null means no explicit set. The baby list/create API
returns each instance's selected `cpuset` when set. The cloud status JSON also
includes each service's configured set.

The policy bytes are part of the canonical manifest and its measurement. These
status observations do not prove host physical C-state residency or CPU
exclusivity, and are not independent hardware attestation. The existing
[secret provisioning notice](secret-provisioning-security-notice.md) applies.

## Image support

Both v0.3.7 image startup scripts delegate the cgroup v2 `cpuset` controller to
Portal. Podman is explicitly given the delegated parent and enabled cgroups
when a set is requested. The staged Portal build check must accept format 16.
A kernel/VM without the necessary controls can still run a workload that omits
them, or explicitly optional unsupported CPU idle and frequency policies.

Reference interfaces: [Linux CPUIdle](https://docs.kernel.org/admin-guide/pm/cpuidle.html), [Linux CPUFreq](https://docs.kernel.org/admin-guide/pm/cpufreq.html),
and [Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html).

## Generated JSON defaults

The source TOML may omit CPU settings. The generated format-16 manifest must
still include `config.cpuset`, `config.cpu-idle`, `config.cpu-frequency`, each
declared dependency's `cpuset`, and each declared baby slot's `cpuset`. Their
default is `null`; no container entries are invented for undeclared services.

Inside a present idle policy, an omitted governor emits `"governor": null`,
omitted disabled states emit `"disabled-states": []`, and omitted `required`
emits `true`. A present frequency policy also emits `"required": true` by
default. The main, dependency and baby CPU sets are independent fields.

These rules follow the [archive defaults contract](atawl-archive-spec.md#explicit-generated-defaults).
Missing source settings must not cause missing applicable JSON keys.

## Operator choices within publisher permissions

The publisher and operator need not trust each other. Omission grants **no
operator permission**. An optional policy (`required = false`) does not, by
itself, allow the operator to change it.

A publisher can opt in with one source-only shorthand:

```toml
[workload]
allow-operator-cpu-tuning = true
```

The builder expands this into the following individual signed settings. Explicit
fields in the source override the expansion, including `false` and empty lists.
The shorthand itself is absent from `manifest.json`.

| Scope | Expanded permission |
|---|---|
| `workload.cpu-idle` | `driver = "auto"`, `allow-operator = true`, `required = false`, `allowed-governors = ["haltpoll", "menu", "teo"]`, `allowed-disabled-states = ["*"]` |
| Main, each declared dependency, each declared baby slot: `cpuset-policy` | `allow-operator = true`, `allowed-cpus = "online"`, `required = false` |
| `workload.cpu-frequency` | `allow-operator = false`, `allowed-governors = []`, `required = false`; frequency delegation needs an explicit publisher allowlist |

The `auto` preset requires v0.3.7 or later. The v0.3.6 builder used `intel_idle`.
Existing signed workloads keep their exact driver requirement. On v0.3.6,
`auto` does not select the guest driver: it reports a driver mismatch, which
skips optional idle settings or fails required settings. Publishers can set an
exact driver to restrict a workload to that driver.

`"*"` permits selection of any idle state name that the guest exposes. It does
not create states or enable disabled states. `"online"` explicitly permits any
online guest CPUs available to Portal's delegated cgroup. Opting into the
shorthand therefore delegates CPU placement for all declared container scopes.
Publishers that want narrower placement must override `allowed-cpus`, or set
`allow-operator = false` for that scope.

For example, allow idle tuning and restrict placement of the parent while
keeping the logger's placement under publisher control:

```toml
[workload]
allow-operator-cpu-tuning = true

[workload.cpuset-policy]
allowed-cpus = "0-3"

[dependencies.logger.cpuset-policy]
allow-operator = false
```

To delegate without the shorthand, specify the individual rules:

```toml
[workload.cpu-idle]
driver = "auto"
allow-operator = true
allowed-governors = ["haltpoll", "menu", "teo"]
allowed-disabled-states = ["*"]
required = false

[workload.cpuset-policy]
allow-operator = true
allowed-cpus = "0-3"
required = false

# Only if the publisher chooses to permit frequency selection:
[workload.cpu-frequency]
allow-operator = true
allowed-governors = ["performance", "powersave"]
required = false
```

Rules:

- `allow-operator = true` requires an explicit allowance. Neither omitted nor
  `null` permission grants control. `false` explicitly forbids operator choices.
- A fixed `governor` or nonempty fixed `disabled-states` makes the entire idle
  policy publisher-fixed. A fixed frequency `governor` fixes that policy.
  A fixed `cpuset` fixes that scope. Operator requests for fixed settings are
  rejected, even with the global shorthand enabled.
- Fixed policies keep their existing `required = true` default. The shorthand
  does not weaken them. Publishers may explicitly make them optional.
- An individually delegated policy defaults to `required = true`. This requires
  an operator selection and successful application. The shorthand explicitly
  uses `required = false`: selection may be omitted and unsupported controls
  fall back to image defaults. No container starts after a required failure.
- Operators must select an explicit idle governor. They cannot submit `required`,
  permissions, a driver, or allowed values. Those belong to the signed manifest.
- Unknown scopes, malformed values and choices outside the signed allowance
  always fail. Optional permission does not excuse an unauthorized choice.
- Actual write/readback failures always fail startup. Portal never silently
  replaces a failed requested configuration with an older saved configuration.

Every applicable generated JSON key remains present. Missing `cpuset-policy`
serializes as `null` on main, dependencies and baby slots. A present rule emits
its `allow-operator`, allowance and `required` keys; missing optional values are
JSON `null`. A present idle rule also emits its driver, governor, disabled states,
allowed governors and allowed disabled states. The builder sorts/deduplicates
allowlists and normalizes allowed CPU ranges. Shorthand and equivalent explicit
rules produce identical manifest bytes.

### Supported idle governors

Portal rejects `ladder` before writing settings. Portal permits `haltpoll` only
when `/sys/devices/system/cpu/cpuidle/haltpoll_state_disable_supported` reads `1`.
The patched kernel exposes this read-only capability and makes haltpoll select
an enabled state. Without this capability, a required haltpoll policy fails and
an optional policy reports `unsupported`. This also applies when the policy
inherits the current governor. A successful sysfs write alone does not prove
enforcement; the earlier kernel entered disabled states under haltpoll.

The v0.3.7 operator-tuning preset allows `haltpoll`, `menu` and `teo`. Existing
signed manifests keep their exact allowlists. The kernel also includes the
haltpoll driver, without forcing it over the platform-selected driver.

On the tested GCP `c4-standard-8` TDX image, the guest exposed `intel_idle`, CPUs
0–7, and `POLL`, `C1`, `C1E`, `C6`. The patched kernel passed all 15 valid
disabled-state subsets for each of `menu`, `teo` and `haltpoll`, before and after
reboot: 90 cases with no disabled-state counter increases after settling. The same guest exposed no CPU-frequency policy
interface. This does not prove host physical idle residency or support on other
VM sizes. An explicit frequency allowance is a permission, not a claim that a
platform provides frequency controls.

## Operator configuration and CLI

See the [complete standalone runtime.toml grammar](runtime-configuration.md#standalone-runtimetoml-grammar)
for every accepted field, value type, limit and omission rule.

Use a standalone `runtime.toml`:

```toml
cpuset = "0-3"

[cpu-idle]
governor = "teo"
disabled-states = ["C6"]

[dependencies]
logger = "4"

[baby-containers]
tools = "5-7"
```

The dependency keys name services. The baby-container keys name signed slots.
The parent still controls baby creation and may narrow a baby's selected slot
allowance using the existing API.

The same structure can live in the operator's `config.toml`:

```toml
[cloud.defaults.runtime.cpu-idle]
governor = "menu"
disabled-states = []

[cloud.targets.my-c4.runtime]
cpuset = "0-3"

[cloud.targets.my-c4.runtime.cpu-idle]
governor = "teo"
```

Resolution is per field: **flags > standalone file > target > shared defaults**.
Omission falls through; an explicit empty state list replaces a lower-priority
list. Dependency and baby-slot selections merge by name. This input layering
never changes publisher permissions.

```sh
atakit cloud deploy --target my-c4 app:v1 --runtime-config runtime.toml
atakit cloud init my-instance app:v1 --runtime-config runtime.toml
atakit cloud configure my-instance --runtime-config runtime.toml --check
atakit cloud configure my-instance --runtime-config runtime.toml
atakit cloud configure my-instance --cpu-idle-governor teo --cpu-idle-disabled-states C6
atakit cloud configure my-instance --cpuset 0-3 --dependency-cpuset logger=4 --baby-cpuset tools=5-7
atakit cloud configure my-instance --reset
atakit cloud status my-instance --live --json
```

`--check` checks signed permissions without saving or applying settings. The
platform's support is checked during startup. `--reset` clears all operator CPU choices and disk queue choices, ignoring input files and configuration defaults; publisher-fixed
settings still apply. Reset fails if the publisher requires delegated choices.
`--cpu-idle-disabled-states ''` clears just the inherited disabled-state list.
`--cpu-frequency-governor` selects a permitted frequency governor when available.

`configure` uses the deployment's provisioned owner key (or `--owner-key`) and an
attestation-verified TLS connection. The CLI checks the saved workload archive and
its PCR23 measurement while the workload is active. The signature covers the exact request body, including the manifest SHA-256, a short-lived
one-use challenge, and the Portal TLS identity. Portal rejects tampering and
replay. The privileged supervisor rechecks manifest integrity and CPU permissions
before saving or activating a request.

Failed startup clears PCR23 during cleanup. In `Failed` state, CPU configuration
still requires attestation-verified base-image TLS and the provisioned owner's
signature. The supervisor checks the stored manifest's integrity, requires the
request's `manifest_hash` to match its exact bytes, and enforces its CPU permission
rules before staging a correction. Startup still performs the existing publisher
signature and measurement checks before applying settings and starting containers.
This allows recovery without treating a failed workload as running or verified.
Disk unlock and secret provisioning retain their measurement checks.
On reboot, a valid pending correction permits a fresh startup from `Failed`.
Without a pending correction, `Failed` remains terminal. A malformed correction,
changed manifest, or choice outside the publisher's permissions leaves it failed.
The correction remains pending until the normal startup checks reach CPU setup.

### Startup and reporting

Configuration updates are pending. They do not write sysfs, move running
containers, or restart them. Portal selects pending settings once at the next
full workload startup, including VM reboot, before starting containers. Baby-only
stop/start continues using the active settings. Saved baby CPU choices must fit
the newly selected slot allowance after a full restart; otherwise recovery fails.
Settings survive reboot and are
bound to the exact manifest bytes. Failed application leaves the workload stopped.

The original manifest on disk and PCR23 binding remain unchanged. Portal uses a
separate in-memory manifest for selected runtime settings. The signed permissions,
not the operator choices, determine the workload's measured policy.

`GET /status` returns a top-level `runtime` object.

To retrieve it through the CLI, use
`atakit cloud status <instance> --live --json`. When the Portal request succeeds,
the object appears at `live.portal.runtime`.

Without `--live`, `cloud status --json` returns only saved deployment details.
Its `live` field is `null`, and runtime CPU settings are absent.

The live text output lists the requested idle driver, governor and disabled
states separately from the current driver and governor. Unsupported policies
include the reason. Live JSON preserves these values at
`live.portal.cpu_idle.requested`, `live.portal.cpu_idle.driver`, and
`live.portal.cpu_idle.governor`. With `driver = "auto"`, the requested driver
remains `auto` and the observed driver reports the guest's actual value.

The `runtime` object contains:

- `publisher.cpu`: the fixed settings and signed permission rules.
- `active.cpu` and `pending.cpu`: operator choices and per-field input sources.
  Sources are display labels, not security evidence.
- `activation.cpu_at_ms`: when the active request was selected for startup;
  consult `cpu_idle`/`cpu_frequency` for application outcomes.
- `observed.cpu.cpusets`: requested/selected CPU sets and unsupported-policy details.
- `observed.cpu.idle`, `observed.cpu.frequency`, `observed_at_ms`: guest snapshots.
- `active.disks`, `pending.disks`, `observed.disks`: disk queue choices and mappings.
- `active.thp`, `pending.thp`, `observed.thp`: THP choices and kernel readback.

See [runtime configuration](runtime-configuration.md) for persistence and THP.

Container status includes parent, dependency and existing baby containers.
`cpuset` is Podman's configured request; `effective_cpuset` is read from the
container's Linux cgroup. An unreadable or stopped container reports `null`
for the latter. These observations remain distinct from attestation claims.

### Shared runtime endpoint

The endpoint also accepts owner-selected disk queue modes. CPU `selection` is
optional when `runtime_disks` or `thp` is supplied. Omitted scopes preserve their pending
and active settings; supplied scopes replace their own pending scope. Disk modes
apply on VM reboot before disks open. See
[cloud disk configuration](cloud-disk-configuration.md) for the exact protocol.

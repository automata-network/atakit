# Runtime configuration (v0.3.7)

CPU choices, disk encryption workqueues and transparent huge pages (THP) share
one typed runtime configuration and the existing owner-authenticated flow.
THP lets Linux use 2 MiB pages for anonymous memory when an application requests
it with madvise. It is optional; the default remains `never`.

## Standalone runtime.toml grammar

This section defines the complete input format accepted by Atakit CLI 0.7.7
with `--runtime-config runtime.toml`. The file uses TOML. It contains the runtime
settings directly, without a `[runtime]` or `[cloud.*]` wrapper.

### Complete field list

Every field and table is optional in the input file. This is the complete list
of accepted fields; unknown fields and tables are rejected.

| Field or table entry | TOML value type | Meaning and accepted values |
| --- | --- | --- |
| `cpuset` | String | CPU list for the main workload, such as `"0-3,6"`. |
| `thp` | String | Exactly `"never"` or `"madvise"`. |
| `cpu-idle.governor` | String | CPU idle governor name, such as `"teo"`, `"menu"` or `"haltpoll"`. |
| `cpu-idle.disabled-states` | Array of strings | Idle state names, such as `["C6"]`; `[]` requests no additional disabled states. |
| `cpu-frequency.governor` | String | CPU frequency governor name, such as `"performance"` or `"powersave"`. |
| `dependencies.<service-name>` | String | CPU list for a dependency service declared in the workload. |
| `baby-containers.<slot-name>` | String | CPU list for a baby-container slot declared in the workload. |

`<service-name>` and `<slot-name>` are placeholders for actual names. Each table
can contain any number of these entries. Quote a key if its name contains a
dot, space or another character that TOML does not allow in an unquoted key.

`cpuset` and `thp` belong at the top level. Put them before the first table
header when using the table form below. In TOML, keys after a table header
belong to that table until another header appears; a blank line does not end
the table. Standard TOML dotted keys and inline tables also work. For example,
`cpu-idle.governor = "teo"` and `cpu-idle = { governor = "teo" }` express the
same setting as `[cpu-idle]` followed by `governor = "teo"`.

### Value grammar and limits

Every CPU list is a quoted string. Its contents follow this grammar, where
`{ ... }` means zero or more repetitions and `[ ... ]` means an optional part:

```text
cpu-list = item, { ",", item } ;
item     = number, [ "-", number ] ;
number   = digit, { digit } ;
digit    = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" ;
```

- CPU numbers are decimal guest CPU IDs from 0 through 1,048,575. Ranges include
  both ends, and the first number must not exceed the last.
- A CPU list must be nonempty and contain at most 8,192 distinct CPUs. Each
  range can contain at most 8,192 CPUs. The string can contain at most 65,535
  bytes. Spaces, empty items, negative numbers, `"online"` and `"*"` are rejected.
- Lists can repeat or overlap CPU IDs. Atakit sorts the IDs and removes
  duplicates before checking the selection.
- Governor and idle state names contain 1 to 64 ASCII letters, digits,
  underscores or hyphens. Names are case-sensitive. A syntactically valid name
  still needs workload permission and support from the VM.
- `disabled-states` can contain at most 128 strings before duplicate removal.
  Atakit sorts the names and removes duplicates. Wildcards are rejected.
- The whole file must be valid UTF-8 and no larger than 65,536 bytes (64 KiB).
  Use TOML strings and arrays, not JSON `null` or bare governor names. Duplicate
  field definitions and wrong value types are rejected.

### Complete syntax example

This example includes every supported field. Include only the settings you
need. The CPU IDs, service and slot names, and governors must be valid for the
actual workload and VM; this is not a universal tuning preset.

```toml
# Top-level fields must precede the table headers in this form.
cpuset = "0-3"
thp = "madvise"

[cpu-idle]
governor = "teo"
disabled-states = ["C6"]

[cpu-frequency]
governor = "performance"

[dependencies]
logger = "4-5"

[baby-containers]
tools = "6-7"
```

### Omission, permissions and checks

For CPU settings, resolution is per field:
**command-line flags > runtime file > target runtime settings > shared runtime defaults**.
THP resolves from the runtime file, then the target, then shared defaults.
There is no THP flag.
An omitted input field falls through to the next source; it does not request a
reset. Dependency and baby-slot maps merge by name. An explicit
`disabled-states = []` replaces an inherited state list; an empty dependency
or baby-slot table does not clear inherited entries. Use `cloud configure --reset`
to clear operator CPU choices, disk queue choices and THP together.

After merging sources, an operator CPU idle selection must include a governor.
For example, a file containing only `cpu-idle.disabled-states` needs an inherited
governor. CPU frequency selection likewise requires a governor. CPU choices
must stay within the signed workload's permissions. Actual CPU availability,
driver, governor and idle state support are checked at workload startup.
See [CPU permissions and startup behavior](workload-cpu-controls.md#operator-choices-within-publisher-permissions).

`required`, `driver`, `allow-operator` and the allowed-value lists belong to
the signed workload, not this file. Disk profiles and
`encryption_workqueues` belong to the operator's target configuration, not this
file. See [cloud disk configuration](cloud-disk-configuration.md).

`cloud configure --check` validates the resolved request against the signed
workload's permissions without saving or applying it. It does not prove that
the VM supports the settings. A valid empty file supplies no choices of its
own; `cloud configure` rejects a request with no resolved CPU, disk or THP
choices unless `--reset` is used.

## Operator input

The following example belongs in the operator's main
`~/.config/atakit/config.toml`. It shows target settings, including disk queue
choices. For a standalone file passed to `--runtime-config`, use the
[runtime.toml grammar above](#standalone-runtimetoml-grammar).

```toml
[cloud.targets.my-gcp]
disks.database = { profile = "fast-data", encryption_workqueues = "bypass" }

[cloud.targets.my-gcp.runtime]
cpuset = "0-3"
thp = "madvise"

[cloud.targets.my-gcp.runtime.cpu-idle]
governor = "teo"
```

Reuse `atakit cloud deploy`, `cloud init`, `cloud configure`, and their existing
`--runtime-config` file for CPU and THP choices. Disk queue choices come from
`cloud.targets.<target>.disks.<disk>.encryption_workqueues`; they are not accepted
in the runtime file. A THP-only file contains `thp = "madvise"` or
`thp = "never"`. Runtime file values override target values, which override
shared defaults. CPU flags keep their existing precedence. Disk profiles only
control disk creation; they do not reset runtime queues when queue selection is
omitted. No new command, flag, manifest permission, or state file is needed.

```sh
atakit cloud configure my-instance --runtime-config runtime.toml --check
atakit cloud configure my-instance --runtime-config runtime.toml
atakit cloud status my-instance --live --verify --json
```

Reboot the VM after staging. `atakit cloud reboot` currently supports AWS.
For GCP with Persistent Disk or Hyperdisk, use an orderly guest reboot or
stop/start while preserving the VM and disks. Stop/start can discard Local SSD
data; use an orderly in-guest reboot for a Local SSD workload. Do not substitute
a hard reset for an orderly reboot. Use the normal provider restart action for Azure.

Omitting THP preserves the saved active or pending choice. Use explicit `never`
to disable automatic THP. `--reset` resets CPU choices, disk queues and THP;
publisher-fixed CPU settings still apply. Identical successful choices are a
no-op. A repeated request can still cancel a different pending choice or request
a retry after failed startup.

## Authorization and persistence

Authenticated `/init` accepts optional `thp`. `POST /runtime-config` accepts
optional `selection`, `runtime_disks`, and `thp`; at least one scope is required.
Retain the existing owner signature, one-use challenge, TLS identity and manifest
hash binding, including signature domain `ATAKIT_RUNTIME_CPU_V1`. Validate all
supplied scopes before one atomic save. CPU permissions remain publisher-signed.
Disk queues and THP are owner choices. `--check` validates without saving/applying.

The existing `/atakit-portal/runtime-cpu.json` stores grouped `active` choices
and partial `pending` choices, with CPU source labels and existing boot metadata.
There is no second runtime file or duplicate representation. Supplied scopes
replace their pending scope; omitted scopes remain unchanged.

CPU choices activate at full workload startup. Disk queues and THP are selected
once per VM boot, before opening workload disks or starting containers. A
supervisor restart in the same boot reuses that selection. A later request made
during startup remains pending for the next boot. Failed application stops
workload startup and retains correction/retry information. Kernel writes cannot
form one atomic transaction: THP validates first, verifies writes and attempts
to restore prior settings if a write or readback fails.

## Fixed THP behavior

Both normal and debug kernels build THP support with the default `never`.
Only `never` and `madvise` are accepted; unknown values are rejected.

| Choice | enabled | defrag |
|---|---|---|
| never | never | never |
| madvise | madvise | defer |

The 2 MiB anonymous-page control inherits the selected policy. Other anonymous
page sizes and shared-memory automatic THP remain disabled. Portal exposes no
arbitrary sysfs path or defrag option. Missing required support rejects madvise;
a kernel without THP can still satisfy never.

Linux `never` disables automatic THP. It is not a security ban on applications
using `MADV_COLLAPSE`. THP does not change owner access or attestation guarantees.

## Status

`live.portal.runtime` groups `active`, `pending`, and `observed` CPU/disks/THP,
plus `activation`, `publisher.cpu`, manifest hash and observation time. Active
means saved selection; it does not prove application succeeded. Consult boot
confirmation, disk verification and `observed.thp.status/settings/detail`.
CPU application outcomes remain in `cpu_idle` and `cpu_frequency`.

THP performance depends on the workload. Unit tests establish parsing, owner
checks, state transitions and write rollback; actual page use and boot support
require tests of the built normal and debug images.

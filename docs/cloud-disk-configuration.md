# Cloud disk configuration

The v0.3.8 development branch extends the v0.3.7 disk profiles with AWS io2 and
Azure persistent and local disks. The workload declares each data disk's name, size,
encryption and service access. The operator, who is the instance owner, chooses
cloud creation settings and the encryption queue mode. These choices do not
change the signed workload manifest or its measurement.

## Operator configuration

```toml
[cloud.providers.aws-main]
platform = "aws"
region = "ap-southeast-1"

[cloud.disk_profiles.aws-fast]
disk_type = "aws-gp3"
iops = 6000
throughput_mibps = 250

[cloud.disk_profiles.aws-standard]
disk_type = "aws-gp3"

[cloud.targets.aws-node]
provider = "aws-main"
vmtype = "m6a.xlarge"
boot_disk = { profile = "aws-fast", size = "32GB" }
disks.database = { profile = "aws-fast", encryption_workqueues = "bypass" }
disks.logs = { profile = "aws-standard" }
```

Keep the target's usual image, chain and owner-key settings. `boot_disk` means
the VM OS volume. Its size must meet the workload's `boot-disk-size` minimum.
The existing `--boot-disk-size` flag takes precedence. The older target
`boot_disk_size` field remains accepted, but setting it together with
`boot_disk.size` is an error. Neither field names a workload data disk.

`database` and `logs` must match declared workload disk names. Each persistent profile use creates a separate disk. Local SSD uses the devices included with the VM. Profile names and target names have no provider meaning:
`target.provider` selects a provider, and the cloud prefix of `disk_type` must match that provider's `platform`. Unknown names, fields and queue modes are errors.

| Provider | Disk type | Performance fields |
| --- | --- | --- |
| AWS | `aws-gp3` | Optional `iops`, `throughput_mibps` |
| AWS | `aws-io2` | Required `iops`; throughput follows IOPS, so `throughput_mibps` is rejected |
| Azure | `azure-premium-ssd` | Neither performance field is accepted; performance follows the disk size |
| Azure | `azure-premium-ssd-v2`, `azure-ultra-disk` | Optional `iops`, `throughput_mibps`; workload data disks only |
| Azure | `azure-local-ssd` | No performance fields; groups all included local disks on DCedsv6 or DCadsv5/v6 |
| GCP | `gcp-pd-balanced`, `gcp-pd-ssd` | Neither performance field is accepted |
| GCP | `gcp-hyperdisk-balanced` | Optional `iops`, `throughput_mibps`; currently supported for C3/C4 standard targets |
| GCP | `gcp-local-ssd` | No performance fields; groups all included SSDs on supported C3 standard `-lssd` targets |

Hyperdisk boot profiles require C4. C4 rejects Persistent Disk profiles. Other
Hyperdisk machine families, including N2D configurations that require provider
enrollment, are rejected by this implementation. QEMU retains its existing disk
creation settings and does not accept these profiles. Azure retains Premium SSD
as its default when a disk has no profile.

Omitted profiles retain the existing provider behavior. Omitted performance
fields use provider defaults. Validation checks size, supported type, performance
ratios and known VM limits before cloud writes. AWS VM limits come from
`describe-instance-types`; GCP C3/C4 Hyperdisk limits use the documented table.
The VM limit is shared across its disks. The preview reports explicit totals and
any aggregate bottleneck. Unavailable quota/capacity information is reported as
not checked. A check does not reserve resources or promise application latency.

The validation sources include [AWS gp3 limits](https://docs.aws.amazon.com/ebs/latest/userguide/general-purpose.html),
[AWS io2 limits](https://docs.aws.amazon.com/ebs/latest/userguide/provisioned-iops.html),
[Azure disk limits](https://learn.microsoft.com/en-us/azure/virtual-machines/disks-types)
and [GCP Hyperdisk Balanced limits](https://docs.cloud.google.com/compute/docs/disks/hd-types/hyperdisk-balanced).

### Azure placement and performance

Set `availability_zone = "1"`, `"2"` or `"3"` on an Azure target that selects
Premium SSD v2 or Ultra Disk. Atakit requires zonal placement for these types.
The provider's `region` still names the region. The deploy check reads Azure's
live SKU catalog to check the exact VM, disk type, subscription restrictions
and zone. Ultra Disk also requires `UltraSSDAvailable` for the selected VM and
zone. Atakit checks the VM's shared disk limits when Azure reports them.
Provider creation still decides current capacity.

```toml
[cloud.disk_profiles.azure-fast]
disk_type = "azure-premium-ssd-v2"
iops = 6000
throughput_mibps = 250

[cloud.disk_profiles.azure-ultra]
disk_type = "azure-ultra-disk"
iops = 20000
throughput_mibps = 1000

[cloud.targets.azure-node]
provider = "azure-main"
vmtype = "Standard_DC32es_v6"
availability_zone = "1"
disks.database = { profile = "azure-fast" }
```

Azure's API accepts whole decimal MB/s. Atakit retains the existing
`throughput_mibps` field, converts to MB/s and rounds up. For example, 250 MiB/s
requests 263 MB/s. The preview shows both values. Validation uses the converted
value, including the disk's maximum and IOPS ratio. Live inventory displays
whole MiB/s rounded down, while disk verification checks the exact MB/s value.
The largest accepted throughput is 1907 MiB/s for Premium SSD v2 and 9536 MiB/s
for Ultra Disk. Small disks and low IOPS settings can impose lower limits.

## Create, inspect and change queue modes

```sh
atakit cloud deploy app:v1 --target aws-node --name app-aws-node --check-only
atakit cloud deploy app:v1 --target aws-node --name app-aws-node
atakit cloud status app-aws-node --target aws-node --live --json

# Edit encryption_workqueues in the target, then validate and stage it.
atakit cloud configure app-aws-node --target aws-node --check
atakit cloud configure app-aws-node --target aws-node
```

The deploy preview prints the boot size, each data disk, profile settings, queue
mode and capability checks. Creation settings are saved with the deployment.
AWS and GCP send performance settings in disk creation. Azure creates empty
managed disks inside the conditional VM creation request. For Premium SSD v2
and Ultra Disk it disables host caching; Ultra Disk also enables the VM's
`ultraSSDEnabled` capability. Azure's VM API does not accept disk performance
values, so Atakit applies them with a disk PATCH after verifying creation,
ownership, size, type, attachment and immutable disk identity. It saves the
existing disk creation record before this update, then checks the exact settings
and identity before granting initialization permission. A lost reply can resume
by reading the disk. A pending update does not grant initialization permission.
A disk whose setup already finished is never retuned by resume.
Editing a profile does not resize,
retune, replace or format an existing disk. `cloud resume` uses the saved request;
it does not resolve updated profiles. It can finish saved disk and VM creation,
waiting and attachment steps. It does not repeat image uploads or network setup.

`cloud configure` sends target queue choices through the existing owner-signed
runtime endpoint. Cloud performance settings and `boot_disk` are creation-only. The Local SSD binding is sent in the existing authenticated initialization configuration; runtime configuration cannot change it. The queue choices take effect on the next VM reboot.
`--check` saves nothing. `--reset` resets CPU choices, all disk queue modes and THP.

## Automatic initialization of fresh cloud data disks

Normal AWS, Azure and GCP deployment needs no initialization flag for its newly
created empty workload disks. The CLI records provider disk IDs, actual settings
and attachment identity. GCP and Azure reject an existing disk with the planned
name. Restored source disks do not qualify. A recorded name or plan alone is
insufficient. Azure profiles choose the managed-disk SKU in the conditional VM
request. Local disks use the original VM creation proof and the guest's device
identity checks instead of a managed-disk creation record.

The CLI saves a single initialization request before provisioning. Its planned
`disk_setup=create` entries are conditional: immediately before sending `/init`,
it must verify fresh creation records, the VM identity, disk IDs, exact
attachments and saved settings. Missing or changed evidence stops submission.
Optional VM catalog information is not part of this identity check.
An interrupted `/init` send is never resent automatically. Cloud creation and
attachment can resume only before `/init` may have been sent.

After `cloud deploy --skip-init`, delayed `cloud init` can use these records only
for the exact saved workload archive. Explicit `--disk-setup` choices retain
their existing meaning. QEMU and unmanaged initialization retain explicit
creation permission. No automatic overwrite is introduced.

Portal still validates the manifest disk name and probes the device. It consumes
each one-time permission before the first destructive write. An interrupted
format does not renew permission. See [disk unlock](disk-unlock-spec.md).

### Creation records and recovery

Atakit CLI 0.7.7 saves requests, provider retry tokens, creation results and
progress in the existing private local state file:
`<data_dir>/cloud/deployments/<target>/<instance>.state.json`.
These records prove which cloud resources the CLI created. They do not record
whether Portal has formatted a disk. Portal keeps its existing disk recognition
and one-time permission rules. Normal VM boots do not consult the CLI state.

- AWS creates each workload volume with `CreateVolume` without a source. It
  saves the returned `VolumeId` before waiting or attaching. An uncertain reply
  retries the exact saved request with the same `ClientToken`. A saved successful
  result is never submitted again. Only the recorded volume can occupy its
  intended device slot. Separate attachments retain `DeleteOnTermination=true`.
- GCP uses Compute Engine insert requests with a saved `requestId`. Recovery
  reads the matching operation and compares its `targetId` with the resource's
  numeric ID. An existing resource name alone cannot establish creation.
- Azure creates workload disks inside the VM request with `createOption=Empty`,
  explicit names and LUNs. The VM PUT sends `If-None-Match: *`; it cannot update
  an existing VM. Existing disks require Attach and are rejected by this path.
  Atakit saves the original VM response and `vmId`, then checks the same VM,
  Empty attachments, disk ownership and each disk's `uniqueId` before granting
  initialization permission. Standalone managed-disk PUT is blocked: Azure
  ignores its create-only header and may update an existing disk.
- Azure creates NSGs, VNets and static-IP NICs through direct requests and saves each original
  resource ID and `resourceGuid` before waiting for completion. NIC, VNet and NSG
  requests use `If-None-Match: *`. Each direct network creation must return HTTP 201;
  HTTP 200 is an update and cannot grant ownership. Each resource has its own
  saved request, so failure does not lose earlier resources or repeat their PUTs.
  Standalone public-IP PUT is blocked because Azure ignores its create-only
  condition. Automatic NICs and Standard static public IPs are created within
  the conditional VM request using `networkInterfaceConfigurations`. Atakit
  requires the original VM response's NIC reference, unchanged VM attachment,
  matching NIC/VM and IP/NIC links, requested subnet, and Detach settings before
  saving the network resource GUIDs. Azure chooses the generated resource names.
  Operator-selected existing public IPs remain references and are never adopted.

`atakit cloud resume <instance> --target <target>` continues the saved steps and
then verifies the VM, boot disk and all workload disks. It accepts an already
completed exact attachment. A different attachment, changed setting, missing
confirmed resource, or missing original creation evidence stops recovery.
Repeated resume does not create new resources or renew formatting permission.
After `--skip-init`, resume finishes provisioning and directs the operator to
`atakit cloud init`.

Creation records distinguish requests not submitted, definite rejection,
unknown outcome, acceptance, success and failure after acceptance. A definite
rejection permits another attempt with a new provider request token. A timeout
or lost response does not. An authentication failure during recovery also does
not erase an earlier unknown outcome. Failed ARM deployments may contain
resources and are never treated as pre-request rejection.

Provider operation history has limited retention. Missing original GCP operation
evidence stops recovery. A lost Azure VM or network PUT response without its
immutable identity also stops recovery; Atakit does not adopt a resource by name.
The command retains local state and reports possible resources and charges.
Recovery requires this local state.

Boot disk recording precedes public-IP lookup and workload disk setup. The CLI
uses the original VM creation response when it contains the boot reference;
otherwise it reads the verified VM. Recovery checks the original VM identity
before accepting an unrecorded boot disk from a saved response. The existing
`created_boot_disk` field keeps the observed identity even when its settings
fail validation. Settings errors still block provisioning and initialization.
This uses the existing state file and creation records.

`atakit cloud destroy` reconciles creation records through read-only provider
calls. It does not create resources. An unresolved request does not block
cleanup of other verified resources. Each disk has its own deletion step.
Each completed deletion is saved, so another destroy skips completed steps.
Once cleanup starts, `cloud resume` refuses to restart provisioning.

Older CLI versions saved disk names without their original provider IDs.
For those disks, destroy reads the current IDs internally and asks for explicit
permission to delete the listed boot and data disks. This also works after an
earlier destroy deleted the VM, provided the disk reference remains in local
state. A disk name or current VM attachment alone does not establish creation.

The disk prompt follows the normal deployment confirmation. `--yes` skips only
the normal prompt; it never approves unrecorded disks. Without terminal input,
or when the operator declines, the CLI retains the disks, continues other safe
cleanup, and explains that disk deletion needs an interactive run. Cancelling
the normal prompt saves no new approvals. Parallel destroys serialize prompts
and identify the deployment in each question. Preserved data disks are excluded
from the deletion prompt.

Approval applies only to disk references saved for that deployment and within
its provider scope. The CLI rechecks the IDs held before the prompt; approval
cannot authorize a replacement. An attached disk can be approved only when all
attachments refer to the original VM and its saved identity still matches.
Before deletion, the CLI checks the approved ID again and requires detachment.
A changed ID, foreign attachment or failed read blocks deletion. Confirmed
absence completes a cleanup step without a deletion request.

The existing cleanup state stores approvals in `confirmed_disks`, with the
provider ID and boot-disk role. This separate record is needed for safe retries
without claiming proof of creation or granting initialization permission.
Approvals are saved only after confirmation and successful checks, together
with cleanup start, before deletion. Azure's group inventory recognizes approved
and intentionally preserved data disks consistently with the per-disk report.
Error output distinguishes missing approval from failures that can be retried
after their cause is resolved.

Before deleting a VM, cleanup prevents deletion of attached resources:

- AWS clears and verifies `DeleteOnTermination` for all EBS attachments.
- GCP disables and verifies automatic deletion for each Persistent Disk.
  Local SSD contents leave with the VM.
- Azure sets and verifies `deleteOption=Detach` for disks and network interfaces.

VM deletion also requires a successful attached-disk inventory. If that lookup
fails, cleanup retains the VM, attempts a verified stop/deallocation, and
continues independent safe cleanup. A retry clears the inventory error only
after a successful inventory; VM absence alone cannot recover the missing disk
list. Unknown disks remain reported through the existing cleanup fields.

The command then deletes each verified boot disk and workload disk separately.
`--preserve disks` retains workload disks; it does not retain the disposable boot
disk. On retries, `--preserve disks` and `--preserve firewall` report only
resources without a completed deletion in the existing `cleanup.completed`
records. Adding a preserve flag cannot restore a resource deleted by an earlier
attempt. Deleted resources do not cause local state to be retained. Azure still
checks resources listed after a completed deletion and reports any that remain
or whose absence it cannot verify. Unverified disks remain untouched. If a
verified VM cannot be deleted, cleanup tries to stop it on AWS/GCP or deallocate
it on Azure, then checks its
power state. A missing or changed VM identity forbids both deletion and power
changes. Failed shutdown checks explicitly report that compute charges may
continue. Stopped/deallocated VMs can still have chargeable disks and addresses.

If a VM deletion request returns an error but the follow-up check confirms the
VM is absent, or AWS reports it fully terminated, cleanup marks the existing
deletion step complete. This requires successful attachment checks and an actual
deletion attempt. A stopped GCP VM or deallocated Azure VM is still present.
Failed verification keeps the step incomplete for retry. This uses existing
completion records and writes, with no additional state files or records.

Azure cleanup never deletes a whole resource group. It checks saved identities
before deleting owned network interfaces, public IPs, virtual networks and
network security groups. It lists the remaining group members, including
rejected or foreign disks. Empty groups remain and are reported. Operator-supplied
reserved IPs and shared images remain and are reported. AWS `--clean-image`
reuses the image-removal journal, keeping snapshot IDs before deregistration so
partial snapshot deletion can be retried.

Unexpected leftovers, unknown creation outcomes and failed deletion or inventory
checks return a nonzero exit status. Output lists resource references, reasons,
and the last checked VM power state. State remains available for another
`atakit cloud destroy`; `cloud status` also shows the saved cleanup report.
GCP cleanup refreshes each pending creation operation once and checks that it
matches the saved request. A completed creation failure closes that request only
after a separate resource lookup confirms absence. A resource found at the same
name remains untouched: a failed operation does not prove ownership. Pending
operations and failed lookups keep the deployment state for another cleanup try.
Intentional preservation of workload disks or firewall resources can finish
successfully while retaining their state. An empty Azure group or an operator-owned
reserved IP is reported without keeping an active deployment that blocks name
reuse. No disk is resized or retuned during recovery or cleanup.

The Azure VM conditional header and Empty disk creation semantics are described
in [Virtual Machines — Create or Update](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/create-or-update?view=rest-compute-2025-04-01).
The CLI records direct resource-creation responses and verifies ownership
before recovery or cleanup. Standalone public-IP creation is blocked before
any provider call.

## Portal protocol and enforcement

Init configuration schema **4** adds `runtime_disks`. Existing authenticated
multipart `POST /init` binds the full configuration hash, including this field
and `disk_setup`, to the temporary deployment initialization key.

```json
{
  "format": 4,
  "disk_setup": { "database": "create", "logs": "create" },
  "runtime_disks": {
    "database": { "encryption_workqueues": "bypass" },
    "logs": { "encryption_workqueues": "default" }
  }
}
```

This is the disk-related subset of the existing init document. The temporary
initialization key is separate from the instance owner key.

For later changes, get `GET /runtime-config/challenge`, then send:

```json
{
  "manifest_hash": "<SHA-256 of the exact stored manifest bytes>",
  "runtime_disks": {
    "database": { "encryption_workqueues": "bypass" }
  },
  "check": false
}
```

`POST /runtime-config` retains `atakit-runtime-challenge` and
`atakit-owner-signature`. The instance owner signs the existing digest:

```text
SHA256(L("ATAKIT_RUNTIME_CPU_V1") || L(tls_hex) || L(challenge_hex)
       || L(SHA256(raw_request_body)))
L(value) = u64-big-endian byte length || value bytes
```

The signature covers disk-only and combined requests. Portal checks the owner
signature, live TLS binding and one-use 60-second challenge. The request limit is
64 KiB. Unknown fields, duplicate disk names, unknown disk names, unsupported
modes and bypass on unencrypted disks fail. The endpoint accepts no `disk_setup`,
device paths or arbitrary cryptsetup arguments. The supervisor rechecks manifest
integrity and the exact hash before staging or preparing disk settings.

The CPU `selection`, `runtime_disks`, and `thp` scopes are optional individually; at least
one is required. Omitted scopes preserve both active and pending settings. Each
supplied scope replaces its whole pending scope. Omitted declared disk names in
a supplied disk map normalize to `default`; `{}` resets the disk scope. All supplied
scopes validate before any changes. An update does not restart services.

Before opening disks, the supervisor freezes a disk selection with the current
kernel boot ID and saves it atomically. A worker or supervisor restart in the
same VM boot reuses that selection. On the next VM boot it selects pending
settings. Confirmation clears only the pending selection actually applied, so a
new request arriving during startup survives for the next boot.

`bypass` adds exactly `NO_READ_WORKQUEUE` and `NO_WRITE_WORKQUEUE`. Both ordinary
LUKS TPM/passphrase paths and integrity-enabled create/reopen paths receive the
flags. The boot RW partition and private baby root mappings keep their existing
policies. Encryption, integrity journaling, authenticated headers, key release,
PCR binding, sector size, discard and service access policies do not change.

Portal reads the live mapping flags before mounting and again for status. A
mismatch blocks startup. Disk settings become confirmed only after all declared
disks mount with verified flags. Failed startup retains a pending correction.

## Status and validation limits

`cloud status --live --json` reports:

- `saved.disk_configuration`: the resolved creation settings and profile names.
- `saved.created_disks`: creation observations and immutable provider disk IDs.
- `live.cloud_disks`: provider observations for boot/data disks, source and known
  shared VM limits. Identity or settings conflicts are errors, never edits.
- `live.portal.runtime.active.disks` and `pending.disks`: saved queue choices.
- `live.portal.runtime.activation`: boot IDs and `disks_verified_this_boot`.
- `live.portal.runtime.observed.disks`: actual kernel queue flags/backing mapping.

If the optional shared-limit lookup fails or times out, status marks those limits
as not checked and retains the verified disk observations.

The active selection is historical unless `disks_verified_this_boot` is true. Closing
a disk removes its live observation. Status reads no encryption keys and never
uses a key-bearing device-mapper table. Plain `--live` guest observations are
unverified; use the existing `--live --verify` flow for attested Portal TLS.

Repository tests cover configuration validation, provider creation arguments,
identity conflicts, owner authorization, replay, pending-scope behavior, boot
selection and queue flags. Live cloud performance and kernel activation require
separate integration tests; these tests do not establish a latency improvement.

## GCP Local SSD grouping

```toml
[cloud.disk_profiles.local]
disk_type = "gcp-local-ssd"

[cloud.targets.my-gcp]
vmtype = "c3-standard-8-lssd"
disks.database = { profile = "local" }
```

Keep the existing target provider/image choices. Exactly one declared workload
disk may select Local SSD; it receives all devices included with the VM. One
member is used directly. Multiple members form a Linux MD RAID 0 array before
the existing encryption and filesystem layers. RAID 0 has no redundancy. Local
SSD contents can be lost with VM stop/deletion or host failure. No automatic
recreation of lost members is introduced.

CLI derives the expected member count from the supported C3 machine type,
checks capacity, and skips Persistent Disk creation for that workload disk.
The existing init request carries `local_ssd = {disk, count}`. No new state file
or duplicate disk creation record is added. Before granting automatic creation,
the CLI checks the VM creation result, current VM identity and SCRATCH members.
Portal checks the manifest disk, authoritative GCP identity, and namespace
`disk_type=LOCAL_SSD`/`device_name=local-nvme-ssd-N` values. It never selects the
boot disk by Linux enumeration order.

Array creation consumes the existing one-time `disk_setup` permission before
writing RAID metadata. Members must pass the existing disk metadata checks.
Normal encryption, filesystem creation, unlock and service mounting follow.
On reboot Portal assembles the existing RAID metadata and checks array UUID,
level, count and actual members. Mixed, missing or unexpected members fail;
Portal does not silently recreate the array or renew creation permission.
Array metadata lives on the members; the selected binding lives in existing
init-config.json. Cloud cleanup retains only Persistent Disks when requested;
Local SSD always leaves with the VM.

## Azure local SSD grouping

```toml
[cloud.disk_profiles.azure-local]
disk_type = "azure-local-ssd"

[cloud.targets.azure-local-node]
provider = "azure-main"
vmtype = "Standard_DC32eds_v6"
disks.database = { profile = "azure-local" }
```

DCedsv6 uses Intel TDX. DCadsv5 and DCadsv6 use AMD SEV-SNP. Availability is
checked against Azure's live VM catalog. A published VM family may not be
available in the selected subscription and region.

Exactly one workload disk receives all included local disks. The CLI derives
the count and capacity from the VM size and skips managed-disk creation for that
workload disk. The existing `local_ssd = {disk, count}` initialization binding
and one-time disk setup permission are reused. No new workload permission or
state file is added. The CLI checks the original VM identity, VM size,
ConfidentialVM security type and managed OS disk before automatic initialization.

Portal uses its authoritative Azure identity to choose the resolver. NVMe disks
must have the exact `Microsoft NVMe Direct Disk v2` model and namespace metadata
with `type=local`, a name and a complete set of unique indexes starting at one.
SCSI resource disks must match Azure's resource-controller ID, disk vendor,
model and LUN. OS and remote data disks do not qualify. See Microsoft's
[disk identification rules](https://github.com/Azure/azure-vm-utils/blob/main/doc/disk-identification.md).

One member is used directly. Multiple members use the same RAID 0 assembly,
encryption and filesystem path as GCP. Six-member groups are supported for the
corresponding DCedsv6 sizes. Existing metadata, incomplete arrays and unexpected
devices retain the normal refusal rules. An Azure resource disk can already
contain disk metadata when the VM is created. Automatic `create` permission
then refuses to format it. To erase the selected local disk on a new deployment,
add `--disk-setup database=overwrite` to `atakit cloud deploy`, replacing
`database` with that workload disk's name. This uses the existing one-time
overwrite permission; it is consumed before formatting and is not repeated on
reboot.

Local data can be lost on VM
deallocation, deletion or host failure. Atakit does not recreate lost data on
reboot, and `--preserve disks` cannot preserve local disks after VM deletion.

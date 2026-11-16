# Remove an uploaded cloud image

```sh
atakit cloud image rm automata-linux:v0.3.2 --provider aws-us-east-2
```

The command requires a tracked image reference and a configured provider. It
shows the removal plan and asks for confirmation. Use `-y` to accept that plan
without prompting. It does not require the local base-image archive or CC types.

- AWS: deregisters the matching owned AMI and deletes its backing snapshots.
- GCP: deletes the tracked image from the configured project.
- Azure: deletes the tracked gallery image version from the configured
  subscription. Other versions, the image definition, and gallery remain.
- QEMU: has no uploaded cloud image; use `atakit image rm` for local images.

Removal preserves VMs, workload disks, local image files, and upload buckets.
The command refuses removal while a locally tracked deployment uses the image.
An unreadable deployment record also blocks removal. Deployments outside the
current atakit data directory are not included in this check.

Before deletion, atakit saves the exact removal targets in the upload record.
On failure, the record remains. Rerun the same command to finish cleanup; for
example, an AWS snapshot deletion can be retried after its AMI is already gone.
Uploads of that image/provider are blocked while this removal is incomplete.
The upload record is removed only after all deletions succeed.

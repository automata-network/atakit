# Static IPs For Cloud Deploy

`atakit cloud deploy` can attach an existing operator-managed static public IP
resource during deployment.

## CLI Flags

```sh
atakit cloud deploy <workload>:<version> \
  --target <target> \
  --name <deployment-name> \
  --static-ip <ref> \
  --yes
```

Provider-specific meaning of `--static-ip <ref>`:

- GCP: reserved address name.
- Azure: Public IP resource name.
- AWS: Elastic IP allocation ID, once AWS support is wired.

Azure has one extra flag when the Public IP lives outside the deployment's
default resource group:

```sh
--static-ip-resource-group <resource-group>
```

## Examples

GCP:

```sh
atakit cloud deploy fedora-oci:v0.0.13 \
  --target gcp-c3-standard-4 \
  --name fedora-demo \
  --static-ip my-reserved-address \
  --yes
```

Azure:

```sh
atakit cloud deploy fedora-oci:v0.0.13 \
  --target azure-snp \
  --name fedora-demo \
  --static-ip my-public-ip \
  --static-ip-resource-group my-network-rg \
  --yes
```

## Config File

Static IPs can be configured on a cloud target:

GCP:

```toml
[cloud.targets.gcp-c3-static]
provider = "gcp-sea"
vmtype = "c3-standard-4"
static_ip = "my-reserved-address"
```

Azure:

```toml
[cloud.targets.azure-snp-static]
provider = "azure-eastus"
vmtype = "Standard_DC4as_v5"
static_ip = "my-public-ip"
static_ip_resource_group = "my-network-rg"
```

Precedence:

1. CLI flags: `--static-ip` and `--static-ip-resource-group`
2. Target config: `static_ip` and `static_ip_resource_group`

Azure static IP deployments require `static_ip_resource_group`. The resource
group must not be the per-deployment resource group named `<deployment-name>-rg`,
because `cloud destroy` deletes that group.

Static IP is not supported for `qemu` targets.

## Operational Notes

- Create or reserve the static IP in the cloud provider before running
  `atakit cloud deploy`.
- The static IP resource is operator-managed. Treat it as independent
  infrastructure, not as an ephemeral deployment artifact.
- Destroying an atakit deployment should not be assumed to delete the static IP.
  Release or delete the static IP separately if you no longer want it.
- A static IP only stabilizes the network address. It does not change portal
  TLS trust; clients still need the existing certificate handling or an
  attestation-bound TLS flow.

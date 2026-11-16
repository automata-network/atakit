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
- AWS: Elastic IP allocation ID (`eipalloc-...`) in the provider's region.

Azure also requires the Public IP's resource group, which must be separate
from the deployment's resource group:

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

AWS:

```sh
atakit cloud deploy fedora-oci:v0.0.13 \
  --target aws-snp \
  --name fedora-demo \
  --static-ip eipalloc-0123456789abcdef0 \
  --yes
```

Reserve the Elastic IP in the AWS account and region used by the target before
deploying. Pass its allocation ID, not the numeric IP address or its Name tag.
Atakit checks the allocation before creating the VM and refuses an address
already associated with another resource. It also disables reassociation in
the attachment request, so it cannot take an address attached after that check.
The AWS identity needs `ec2:DescribeAddresses` and `ec2:AssociateAddress` in
addition to its existing deployment permissions.

Atakit attaches the Elastic IP before waiting for the portal or initializing
the workload. A failed attachment leaves the VM recorded for
`atakit cloud destroy` and provisioning incomplete; `cloud resume` cannot
initialize that incomplete deployment. Destroy the failed deployment and retry
after fixing the allocation or permissions.

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

AWS:

```toml
[cloud.targets.aws-snp-static]
provider = "aws-ohio"
vmtype = "m6a.large"
static_ip = "eipalloc-0123456789abcdef0"
```

The provider names in these examples refer to your `[cloud.providers]` entries.

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
- For AWS, `atakit cloud destroy` terminates the VM and leaves the Elastic IP
  allocated to your account for reuse. Atakit does not allocate or release
  Elastic IPs. AWS continues to charge for a reserved address until you release
  it. See [AWS Elastic IP documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html).
- A static IP only stabilizes the network address. It does not change portal
  TLS trust; clients still need the existing certificate handling or an
  attestation-bound TLS flow.

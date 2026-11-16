use crate::config::CcType;
use crate::error::CloudError;
use crate::exec::CommandRunner;
use base64::Engine;

/// Create an Azure CVM instance. Returns the external IP address.
///
/// Compute creates new Empty data disks in the create-only VM request.
#[allow(clippy::too_many_arguments)]
pub async fn create_instance(
    subscription: &str,
    rg: &str,
    name: &str,
    vm_size: &str,
    image_id: &str,
    _cc_type: CcType,
    nsg: &str,
    metadata: &[(String, String)],
    boot_disk_size_gb: Option<u64>,
    static_public_ip_id: Option<&str>,
    disks: &[crate::DiskSpec],
    availability_zone: Option<&str>,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    if let Some(saved) = runner.recorded_creation("instance").await? {
        let recovering = saved.result.is_some() || saved.receipt.is_some();
        let value = runner.create_resource("instance", &saved.request).await?;
        return finish_creation(subscription, rg, name, &value, recovering, runner).await;
    }
    let api = "2024-11-01";
    let network_api = "2024-05-01";
    let prefix = format!("/subscriptions/{subscription}/resourceGroups/{rg}/providers");
    let network_name = format!("{name}-vnet");
    let network_id = format!("{prefix}/Microsoft.Network/virtualNetworks/{network_name}");
    let nic_name = format!("{name}-nic");
    let nic_id = format!("{prefix}/Microsoft.Network/networkInterfaces/{nic_name}");
    let ip_name = format!("{name}-ip");
    // Resolve location from the resource group, which is already saved/created.
    let out = runner
        .run_capture(
            "az",
            &[
                "group",
                "show",
                "--subscription",
                subscription,
                "--name",
                rg,
                "--query",
                "location",
                "--output",
                "tsv",
            ],
        )
        .await?;
    let location = out.stdout.trim();
    if location.is_empty() {
        return Err(crate::provisioning::error("Azure group has no location"));
    }
    let mut resources = vec![
        serde_json::json!({"type":"Microsoft.Network/virtualNetworks","apiVersion":network_api,
        "name":network_name,"location":location,"properties":{"addressSpace":{"addressPrefixes":["10.0.0.0/16"]},
        "subnets":[{"name":"default","properties":{"addressPrefix":"10.0.0.0/24"}}]}}),
    ];
    if let Some(public_ip) = static_public_ip_id {
        resources.push(serde_json::json!({"type":"Microsoft.Network/networkInterfaces","apiVersion":network_api,"name":nic_name,
            "location":location,"properties":{"networkSecurityGroup":{"id":format!("{prefix}/Microsoft.Network/networkSecurityGroups/{nsg}")},
            "ipConfigurations":[{"name":"primary","properties":{"privateIPAllocationMethod":"Dynamic","subnet":{"id":format!("{network_id}/subnets/default")},"publicIPAddress":{"id":public_ip}}}]}}));
    }
    for disk in disks {
        if crate::azure::disk::check_disk_exists(subscription, rg, &disk.name, runner).await? {
            return Err(crate::provisioning::error(format!(
                "Azure disk {} already exists; refusing modification",
                disk.name
            )));
        }
    }
    let mut os_disk = serde_json::json!({"createOption":"FromImage","deleteOption":"Detach","osType":"Linux",
        "managedDisk":{"storageAccountType":"Premium_LRS","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}});
    if let Some(size) = boot_disk_size_gb {
        os_disk["diskSizeGB"] = size.into();
    }
    let tags: serde_json::Map<String, serde_json::Value> = metadata
        .iter()
        .filter(|(k, _)| k != "atakit-init-auth")
        .map(|(k, v)| (k.clone(), v.clone().into()))
        .collect();
    let mut vm = serde_json::json!({"type":"Microsoft.Compute/virtualMachines","apiVersion":api,"name":name,
        "location":location,"dependsOn":[nic_id.clone()],"tags":tags,"properties":{
        "hardwareProfile":{"vmSize":vm_size},"storageProfile":{"imageReference":{"id":image_id},"osDisk":os_disk,"dataDisks":disks.iter().map(|d| serde_json::json!({"name":d.name,"lun":d.index,"createOption":"Empty","deleteOption":"Detach","diskSizeGB":d.size_gb,"managedDisk":{"storageAccountType":d.disk_type}})).collect::<Vec<_>>()},
        "networkProfile":{"networkInterfaces":[{"id":nic_id,"properties":{"deleteOption":"Detach"}}]},
        "securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"vTpmEnabled":true,"secureBootEnabled":true}}}});
    if let Some(zone) = availability_zone {
        vm["zones"] = serde_json::json!([zone]);
    }
    if disks.iter().any(|d| d.disk_type == "UltraSSD_LRS") {
        vm["properties"]["additionalCapabilities"]["ultraSSDEnabled"] = true.into();
    }
    // Premium SSD v2 and Ultra Disk do not support host caching. Their
    // performance is applied to the verified newly created disks afterwards.
    for disk in vm["properties"]["storageProfile"]["dataDisks"]
        .as_array_mut()
        .unwrap()
    {
        if matches!(
            disk["managedDisk"]["storageAccountType"].as_str(),
            Some("PremiumV2_LRS" | "UltraSSD_LRS")
        ) {
            disk["caching"] = "None".into();
        }
    }
    if static_public_ip_id.is_none() {
        // Compute allocates the NIC and public IP as part of the conditional VM
        // creation. Never PUT a standalone public IP: that API can update an
        // existing address even when If-None-Match is supplied.
        vm["properties"]["networkProfile"] = serde_json::json!({
            "networkApiVersion":"2022-11-01",
            "networkInterfaceConfigurations":[{"name":nic_name,"properties":{
                "primary":true,"deleteOption":"Detach",
                "networkSecurityGroup":{"id":format!("{prefix}/Microsoft.Network/networkSecurityGroups/{nsg}")},
                "ipConfigurations":[{"name":"primary","properties":{
                    "primary":true,"subnet":{"id":format!("{network_id}/subnets/default")},
                    "publicIPAddressConfiguration":{"name":ip_name,"sku":{"name":"Standard"},"properties":{
                        "deleteOption":"Detach","publicIPAllocationMethod":"Static","publicIPAddressVersion":"IPv4"
                    }}
                }}]
            }}]
        });
    }
    if let Some((_, bootstrap)) = metadata.iter().find(|(k, _)| k == "atakit-init-auth") {
        let user_data = atakit_init_auth::encode_user_data(&serde_json::from_str(bootstrap)?)?;
        vm["properties"]["userData"] = base64::engine::general_purpose::STANDARD
            .encode(user_data)
            .into();
    }

    for mut resource in resources {
        let id = format!(
            "{prefix}/{}/{}",
            resource["type"].as_str().unwrap(),
            resource["name"].as_str().unwrap()
        );
        let key = format!("network:{}", resource["name"].as_str().unwrap());
        if !runner.creation_recorded(&key).await? {
            match runner
                .run_capture(
                    "az",
                    &[
                        "resource",
                        "show",
                        "--ids",
                        &id,
                        "--api-version",
                        resource["apiVersion"].as_str().unwrap(),
                        "--output",
                        "json",
                    ],
                )
                .await
            {
                Ok(_) => {
                    return Err(crate::provisioning::error(format!(
                        "Azure resource already exists: {id}; refusing modification"
                    )))
                }
                Err(CloudError::CommandFailed { stderr, .. })
                    if stderr.contains("ResourceNotFound") => {}
                Err(e) => return Err(e),
            }
        }
        for field in ["type", "apiVersion", "name", "dependsOn"] {
            resource.as_object_mut().unwrap().remove(field);
        }
        runner
            .create_resource(
                &key,
                &crate::provisioning::CreateRequest::AzureNetwork {
                    id,
                    api_version: network_api.into(),
                    body: resource,
                },
            )
            .await?;
    }
    // VM PUT enforces If-None-Match. Compute creates each Empty data disk;
    // this request never PUTs a standalone managed disk resource.
    vm.as_object_mut().unwrap().remove("type");
    vm.as_object_mut().unwrap().remove("apiVersion");
    vm.as_object_mut().unwrap().remove("name");
    vm.as_object_mut().unwrap().remove("dependsOn");
    let value = runner
        .create_resource(
            "instance",
            &crate::provisioning::CreateRequest::AzureVm {
                subscription: subscription.into(),
                group: rg.into(),
                name: name.into(),
                body: vm,
            },
        )
        .await?;
    finish_creation(subscription, rg, name, &value, false, runner).await
}

async fn finish_creation(
    subscription: &str,
    rg: &str,
    name: &str,
    value: &serde_json::Value,
    recovering: bool,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let vm_id = format!("/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}");
    let identity = crate::provisioning::identity(&value["properties"]["vmId"])?;
    if !value["id"]
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(&vm_id))
    {
        return Err(crate::provisioning::error(
            "Azure creation returned a different VM",
        ));
    }
    runner
        .record_created_instance(name, "", false, Some(&identity))
        .await?;
    let current = if recovering {
        Some(read_created_vm(subscription, rg, name, &identity, runner).await?)
    } else {
        None
    };
    let original = &value["properties"];
    let has_boot_reference = original["storageProfile"]["osDisk"]["managedDisk"]["id"]
        .as_str()
        .is_some();
    if has_boot_reference
        && current.as_ref().is_some_and(|vm| {
            !vm["storageProfile"]["osDisk"]["managedDisk"]["id"]
                .as_str()
                .zip(original["storageProfile"]["osDisk"]["managedDisk"]["id"].as_str())
                .is_some_and(|(live, original)| live.eq_ignore_ascii_case(original))
        })
    {
        return Err(crate::provisioning::error(
            "Azure boot attachment changed since VM creation",
        ));
    }
    if has_boot_reference {
        runner
            .record_boot_disk(&crate::disk_inventory::azure_boot_from_vm(original, runner).await?)
            .await?;
    }
    let current = match current {
        Some(vm) => vm,
        None => read_created_vm(subscription, rg, name, &identity, runner).await?,
    };
    if !has_boot_reference {
        runner
            .record_boot_disk(&crate::disk_inventory::azure_boot_from_vm(&current, runner).await?)
            .await?;
    }
    let ip = get_instance_ip(subscription, rg, name, runner)
        .await?
        .unwrap_or_default();
    runner
        .record_created_instance(name, &ip, false, Some(&identity))
        .await?;
    Ok(ip)
}

async fn read_created_vm(
    subscription: &str,
    rg: &str,
    name: &str,
    expected_identity: &str,
    runner: &dyn CommandRunner,
) -> Result<serde_json::Value, CloudError> {
    let out = runner
        .run_capture(
            "az",
            &[
                "vm",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--output",
                "json",
            ],
        )
        .await?;
    let current: serde_json::Value = serde_json::from_str(&out.stdout)?;
    if current["vmId"] != expected_identity {
        return Err(crate::provisioning::error("Azure VM was replaced"));
    }
    Ok(current)
}

/// Record the networking allocated by the conditional VM creation, using only
/// NIC references returned in that request's original response.
pub(crate) async fn record_vm_created_network<R: CommandRunner + ?Sized>(
    body: &serde_json::Value,
    original: &serde_json::Value,
    current: &serde_json::Value,
    runner: &R,
) -> Result<(), CloudError> {
    use crate::provisioning::{azure_network_record, error, identity};
    let profile = &body["properties"]["networkProfile"];
    let Some(configs) = profile["networkInterfaceConfigurations"].as_array() else {
        return Ok(());
    };
    if configs.len() != 1 || profile.get("networkInterfaces").is_some() {
        return Err(error("invalid VM-created network configuration"));
    }
    let vm_id = identity(&original["id"])?;
    let prefix = vm_id
        .split_once("/providers/")
        .ok_or_else(|| error("invalid Azure VM resource ID"))?
        .0;
    let nics = original["properties"]["networkProfile"]["networkInterfaces"]
        .as_array()
        .filter(|n| n.len() == 1)
        .ok_or_else(|| error("original VM creation response has no unique NIC reference"))?;
    let nic_id = identity(&nics[0]["id"])?;
    let current_nics = current["properties"]["networkProfile"]["networkInterfaces"].as_array();
    if !current_nics.is_some_and(|n| {
        n.len() == 1
            && n[0]["id"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(&nic_id))
    }) {
        return Err(error(
            "VM network attachment differs from its creation response",
        ));
    }
    if !nic_id.to_ascii_lowercase().starts_with(
        &format!("{prefix}/providers/Microsoft.Network/networkInterfaces/").to_ascii_lowercase(),
    ) {
        return Err(error(
            "VM-created NIC is outside the deployment resource group",
        ));
    }
    let api = "2024-05-01";
    let nic = runner
        .azure_api(
            "GET",
            &format!("https://management.azure.com{nic_id}?api-version={api}"),
            None,
            false,
        )
        .await?;
    let nic_record = azure_network_record(&nic_id, api, &nic)?;
    if !nic["properties"]["virtualMachine"]["id"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(&vm_id))
    {
        return Err(error("VM-created NIC is not attached to the recorded VM"));
    }
    let ips = nic["properties"]["ipConfigurations"]
        .as_array()
        .filter(|ips| ips.len() == 1)
        .ok_or_else(|| error("VM-created NIC has unexpected IP configurations"))?;
    let expected = &configs[0]["properties"]["ipConfigurations"][0];
    if ips[0]["name"] != expected["name"]
        || !ips[0]["properties"]["subnet"]["id"]
            .as_str()
            .zip(expected["properties"]["subnet"]["id"].as_str())
            .is_some_and(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
    {
        return Err(error(
            "VM-created NIC IP configuration differs from the request",
        ));
    }
    let ip_id = identity(&ips[0]["properties"]["publicIPAddress"]["id"])?;
    if !ip_id.to_ascii_lowercase().starts_with(
        &format!("{prefix}/providers/Microsoft.Network/publicIPAddresses/").to_ascii_lowercase(),
    ) {
        return Err(error(
            "VM-created public IP is outside the deployment resource group",
        ));
    }
    let ip = runner
        .azure_api(
            "GET",
            &format!("https://management.azure.com{ip_id}?api-version={api}"),
            None,
            false,
        )
        .await?;
    let ip_record = azure_network_record(&ip_id, api, &ip)?;
    let attachment_id = identity(&ips[0]["id"])?;
    if !ip["properties"]["ipConfiguration"]["id"]
        .as_str()
        .is_some_and(|id| id.eq_ignore_ascii_case(&attachment_id))
        || ips[0]["properties"]["publicIPAddress"]["properties"]["deleteOption"] != "Detach"
        || ip["properties"]["publicIPAllocationMethod"] != "Static"
        || ip["sku"]["name"] != "Standard"
    {
        return Err(error(
            "VM-created public IP attachment or retention settings differ from the request",
        ));
    }
    runner.record_azure_resource(&nic_record).await?;
    runner.record_azure_resource(&ip_record).await
}

/// Resolve and validate an existing Azure Public IP resource.
pub async fn resolve_static_public_ip(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "network",
                "public-ip",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--output",
                "json",
            ],
        )
        .await
        .map_err(|e| CloudError::InstanceError {
            message: format!(
                "failed to resolve Azure static IP '{name}' in resource group '{rg}': {e}"
            ),
        })?;
    let parsed: serde_json::Value = serde_json::from_str(&output.stdout)?;
    let allocation = parsed
        .get("publicIpAllocationMethod")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if allocation != "Static" {
        return Err(CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' must use Static allocation"
            ),
        });
    }
    let sku = parsed
        .get("sku")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if sku != "Standard" {
        return Err(CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' must use Standard SKU"
            ),
        });
    }
    parsed
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
        .map(|id| id.to_string())
        .ok_or_else(|| CloudError::InstanceError {
            message: format!(
                "Azure public IP '{name}' in resource group '{rg}' did not return a resource ID"
            ),
        })
}

/// Attach a managed disk to an instance with a specific LUN.
pub async fn attach_recorded_disk(
    subscription: &str,
    rg: &str,
    vm_name: &str,
    spec: &crate::DiskSpec,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    let record = runner
        .recorded_creation(&format!("disk:{}", spec.device_name))
        .await?
        .and_then(|c| c.result)
        .ok_or_else(|| crate::provisioning::error("missing Azure disk creation result"))?;
    let unique = crate::provisioning::identity(&record["properties"]["uniqueId"])?;
    let id = super::disk::resource_id(subscription, rg, &spec.name);
    let live = super::disk::show(subscription, rg, &spec.name, runner).await?;
    super::disk::verify_id(&live, &id, &unique)?;
    crate::disk_inventory::validate(spec, &crate::disk_inventory::azure_observation(&live)?)?;
    let created_vm = runner
        .recorded_creation("instance")
        .await?
        .and_then(|c| c.result)
        .ok_or_else(|| crate::provisioning::error("missing Azure VM creation result"))?;
    let out = runner
        .run_capture(
            "az",
            &[
                "vm",
                "show",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                vm_name,
                "--output",
                "json",
            ],
        )
        .await?;
    let vm: serde_json::Value = serde_json::from_str(&out.stdout)?;
    if vm["vmId"] != created_vm["properties"]["vmId"] {
        return Err(crate::provisioning::error("Azure VM was replaced"));
    }
    let slots = vm["storageProfile"]["dataDisks"]
        .as_array()
        .ok_or_else(|| crate::provisioning::error("missing Azure disk list"))?;
    let found: Vec<_> = slots
        .iter()
        .filter(|s| s["lun"].as_u64() == Some(spec.index as u64))
        .collect();
    if found.len() > 1
        || found.first().is_some_and(|s| {
            !s["managedDisk"]["id"]
                .as_str()
                .is_some_and(|v| v.eq_ignore_ascii_case(&id))
        })
    {
        return Err(crate::provisioning::error(
            "Azure LUN is occupied by a different disk",
        ));
    }
    if !found.is_empty() {
        return Ok(());
    }
    if slots.iter().any(|s| {
        s["managedDisk"]["id"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(&id))
    }) {
        return Err(crate::provisioning::error(
            "Azure disk is attached at a different LUN",
        ));
    }
    if live["managedBy"].as_str().is_some_and(|s| !s.is_empty())
        || live["managedByExtended"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    {
        return Err(crate::provisioning::error(
            "Azure disk is already attached to another VM",
        ));
    }
    attach_disk(subscription, rg, vm_name, &id, spec.index, runner).await
}

pub async fn attach_disk(
    subscription: &str,
    rg: &str,
    vm_name: &str,
    disk_name: &str,
    lun: u32,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    runner
        .run_capture(
            "az",
            &[
                "vm",
                "disk",
                "attach",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--vm-name",
                vm_name,
                "--name",
                disk_name,
                "--lun",
                &lun.to_string(),
            ],
        )
        .await
        .map_err(|e| CloudError::DiskError {
            message: format!("failed to attach disk '{disk_name}' at LUN {lun}: {e}"),
        })?;
    Ok(())
}

/// Get the public IP of a running instance.
pub async fn get_instance_ip(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<Option<String>, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "vm",
                "list-ip-addresses",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--query",
                "[0].virtualMachine.network.publicIpAddresses[0].ipAddress",
                "-o",
                "tsv",
            ],
        )
        .await?;

    let ip = output.stdout.trim().to_string();
    if ip.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ip))
    }
}

/// Delete an instance.
pub async fn delete_instance(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "vm",
                "delete",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
                "--yes",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("instance '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("instance/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Get boot diagnostics log from an instance.
pub async fn get_boot_log(
    subscription: &str,
    rg: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<String, CloudError> {
    let output = runner
        .run_capture(
            "az",
            &[
                "vm",
                "boot-diagnostics",
                "get-boot-log",
                "--subscription",
                subscription,
                "--resource-group",
                rg,
                "--name",
                name,
            ],
        )
        .await?;
    Ok(output.stdout)
}

/// Delete a resource group and all resources within it.
pub async fn delete_resource_group(
    subscription: &str,
    name: &str,
    runner: &dyn CommandRunner,
) -> Result<(), CloudError> {
    match runner
        .run_capture(
            "az",
            &[
                "group",
                "delete",
                "--subscription",
                subscription,
                "--name",
                name,
                "--yes",
                "--no-wait",
            ],
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(CloudError::CommandFailed { stderr, .. })
            if stderr.contains("not found") || stderr.contains("NotFound") =>
        {
            tracing::debug!("resource group '{name}' already deleted");
            Ok(())
        }
        Err(e) => Err(CloudError::DestroyFailed {
            resource: format!("resource-group/{name}"),
            message: e.to_string(),
        }),
    }
}

/// Parse the public IP from `az vm create --output json`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CommandOutput;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[tokio::test]
    async fn init_bootstrap_uses_user_data_not_tags() {
        let runner = MockRunner::new(vec![output(r#"{"publicIpAddress":"203.0.113.30"}"#)]);
        let public = r#"{"format":1,"scheme":"atakit-init-es256k-v1","public_key":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","deployment_id":"1111111111111111111111111111111111111111111111111111111111111111"}"#;
        create_instance(
            "sub",
            "rg",
            "vm",
            "Standard_DC4as_v5",
            "image",
            CcType::SevSnp,
            "nsg",
            &[("atakit-init-auth".into(), public.into())],
            None,
            None,
            &[],
            None,
            &runner,
        )
        .await
        .unwrap();
        let requests = runner.requests.lock().unwrap();
        let vm = requests.last().unwrap();
        let user_data = base64::engine::general_purpose::STANDARD
            .decode(vm["properties"]["userData"].as_str().unwrap())
            .unwrap();
        let decoded = atakit_init_auth::decode_user_data(std::str::from_utf8(&user_data).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, serde_json::from_str(public).unwrap());
        assert!(vm["tags"].get("atakit-init-auth").is_none());
        assert_eq!(
            vm["properties"]["securityProfile"]["securityType"],
            "ConfidentialVM"
        );
        assert_eq!(
            vm["properties"]["securityProfile"]["uefiSettings"]["secureBootEnabled"],
            true
        );
    }

    struct MockRunner {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        responses: Mutex<VecDeque<CommandOutput>>,
        requests: Mutex<Vec<serde_json::Value>>,
    }

    impl MockRunner {
        fn new(responses: Vec<CommandOutput>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(vec![]),
            }
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl CommandRunner for MockRunner {
        async fn create_resource(
            &self,
            _: &str,
            request: &crate::provisioning::CreateRequest,
        ) -> Result<serde_json::Value, CloudError> {
            match request {
                crate::provisioning::CreateRequest::AzureNetwork { id, body, .. } => {
                    let mut recorded = body.clone();
                    recorded["type"] = id
                        .split("/providers/")
                        .nth(1)
                        .unwrap()
                        .rsplit_once('/')
                        .unwrap()
                        .0
                        .into();
                    self.requests.lock().unwrap().push(recorded);
                    Ok(serde_json::json!({}))
                }
                crate::provisioning::CreateRequest::AzureVm {
                    subscription,
                    group,
                    name,
                    body,
                } => {
                    self.requests.lock().unwrap().push(body.clone());
                    Ok(
                        serde_json::json!({"id":format!("/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/virtualMachines/{name}"),"properties":{"vmId":"vm-id","storageProfile":{"osDisk":{"managedDisk":{"id":format!("/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Compute/disks/boot")}}}}}),
                    )
                }
                _ => panic!("unexpected request"),
            }
        }

        async fn run_capture(
            &self,
            program: &str,
            args: &[&str],
        ) -> Result<CommandOutput, CloudError> {
            self.calls.lock().unwrap().push((
                program.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            ));
            if args.starts_with(&["group", "show"]) {
                return Ok(output("region"));
            }
            if args.starts_with(&["resource", "show"]) {
                return Err(CloudError::CommandFailed {
                    program: "az".into(),
                    args: args.join(" "),
                    stderr: "ResourceNotFound".into(),
                    code: Some(3),
                });
            }
            if args.starts_with(&["vm", "show"]) {
                return Ok(output(r#"{"vmId":"vm-id"}"#));
            }
            if args.starts_with(&["disk", "show"]) {
                if args.contains(&"vm-data") {
                    return Err(CloudError::CommandFailed {
                        program: "az".into(),
                        args: args.join(" "),
                        stderr: "ResourceNotFound".into(),
                        code: Some(3),
                    });
                }
                return Ok(output(&serde_json::json!({"id":args[3],"uniqueId":"boot-id","diskSizeGB":32,"sku":{"name":"Premium_LRS"}}).to_string()));
            }
            if args.starts_with(&["vm", "list-ip-addresses"]) {
                return Ok(output("203.0.113.30"));
            }
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| CloudError::State {
                    message: "missing mock response".to_string(),
                })
        }

        async fn run_stream(
            &self,
            _program: &str,
            _args: &[&str],
            _verbose: bool,
        ) -> Result<CommandOutput, CloudError> {
            unimplemented!("streaming is not used by these tests")
        }
    }

    fn output(stdout: &str) -> CommandOutput {
        CommandOutput {
            status: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[tokio::test]
    async fn fast_disks_use_zonal_vm_creation_without_host_caching() {
        for kind in ["PremiumV2_LRS", "UltraSSD_LRS"] {
            let runner = MockRunner::new(vec![]);
            let disk = crate::DiskSpec {
                name: "vm-data".into(),
                device_name: "data".into(),
                index: 10,
                size_gb: 32,
                disk_type: kind.into(),
                performance: None,
            };
            create_instance(
                "sub",
                "rg",
                "vm",
                "Standard_DC32es_v6",
                "image",
                CcType::Tdx,
                "nsg",
                &[],
                Some(32),
                None,
                &[disk],
                Some("1"),
                &runner,
            )
            .await
            .unwrap();
            let requests = runner.requests.lock().unwrap();
            let vm = requests.last().unwrap();
            assert_eq!(vm["zones"], serde_json::json!(["1"]));
            let data = &vm["properties"]["storageProfile"]["dataDisks"][0];
            assert_eq!(data["createOption"], "Empty");
            assert_eq!(data["caching"], "None");
            assert_eq!(data["managedDisk"]["storageAccountType"], kind);
            assert_eq!(data["lun"], 10);
            assert_eq!(
                vm["properties"]["additionalCapabilities"]["ultraSSDEnabled"].as_bool(),
                if kind == "UltraSSD_LRS" {
                    Some(true)
                } else {
                    None
                }
            );
        }
    }

    #[tokio::test]
    async fn static_public_ip_is_validated_and_passed_to_vm_create() {
        let public_ip_id =
            "/subscriptions/sub/resourceGroups/network-rg/providers/Microsoft.Network/publicIPAddresses/portal-ip";
        let runner = MockRunner::new(vec![
            output(&format!(
                r#"{{
                    "id": "{public_ip_id}",
                    "publicIpAllocationMethod": "Static",
                    "sku": {{"name": "Standard"}}
                }}"#
            )),
            output(r#"{"publicIpAddress":"203.0.113.30"}"#),
        ]);

        let resolved = resolve_static_public_ip("sub", "network-rg", "portal-ip", &runner)
            .await
            .unwrap();
        assert_eq!(resolved, public_ip_id);

        create_instance(
            "sub",
            "deploy-rg",
            "vm1",
            "Standard_DC4as_v5",
            public_ip_id,
            CcType::SevSnp,
            "vm1-nsg",
            &[],
            None,
            Some(&resolved),
            &[],
            None,
            &runner,
        )
        .await
        .unwrap();

        let calls = runner.calls();
        assert_eq!(
            calls[0].1,
            vec![
                "network",
                "public-ip",
                "show",
                "--subscription",
                "sub",
                "--resource-group",
                "network-rg",
                "--name",
                "portal-ip",
                "--output",
                "json",
            ]
        );
        let requests = runner.requests.lock().unwrap();
        let resources = &*requests;
        assert!(!resources
            .iter()
            .any(|v| v["type"] == "Microsoft.Network/publicIPAddresses"));
        let nic = resources
            .iter()
            .find(|v| v["type"] == "Microsoft.Network/networkInterfaces")
            .unwrap();
        assert_eq!(
            nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"]["id"],
            public_ip_id
        );
    }

    #[tokio::test]
    async fn create_instance_without_reserved_ip_creates_standard_public_ip() {
        let runner = MockRunner::new(vec![output(r#"{"publicIpAddress":"198.51.100.40"}"#)]);

        create_instance(
            "sub",
            "deploy-rg",
            "vm1",
            "Standard_DC4as_v5",
            "image-id",
            CcType::SevSnp,
            "vm1-nsg",
            &[],
            None,
            None,
            &[],
            None,
            &runner,
        )
        .await
        .unwrap();

        let requests = runner.requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "only VNet and VM creation requests");
        let network = &requests.last().unwrap()["properties"]["networkProfile"];
        assert!(network.get("networkInterfaces").is_none());
        let nic = &network["networkInterfaceConfigurations"][0];
        assert_eq!(nic["properties"]["deleteOption"], "Detach");
        let ip =
            &nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddressConfiguration"];
        assert_eq!(ip["sku"]["name"], "Standard");
        assert_eq!(ip["properties"]["publicIPAllocationMethod"], "Static");
        assert_eq!(ip["properties"]["deleteOption"], "Detach");
    }
}

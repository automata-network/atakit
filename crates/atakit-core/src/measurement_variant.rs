//! Names for separately measured Azure SEV-SNP firmware baselines.

use sha3::{Digest, Keccak256};

const FIRMWARE_SEPARATOR: &str = "@firmware-";

/// Name a complete SHA-256 PCR 0/PCR 2 pair. This names a measurement; it does
/// not authorize that measurement. Publishers must review every baseline.
pub fn azure_snp_firmware_variant_name(
    machine_type: &str,
    pcr0: &[u8; 32],
    pcr2: &[u8; 32],
) -> String {
    let mut input = b"atakit.azure-sev-snp.firmware.v1\0".to_vec();
    input.extend_from_slice(pcr0);
    input.extend_from_slice(pcr2);
    let digest = hex::encode(Keccak256::digest(input));
    format!("{machine_type}{FIRMWARE_SEPARATOR}{digest}")
}

/// Recover the machine selector from a canonical firmware variant name.
/// Legacy names remain literal machine types. A malformed reserved suffix is
/// an error, not a different machine name.
pub fn measurement_variant_machine_type(name: &str) -> Result<&str, &'static str> {
    let Some((machine, digest)) = name.split_once(FIRMWARE_SEPARATOR) else {
        return Ok(name);
    };
    if machine.is_empty()
        || machine.contains('@')
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "invalid firmware variant name; expected <machine>@firmware-<64 lowercase hex digits>",
        );
    }
    Ok(machine)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_variant_names_bind_the_complete_ordered_pair() {
        let name = azure_snp_firmware_variant_name("Standard_DC2as_v5", &[1; 32], &[2; 32]);
        assert_eq!(
            measurement_variant_machine_type(&name),
            Ok("Standard_DC2as_v5")
        );
        assert_ne!(
            name,
            azure_snp_firmware_variant_name("Standard_DC2as_v5", &[2; 32], &[1; 32])
        );
        assert_ne!(
            name,
            azure_snp_firmware_variant_name("Standard_DC2as_v5", &[1; 32], &[3; 32])
        );
        assert_eq!(
            measurement_variant_machine_type("Standard_DC2as_v5"),
            Ok("Standard_DC2as_v5")
        );
        assert!(measurement_variant_machine_type("Standard_DC2as_v5@firmware-abc").is_err());
        assert!(
            measurement_variant_machine_type(&format!("x@firmware-{}", "A".repeat(64))).is_err()
        );
    }
}

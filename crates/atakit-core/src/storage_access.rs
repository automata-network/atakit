//! Measured mount rights. These do not override Unix file permissions.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageAccess {
    Read,
    Write,
    Execute,
}

pub fn validate_access(access: &[StorageAccess], allow_empty: bool) -> Result<(), String> {
    if allow_empty && access.is_empty() {
        return Ok(());
    }
    if !access.contains(&StorageAccess::Read) {
        return Err("storage access must include read".into());
    }
    let mut unique = access.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != access.len() {
        return Err("storage access must not contain duplicates".into());
    }
    Ok(())
}

pub fn canonical_access(access: &Option<Vec<StorageAccess>>) -> Option<Vec<StorageAccess>> {
    access.as_ref().map(|rights| {
        let mut rights = rights.clone();
        rights.sort();
        rights
    })
}

pub fn validate_mount_access(
    format: u32,
    access: &Option<Vec<StorageAccess>>,
    read_only: Option<bool>,
    executable: Option<bool>,
) -> Result<(), String> {
    if format >= 14 {
        if read_only.is_some() || executable.is_some() {
            return Err(
                "format 14 storage requires access instead of read-only/read_only and executable"
                    .into(),
            );
        }
        validate_access(
            access.as_ref().ok_or("format 14 storage requires access")?,
            false,
        )
    } else if access.is_some() {
        Err("storage access requires format 14".into())
    } else {
        Ok(())
    }
}

pub fn read_only(access: &Option<Vec<StorageAccess>>, legacy: Option<bool>) -> bool {
    access.as_ref().map_or(legacy.unwrap_or(false), |a| {
        !a.contains(&StorageAccess::Write)
    })
}

pub fn executable(access: &Option<Vec<StorageAccess>>, legacy: Option<bool>) -> bool {
    access.as_ref().map_or(legacy.unwrap_or(false), |a| {
        a.contains(&StorageAccess::Execute)
    })
}

pub fn parent_allows(access: &[StorageAccess], read_only: bool, executable: bool) -> bool {
    access.contains(&StorageAccess::Read)
        && (read_only || access.contains(&StorageAccess::Write))
        && (!executable || access.contains(&StorageAccess::Execute))
}

pub fn execution_disabled(value: &Option<bool>) -> bool {
    !value.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_require_read_and_are_unique() {
        use StorageAccess::*;
        for rights in [vec![], vec![Write], vec![Execute], vec![Read, Read]] {
            assert!(validate_access(&rights, false).is_err());
        }
        assert!(validate_access(&[], true).is_ok());
        for rights in [
            vec![Read],
            vec![Read, Write],
            vec![Read, Execute],
            vec![Read, Write, Execute],
        ] {
            validate_access(&rights, false).unwrap();
        }
    }

    #[test]
    fn parent_grants_cannot_be_exceeded_by_an_overlapping_mount() {
        use StorageAccess::*;
        assert!(!parent_allows(&[], true, false));
        assert!(parent_allows(&[Read], true, false));
        assert!(!parent_allows(&[Read], false, false));
        assert!(!parent_allows(&[Read, Write], false, true));
        assert!(parent_allows(&[Read, Execute], true, true));
        assert!(!parent_allows(&[Read, Execute], false, true));
        assert!(parent_allows(&[Read, Write, Execute], false, true));
    }
}

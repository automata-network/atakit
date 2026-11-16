//! Per-process descriptor limits. The image owns the default and ceiling.

pub const NOFILE_FORMAT: u32 = 16;
pub const DEFAULT_NOFILE: u64 = 1_048_576;

pub const fn default_nofile() -> u64 {
    DEFAULT_NOFILE
}

pub fn validate(value: u64) -> Result<(), String> {
    if value == 0 || value > i32::MAX as u64 {
        return Err("nofile must be a positive integer no greater than 2147483647".into());
    }
    Ok(())
}

pub fn validate_requests(format: u32, values: impl Iterator<Item = u64>) -> Result<(), String> {
    for value in values {
        if format != NOFILE_FORMAT {
            return Err("nofile requires manifest format 16".into());
        }
        validate(value)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofilePolicy {
    pub default: u64,
    pub max: u64,
}

impl Default for NofilePolicy {
    fn default() -> Self {
        Self {
            default: DEFAULT_NOFILE,
            max: DEFAULT_NOFILE,
        }
    }
}

impl NofilePolicy {
    pub fn validate(self) -> Result<(), String> {
        validate(self.default)?;
        validate(self.max)?;
        if self.default > self.max {
            return Err("nofile-default exceeds nofile-max".into());
        }
        Ok(())
    }

    pub fn resolve(self, requested: Option<u64>) -> Result<u64, String> {
        self.validate()?;
        let value = requested.unwrap_or(self.default);
        validate(value)?;
        if value > self.max {
            return Err(format!(
                "nofile {value} exceeds base-image nofile-max {}",
                self.max
            ));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_default_and_ceiling_are_independent_of_request() {
        let policy = NofilePolicy {
            default: 65536,
            max: 1048576,
        };
        assert_eq!(policy.resolve(None).unwrap(), 65536);
        assert_eq!(policy.resolve(Some(262144)).unwrap(), 262144);
        assert!(policy.resolve(Some(1048577)).is_err());
        assert!(policy.resolve(Some(0)).is_err());
        assert!(NofilePolicy { default: 2, max: 1 }.resolve(None).is_err());
        assert!(validate(u64::MAX).is_err());
        assert!(validate_requests(15, [65536].into_iter()).is_err());
        assert!(validate_requests(16, [65536].into_iter()).is_ok());
    }
}

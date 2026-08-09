//! Chain-independent CVM protocol types.

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// A publisher-qualified reference to a base image or workload.
///
/// The canonical text form is `<publisher>/<name>:<version>`. `publisher` is
/// the complete 32-byte key fingerprint encoded as lowercase hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRef {
    pub publisher: [u8; 32],
    pub name: String,
    pub version: String,
}

impl AppRef {
    pub fn new(publisher: [u8; 32], name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            publisher,
            name: name.into(),
            version: version.into(),
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AppRefParseError {
    #[error(
        "expected format '<publisher>/<name>:<version>', got '{input}'; a reference without a publisher is not accepted"
    )]
    MissingPublisher { input: String },
    #[error(
        "publisher must be '0x' followed by 64 lowercase hexadecimal characters, got '{publisher}'"
    )]
    InvalidPublisher { publisher: String },
    #[error("expected format '<publisher>/<name>:<version>', got '{input}'")]
    MissingNameOrVersion { input: String },
    #[error("name must not be empty in '{input}'")]
    EmptyName { input: String },
    #[error("version must not be empty in '{input}'")]
    EmptyVersion { input: String },
}

impl FromStr for AppRef {
    type Err = AppRefParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Some((publisher, rest)) = input.split_once('/') else {
            return Err(AppRefParseError::MissingPublisher {
                input: input.to_owned(),
            });
        };
        if publisher.len() != 66
            || !publisher.starts_with("0x")
            || !publisher[2..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AppRefParseError::InvalidPublisher {
                publisher: publisher.to_owned(),
            });
        }
        let mut publisher_bytes = [0u8; 32];
        if hex::decode_to_slice(&publisher[2..], &mut publisher_bytes).is_err() {
            return Err(AppRefParseError::InvalidPublisher {
                publisher: publisher.to_owned(),
            });
        }
        let Some((name, version)) = rest.split_once(':') else {
            return Err(AppRefParseError::MissingNameOrVersion {
                input: input.to_owned(),
            });
        };
        if name.is_empty() {
            return Err(AppRefParseError::EmptyName {
                input: input.to_owned(),
            });
        }
        if version.is_empty() {
            return Err(AppRefParseError::EmptyVersion {
                input: input.to_owned(),
            });
        }
        Ok(Self::new(publisher_bytes, name, version))
    }
}

impl fmt::Display for AppRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "0x{}/{}:{}",
            hex::encode(self.publisher),
            self.name,
            self.version
        )
    }
}

impl Serialize for AppRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AppRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLISHER: [u8; 32] = [0xae; 32];

    fn canonical() -> String {
        format!("0x{}/fedora-oci:v0.0.16", "ae".repeat(32))
    }

    #[test]
    fn canonical_form_round_trips() {
        let parsed: AppRef = canonical().parse().unwrap();
        assert_eq!(parsed, AppRef::new(PUBLISHER, "fedora-oci", "v0.0.16"));
        assert_eq!(parsed.to_string(), canonical());
    }

    #[test]
    fn reference_without_publisher_is_rejected() {
        let error = "fedora-oci:v0.0.16".parse::<AppRef>().unwrap_err();
        assert!(error.to_string().contains("without a publisher"));
    }

    #[test]
    fn malformed_publishers_are_rejected() {
        for input in [
            "0x9f2c/name:v1",
            "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/name:v1",
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/name:v1",
        ] {
            assert!(matches!(
                input.parse::<AppRef>(),
                Err(AppRefParseError::InvalidPublisher { .. })
            ));
        }
    }

    #[test]
    fn serde_uses_canonical_string() {
        let parsed: AppRef = canonical().parse().unwrap();
        let encoded = serde_json::to_string(&parsed).unwrap();
        assert_eq!(encoded, format!("\"{}\"", canonical()));
        assert_eq!(serde_json::from_str::<AppRef>(&encoded).unwrap(), parsed);
    }
}

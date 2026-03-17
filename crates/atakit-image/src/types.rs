use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ImageError;

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct ImageRef {
    pub repository: String,
    pub tag: String,
}

impl Serialize for ImageRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ImageRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl ImageRef {
    pub fn new(repository: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            repository: repository.into(),
            tag: tag.into(),
        }
    }
}

impl FromStr for ImageRef {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (repository, tag) = s
            .split_once(':')
            .ok_or_else(|| ImageError::InvalidImageRef(s.to_string()))?;

        if repository.contains('/') {
            return Err(ImageError::InvalidRepository(repository.to_string()));
        }

        Ok(ImageRef {
            repository: repository.to_string(),
            tag: tag.to_string(),
        })
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.repository, self.tag)
    }
}

/// Target cloud platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Gcp,
    Aws,
    Azure,
}

impl Platform {
    pub const ALL: [Platform; 3] = [Platform::Gcp, Platform::Aws, Platform::Azure];
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gcp => f.write_str("gcp"),
            Self::Aws => f.write_str("aws"),
            Self::Azure => f.write_str("azure"),
        }
    }
}

impl FromStr for Platform {
    type Err = ImageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gcp" => Ok(Platform::Gcp),
            "aws" => Ok(Platform::Aws),
            "azure" => Ok(Platform::Azure),
            other => Err(ImageError::UnsupportedPlatform(other.to_string())),
        }
    }
}

/// Specifies which release version to resolve.
#[derive(Clone, Debug)]
pub enum VersionSelector {
    /// The GitHub "latest" release (may not contain disk images).
    Latest,
    /// The most recent release that contains any disk image.
    LatestImage,
    /// The most recent release that contains a disk image for a specific platform.
    LatestImageFor(Platform),
    /// A specific release identified by its Git tag.
    Tag(ImageRef),
}

/// Classification of a release asset by its filename.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetKind {
    /// A disk image for the given platform.
    DiskImage(Platform),
    /// Secure-boot certificate bundle.
    SecureBootCerts,
    /// Unrecognised asset.
    Unknown,
}

/// A GitHub release.
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub name: Option<String>,
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    pub published_at: Option<String>,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

/// A single asset attached to a release.
#[derive(Clone, Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
    /// API URL used for authenticated downloads.
    pub url: String,
    pub content_type: String,
}

impl Asset {
    /// Classify this asset based on its filename.
    pub fn kind(&self) -> AssetKind {
        match self.name.as_str() {
            "gcp_disk.tar.gz" => AssetKind::DiskImage(Platform::Gcp),
            "aws_disk.vmdk" => AssetKind::DiskImage(Platform::Aws),
            "azure_disk.vhd.xz" => AssetKind::DiskImage(Platform::Azure),
            "secure-boot-certs.zip" => AssetKind::SecureBootCerts,
            _ => AssetKind::Unknown,
        }
    }
}

impl Release {
    /// Get the disk image asset for a specific platform, if present.
    pub fn disk_image(&self, platform: Platform) -> Option<&Asset> {
        self.assets
            .iter()
            .find(|a| a.kind() == AssetKind::DiskImage(platform))
    }

    /// Get the secure-boot-certs asset, if present.
    pub fn secure_boot_certs(&self) -> Option<&Asset> {
        self.assets
            .iter()
            .find(|a| a.kind() == AssetKind::SecureBootCerts)
    }

    /// Whether this release contains at least one disk image asset.
    pub fn has_disk_images(&self) -> bool {
        self.assets
            .iter()
            .any(|a| matches!(a.kind(), AssetKind::DiskImage(_)))
    }

    /// Classify every asset in this release.
    pub fn classify_assets(&self) -> Vec<(&Asset, AssetKind)> {
        self.assets.iter().map(|a| (a, a.kind())).collect()
    }

    /// List which platforms have disk images in this release.
    pub fn available_platforms(&self) -> Vec<Platform> {
        Platform::ALL
            .iter()
            .copied()
            .filter(|&p| self.disk_image(p).is_some())
            .collect()
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag_name)?;

        if let Some(date) = &self.published_at {
            let short = date.get(..10).unwrap_or(date);
            write!(f, "  ({short})")?;
        }

        let platforms = self.available_platforms();
        if platforms.is_empty() {
            write!(f, "  [no disk images]")?;
        } else {
            let names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
            write!(f, "  [{}]", names.join(", "))?;
        }

        if self.secure_boot_certs().is_some() {
            write!(f, " +certs")?;
        }

        Ok(())
    }
}

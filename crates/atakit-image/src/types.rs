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

/// Target platform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Gcp,
    Aws,
    Azure,
    Qemu,
}

impl Platform {
    pub const ALL: [Platform; 4] = [Platform::Gcp, Platform::Aws, Platform::Azure, Platform::Qemu];
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gcp => f.write_str("gcp"),
            Self::Aws => f.write_str("aws"),
            Self::Azure => f.write_str("azure"),
            Self::Qemu => f.write_str("qemu"),
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
            "qemu" => Ok(Platform::Qemu),
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
    /// An `.atabi` archive containing disk images (and optionally certs).
    ImageArchive(Vec<Platform>),
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

impl From<atakit_github::Release> for Release {
    fn from(r: atakit_github::Release) -> Self {
        Self {
            tag_name: r.tag_name,
            name: r.name,
            body: r.body,
            draft: r.draft,
            prerelease: r.prerelease,
            published_at: r.published_at,
            assets: r.assets.into_iter().map(Asset::from).collect(),
        }
    }
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

impl From<atakit_github::Asset> for Asset {
    fn from(a: atakit_github::Asset) -> Self {
        Self {
            name: a.name,
            size: a.size,
            browser_download_url: a.browser_download_url,
            url: a.url,
            content_type: a.content_type,
        }
    }
}

impl From<&Asset> for atakit_github::Asset {
    fn from(a: &Asset) -> Self {
        Self {
            name: a.name.clone(),
            size: a.size,
            browser_download_url: a.browser_download_url.clone(),
            url: a.url.clone(),
            content_type: a.content_type.clone(),
            id: None,
        }
    }
}

impl Asset {
    /// Classify this asset based on its filename.
    ///
    /// Recognises `.atabi` archives with platform suffix:
    /// `{repo}-{tag}-{suffix}.atabi` where suffix is `all` or dash-separated
    /// platform names (e.g. `gcp`, `aws-gcp`, `all`).
    pub fn kind(&self) -> AssetKind {
        let Some(stem) = self.name.strip_suffix(".atabi") else {
            return AssetKind::Unknown;
        };
        // Format: {repo}-{tag}-{suffix}.atabi
        // Suffix is "all" or dash-joined platform names (gcp, aws, azure).
        // Greedily collect valid platform tokens from the right.
        let segments: Vec<&str> = stem.rsplit('-').collect();
        if segments.len() < 2 {
            return AssetKind::Unknown;
        }
        // Check for "all" as the last segment.
        if segments[0] == "all" {
            return AssetKind::ImageArchive(Platform::ALL.to_vec());
        }
        // Collect platform tokens from the right until one doesn't parse.
        let mut platforms = Vec::new();
        for seg in &segments {
            match seg.parse::<Platform>() {
                Ok(p) => {
                    if !platforms.contains(&p) {
                        platforms.push(p);
                    }
                }
                Err(_) => break,
            }
        }
        if platforms.is_empty() {
            return AssetKind::Unknown;
        }
        // Reverse since we collected right-to-left.
        platforms.reverse();
        AssetKind::ImageArchive(platforms)
    }
}


impl Release {
    /// Find an `.atabi` archive asset that contains the given platform.
    pub fn archive_for_platform(&self, platform: Platform) -> Option<&Asset> {
        self.assets.iter().find(|a| {
            if let AssetKind::ImageArchive(ref platforms) = a.kind() {
                platforms.contains(&platform)
            } else {
                false
            }
        })
    }

    /// Whether this release contains at least one `.atabi` archive.
    pub fn has_archives(&self) -> bool {
        self.assets
            .iter()
            .any(|a| matches!(a.kind(), AssetKind::ImageArchive(_)))
    }

    /// List all `.atabi` archive assets.
    pub fn archives(&self) -> Vec<&Asset> {
        self.assets
            .iter()
            .filter(|a| matches!(a.kind(), AssetKind::ImageArchive(_)))
            .collect()
    }

    /// List which platforms are available across all `.atabi` archives in this release.
    pub fn available_platforms(&self) -> Vec<Platform> {
        let mut platforms = Vec::new();
        for a in &self.assets {
            if let AssetKind::ImageArchive(ref ps) = a.kind() {
                for p in ps {
                    if !platforms.contains(p) {
                        platforms.push(*p);
                    }
                }
            }
        }
        // Sort to consistent order.
        platforms.sort_by_key(|p| match p {
            Platform::Gcp => 0,
            Platform::Aws => 1,
            Platform::Azure => 2,
            Platform::Qemu => 3,
        });
        platforms
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
            write!(f, "  [no archives]")?;
        } else {
            let names: Vec<_> = platforms.iter().map(|p| p.to_string()).collect();
            write!(f, "  [{}]", names.join(", "))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.to_string(),
            size: 0,
            browser_download_url: String::new(),
            url: String::new(),
            content_type: String::new(),
        }
    }

    #[test]
    fn parse_atabi_all() {
        assert_eq!(
            asset("automata-linux-v0.1.6-all.atabi").kind(),
            AssetKind::ImageArchive(Platform::ALL.to_vec()),
        );
    }

    #[test]
    fn parse_atabi_single_platform() {
        assert_eq!(
            asset("automata-linux-v0.1.6-gcp.atabi").kind(),
            AssetKind::ImageArchive(vec![Platform::Gcp]),
        );
    }

    #[test]
    fn parse_atabi_multi_platform() {
        assert_eq!(
            asset("automata-linux-v0.1.6-aws-azure.atabi").kind(),
            AssetKind::ImageArchive(vec![Platform::Aws, Platform::Azure]),
        );
    }

    #[test]
    fn parse_unknown_extension() {
        assert_eq!(asset("gcp_disk.tar.gz").kind(), AssetKind::Unknown);
        assert_eq!(asset("README.md").kind(), AssetKind::Unknown);
    }

    #[test]
    fn parse_atabi_no_suffix() {
        // No platform suffix - the stem is just "foo"
        assert_eq!(asset("foo.atabi").kind(), AssetKind::Unknown);
    }
}

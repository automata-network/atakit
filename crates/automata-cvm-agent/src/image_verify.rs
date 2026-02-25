use std::collections::BTreeMap;

use serde::Serialize;

// ---------------------------------------------------------------------------
// Image Signature Verification Policy
// (config/cvm_agent/sample_image_verify_policy.json)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ImageVerifyPolicy {
    pub default: Vec<PolicyRequirement>,
    pub transports: ImageTransports,
}

#[derive(Debug, Serialize)]
pub struct ImageTransports {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub docker: BTreeMap<String, Vec<PolicyRequirement>>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum PolicyRequirement {
    #[serde(rename = "reject")]
    Reject,
    #[serde(rename = "insecureAcceptAnything")]
    InsecureAcceptAnything,
    #[serde(rename = "sigstoreSigned")]
    SigstoreSigned {
        #[serde(rename = "keyPath")]
        key_path: String,
        #[serde(rename = "signedIdentity")]
        signed_identity: SignedIdentity,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum SignedIdentity {
    #[serde(rename = "matchRepository")]
    MatchRepository,
}

impl Default for ImageVerifyPolicy {
    fn default() -> Self {
        let mut docker = BTreeMap::new();
        docker.insert(
            "docker.io/user/busybox".into(),
            vec![PolicyRequirement::SigstoreSigned {
                key_path: "/data/workload/config/cvm_agent/cosign.pub".into(),
                signed_identity: SignedIdentity::MatchRepository,
            }],
        );

        Self {
            default: vec![PolicyRequirement::Reject],
            transports: ImageTransports { docker },
        }
    }
}

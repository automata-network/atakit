//! Shared, bounded initialization authorization wire format. No network I/O.
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "atakit-init-es256k-v1";
pub const HEADER: &str = "atakit-init-authorization";
pub const MAX_HEADER: usize = 8192;
const DOMAIN: &[u8] = b"ATAKIT_INIT_AUTH_V1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub format: u32,
    pub scheme: String,
    pub public_key: String,
    pub deployment_id: String,
}

/// AWS/Azure user-data document. Unknown settings are allowed for future uses.
/// Missing init_auth means unsigned initialization; explicit null is invalid.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisioningData {
    pub format: u32,
    #[serde(default)]
    pub atakit: ProvisioningSettings,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProvisioningSettings {
    #[serde(
        default,
        deserialize_with = "present_bootstrap",
        skip_serializing_if = "Option::is_none"
    )]
    pub init_auth: Option<Bootstrap>,
}

fn present_bootstrap<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Bootstrap>, D::Error> {
    Bootstrap::deserialize(deserializer).map(Some)
}

pub fn encode_user_data(bootstrap: &Bootstrap) -> Result<String, serde_json::Error> {
    serde_json::to_string(&ProvisioningData {
        format: 1,
        atakit: ProvisioningSettings {
            init_auth: Some(bootstrap.clone()),
        },
    })
}

pub fn decode_user_data(body: &str) -> Result<Option<Bootstrap>, String> {
    if body.len() > 4096 {
        return Err("provisioning user data exceeds 4096 bytes".into());
    }
    // Serde structs also accept sequences; the wire format requires objects.
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|_| "invalid provisioning user data")?;
    if !value.is_object()
        || value.get("atakit").is_some_and(|settings| {
            !settings.is_object()
                || settings
                    .get("init_auth")
                    .is_some_and(|auth| !auth.is_object())
        })
    {
        return Err("provisioning settings must be JSON objects".into());
    }
    let document: ProvisioningData =
        serde_json::from_str(body).map_err(|_| "invalid provisioning user data")?;
    if document.format != 1 {
        return Err("unsupported provisioning user-data format".into());
    }
    if let Some(bootstrap) = &document.atakit.init_auth {
        bootstrap.validate().map_err(str::to_string)?;
    }
    Ok(document.atakit.init_auth)
}

impl Bootstrap {
    pub fn validate(&self) -> Result<VerifyingKey, &'static str> {
        if self.format != 1 || self.scheme != SCHEME || self.deployment_id.len() != 64 {
            return Err("invalid init authentication bootstrap");
        }
        hex::decode(&self.deployment_id).map_err(|_| "invalid deployment ID")?;
        let bytes = hex::decode(&self.public_key).map_err(|_| "invalid init public key")?;
        if bytes.len() != 33 {
            return Err("init public key must use compressed SEC1 encoding");
        }
        VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| "invalid init public key")
    }

    pub fn fingerprint(&self) -> Result<String, &'static str> {
        Ok(hash(self.validate()?.to_encoded_point(true).as_bytes()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub scheme: String,
    pub deployment_id: String,
    pub key_fingerprint: String,
    pub tls_fingerprint: String,
    pub challenge: String,
    pub expires_in_seconds: u64,
}

/// Hashes commit to exact part bytes. Remote descriptors are also committed,
/// so authorization cannot be reused to make the portal fetch another URL.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub deployment_id: String,
    pub tls_fingerprint: String,
    pub challenge: String,
    pub transfer_id: String,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub workload_id: String,
    pub config_sha256: String,
    pub unmeasured_sha256: Option<String>,
    pub source_sha256: Option<String>,
    pub transfer_timeout: u64,
    pub init_timeout: u64,
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sign(intent: &Intent, key: &SigningKey) -> Result<String, &'static str> {
    let payload = serde_json::to_vec(intent).map_err(|_| "encode init intent")?;
    let message = [DOMAIN, &payload].concat();
    let signature: Signature = key.sign(&message);
    let value = format!(
        "{}.{}",
        hex::encode(&payload),
        hex::encode(signature.to_bytes())
    );
    if value.len() > MAX_HEADER {
        return Err("init authorization is too large");
    }
    Ok(value)
}

pub fn verify(value: &str, bootstrap: &Bootstrap) -> Result<Intent, &'static str> {
    if value.len() > MAX_HEADER {
        return Err("init authorization is too large");
    }
    let (payload, signature) = value.split_once('.').ok_or("invalid init authorization")?;
    let payload = hex::decode(payload).map_err(|_| "invalid init authorization")?;
    let signature = hex::decode(signature).map_err(|_| "invalid init signature")?;
    let signature = Signature::from_slice(&signature).map_err(|_| "invalid init signature")?;
    bootstrap
        .validate()?
        .verify(&[DOMAIN, &payload].concat(), &signature)
        .map_err(|_| "invalid init signature")?;
    let intent: Intent = serde_json::from_slice(&payload).map_err(|_| "invalid init intent")?;
    if intent.deployment_id != bootstrap.deployment_id {
        return Err("wrong init deployment");
    }
    if intent.archive_size == 0 || intent.transfer_timeout == 0 || intent.init_timeout == 0 {
        return Err("invalid init limits");
    }
    for digest in [
        &intent.archive_sha256,
        &intent.config_sha256,
        &intent.workload_id,
        &intent.tls_fingerprint,
        &intent.challenge,
    ]
    .into_iter()
    .chain(intent.unmeasured_sha256.iter())
    .chain(intent.source_sha256.iter())
    {
        if digest.len() != 64 || hex::decode(digest).is_err() {
            return Err("invalid init digest");
        }
    }
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisioning_data_supports_other_settings_and_optional_auth() {
        let (_, bootstrap, _) = fixture();
        let encoded = encode_user_data(&bootstrap).unwrap();
        assert_eq!(decode_user_data(&encoded).unwrap(), Some(bootstrap.clone()));
        let mut document: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        document["other"] = serde_json::json!({"name": "example"});
        document["atakit"]["future_setting"] = serde_json::json!(true);
        assert_eq!(
            decode_user_data(&document.to_string()).unwrap(),
            Some(bootstrap)
        );
        for body in [
            r#"{"format":1}"#,
            r#"{"format":1,"atakit":{},"other":42}"#,
            r#"{"format":1,"atakit":{"future_setting":true}}"#,
        ] {
            assert_eq!(decode_user_data(body).unwrap(), None);
        }
    }

    #[test]
    fn provisioning_data_rejects_invalid_documents_without_disabling_auth() {
        for body in [
            "",
            "not json",
            "null",
            "[]",
            "[1, {}]",
            "{}",
            r#"{"format":2}"#,
            r#"{"format":1,"atakit":null}"#,
            r#"{"format":1,"atakit":[]}"#,
            r#"{"format":1,"atakit":{"init_auth":null}}"#,
            r#"{"format":1,"atakit":{"init_auth":{}}}"#,
            r#"{"format":1,"atakit":{"init_auth":"key"}}"#,
            r#"{"format":1,"atakit":{},"atakit":{}}"#,
            r#"{"format":1,"format":1}"#,
        ] {
            assert!(decode_user_data(body).is_err(), "accepted {body}");
        }
        let (_, mut bootstrap, _) = fixture();
        bootstrap.public_key = "bad key".into();
        assert!(decode_user_data(&encode_user_data(&bootstrap).unwrap()).is_err());
        assert!(decode_user_data(&" ".repeat(4097)).is_err());
    }

    fn fixture() -> (SigningKey, Bootstrap, Intent) {
        let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let bootstrap = Bootstrap {
            format: 1,
            scheme: SCHEME.into(),
            public_key: hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()),
            deployment_id: "11".repeat(32),
        };
        let intent = Intent {
            deployment_id: bootstrap.deployment_id.clone(),
            tls_fingerprint: "22".repeat(32),
            challenge: "33".repeat(32),
            transfer_id: "test".into(),
            archive_sha256: hash(b"archive"),
            archive_size: 7,
            workload_id: "44".repeat(32),
            config_sha256: hash(b"config"),
            unmeasured_sha256: None,
            source_sha256: None,
            transfer_timeout: 300,
            init_timeout: 900,
        };
        (key, bootstrap, intent)
    }
    #[test]
    fn every_intent_field_is_signed() {
        let (key, bootstrap, intent) = fixture();
        let signed = sign(&intent, &key).unwrap();
        let signature = signed.split_once('.').unwrap().1;
        let original = serde_json::to_value(&intent).unwrap();
        for name in original.as_object().unwrap().keys() {
            let mut changed = original.clone();
            changed[name] = match &original[name] {
                serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 1),
                _ => serde_json::json!("modified"),
            };
            let header = format!(
                "{}.{}",
                hex::encode(serde_json::to_vec(&changed).unwrap()),
                signature
            );
            assert!(
                verify(&header, &bootstrap).is_err(),
                "unsigned change to {name}"
            );
        }
        let wrong_key = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        assert!(verify(&sign(&intent, &wrong_key).unwrap(), &bootstrap).is_err());
    }

    #[test]
    fn signature_commits_to_exact_payload_and_deployment() {
        let (key, mut bootstrap, intent) = fixture();
        let signed = sign(&intent, &key).unwrap();
        assert!(verify(&signed, &bootstrap).is_ok());
        bootstrap.deployment_id = "55".repeat(32);
        assert!(verify(&signed, &bootstrap).is_err());
        let (_, bootstrap, _) = fixture();
        let mut changed = intent.clone();
        changed.transfer_timeout += 1;
        let altered = format!(
            "{}.{}",
            hex::encode(serde_json::to_vec(&changed).unwrap()),
            signed.split_once('.').unwrap().1
        );
        assert!(verify(&altered, &bootstrap).is_err());
        assert!(verify(&"x".repeat(MAX_HEADER + 1), &bootstrap).is_err());
    }
}

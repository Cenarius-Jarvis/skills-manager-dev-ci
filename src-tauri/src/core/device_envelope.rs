//! Versioned, domain-separated device messages.
//!
//! Verifying a signature alone does not authorize execution. Pairing, durable
//! replay protection, and agent/root approval remain separate requirements.
use anyhow::{bail, Result};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"skills-manager/device-envelope/v1\0";
const MAX_PAYLOAD: usize = 1024 * 1024;
const MAX_LIFETIME: i64 = 900;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnvelope {
    pub version: u8,
    pub kind: MessageKind,
    pub message_id: String,
    pub device_id: String,
    pub key_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind { Command, Receipt, LibraryReport }

fn identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn signing_bytes(envelope: &DeviceEnvelope) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(envelope)?);
    Ok(bytes)
}

/// Verify using a public key and identity obtained from *local pairing*, never
/// from the message or Git repository. Caller must atomically check replay and
/// authorize the operation before executing it.
pub fn verify_envelope(
    envelope: &DeviceEnvelope, signature: &[u8], payload: &[u8],
    trusted_public_key: &[u8], expected_device: &str, expected_key_id: &str, now: i64,
) -> Result<()> {
    if envelope.version != 1 || !identifier(&envelope.message_id)
        || !identifier(&envelope.device_id) || !identifier(&envelope.key_id)
        || envelope.device_id != expected_device || envelope.key_id != expected_key_id
        || !hex_sha256(&envelope.payload_sha256)
        || payload.len() > MAX_PAYLOAD || trusted_public_key.len() != 32 || signature.len() != 64
    { bail!("invalid signed envelope"); }
    let lifetime = envelope.expires_at.checked_sub(envelope.issued_at)
        .ok_or_else(|| anyhow::anyhow!("invalid signed envelope lifetime"))?;
    if envelope.issued_at <= 0 || lifetime <= 0 || lifetime > MAX_LIFETIME
        || now < envelope.issued_at || now >= envelope.expires_at
    { bail!("signed envelope is outside its validity window"); }
    let payload_hash = hex::encode(Sha256::digest(payload));
    if payload_hash != envelope.payload_sha256 { bail!("signed payload does not match"); }
    UnparsedPublicKey::new(&ED25519, trusted_public_key)
        .verify(&signing_bytes(envelope)?, signature)
        .map_err(|_| anyhow::anyhow!("signed envelope verification failed"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};

    fn fixture() -> (Ed25519KeyPair, DeviceEnvelope, Vec<u8>, Vec<u8>) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let payload = b"fixture".to_vec();
        let envelope = DeviceEnvelope {
            version: 1, kind: MessageKind::LibraryReport, message_id: "msg-1".into(),
            device_id: "device-1".into(), key_id: "key-1".into(),
            issued_at: 1000, expires_at: 1100,
            payload_sha256: hex::encode(Sha256::digest(&payload)),
        };
        let signature = key.sign(&signing_bytes(&envelope).unwrap()).as_ref().to_vec();
        (key, envelope, payload, signature)
    }

    #[test]
    fn device_envelope_accepts_locally_trusted_key_and_exact_payload() {
        let (key, env, payload, sig) = fixture();
        assert!(verify_envelope(&env, &sig, &payload, key.public_key().as_ref(),
            "device-1", "key-1", 1050).is_ok());
    }

    #[test]
    fn device_envelope_rejects_tampering_wrong_identity_and_time() {
        let (key, env, payload, sig) = fixture();
        let pk = key.public_key().as_ref();
        assert!(verify_envelope(&env, &sig, b"modified", pk, "device-1", "key-1", 1050).is_err());
        assert!(verify_envelope(&env, &sig, &payload, pk, "device-2", "key-1", 1050).is_err());
        assert!(verify_envelope(&env, &sig, &payload, pk, "device-1", "key-2", 1050).is_err());
        assert!(verify_envelope(&env, &sig, &payload, pk, "device-1", "key-1", 999).is_err());
        assert!(verify_envelope(&env, &sig, &payload, pk, "device-1", "key-1", 1100).is_err());
        let mut changed = env.clone(); changed.kind = MessageKind::Command;
        assert!(verify_envelope(&changed, &sig, &payload, pk, "device-1", "key-1", 1050).is_err());
        let mut changed = env.clone(); changed.expires_at = 3000;
        assert!(verify_envelope(&changed, &sig, &payload, pk, "device-1", "key-1", 1050).is_err());
        let mut changed_sig = sig.clone(); changed_sig[0] ^= 1;
        assert!(verify_envelope(&env, &changed_sig, &payload, pk, "device-1", "key-1", 1050).is_err());
        let (other, _, _, _) = fixture();
        assert!(verify_envelope(&env, &sig, &payload, other.public_key().as_ref(),
            "device-1", "key-1", 1050).is_err());
    }

    #[test]
    fn device_envelope_rejects_unknown_fields() {
        let (_, env, _, _) = fixture();
        let mut value = serde_json::to_value(env).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DeviceEnvelope>(value).is_err());
    }
}

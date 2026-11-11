//! The local device's signing identity: one Ed25519 key pair per machine.
//!
//! The private key lives in the OS keychain and never leaves this process;
//! signing a message is not publishing it, and importing a peer's key still
//! requires explicit local approval before it is trusted. This module only
//! creates and applies identities — it never publishes anything and never
//! authorizes execution.

use anyhow::{bail, Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::device_envelope::{self, DeviceEnvelope, MessageKind};
use super::device_pairing;
use super::skill_store::SkillStore;

/// Keyring service for the local device identity. The account key is the
/// local device id, so two identities never share an entry.
const KEYRING_SERVICE: &str = "skills-manager-device-identity";

/// Maximum envelope lifetime, mirroring device_envelope's protocol limit.
const MAX_LIFETIME_SECS: i64 = 900;

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    /// PKCS#8 document for the Ed25519 key pair, hex-encoded.
    pkcs8_hex: String,
    key_id: String,
    created_at: i64,
}

/// The local signing identity. The key pair stays in memory only; dropping
/// this value releases it, and the keychain copy remains for the next load.
pub struct DeviceIdentity {
    pub device_id: String,
    pub key_id: String,
    public_key: [u8; 32],
    keypair: Ed25519KeyPair,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material, even in debug logs.
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Stable identifier for one key: `key-` plus the first 16 hex chars of
/// SHA-256 over the raw public key. Written next to signatures so a paired
/// device can pick the right trusted key.
fn key_id_for(public_key: &[u8]) -> String {
    format!("key-{}", fingerprint_hex(public_key))
}

/// First 16 hex chars of SHA-256 over the raw public key bytes.
fn fingerprint_hex(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    hex::encode(&digest[..8])
}

/// Grouped display form of a fingerprint, for a human to compare aloud:
/// `1234abcd ef012345`.
pub fn display_fingerprint(fingerprint: &str) -> String {
    let chars: Vec<char> = fingerprint.chars().collect();
    chars
        .chunks(8)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

fn valid_key_id(key_id: &str) -> bool {
    device_envelope::identifier(key_id) && key_id.starts_with("key-")
}

/// Load this machine's identity, generating and storing a new key pair on
/// first use. The device id is the stable `local_device_id`, so reloading
/// never creates a second identity for the same machine.
pub fn ensure_identity(store: &SkillStore) -> Result<DeviceIdentity> {
    let device_id = super::devices::local_device_id(store)?;
    let entry = keyring::Entry::new(KEYRING_SERVICE, &device_id)
        .context("failed to open the device identity keychain entry")?;
    match entry.get_password() {
        Ok(payload) => {
            let stored: StoredIdentity = serde_json::from_str(&payload)
                .context("stored device identity is not valid JSON")?;
            if stored.version != 1 {
                bail!("unsupported stored device identity version {}", stored.version);
            }
            let pkcs8 = hex::decode(&stored.pkcs8_hex)
                .context("stored device identity key is not valid hex")?;
            let identity = identity_from_pkcs8(&device_id, &pkcs8)?;
            if identity.key_id != stored.key_id {
                bail!("stored device identity key id does not match its key material");
            }
            Ok(identity)
        }
        Err(keyring::Error::NoEntry) => {
            let pkcs8_document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("failed to generate the device identity key"))?;
            let identity = identity_from_pkcs8(&device_id, pkcs8_document.as_ref())?;
            let stored = StoredIdentity {
                version: 1,
                pkcs8_hex: hex::encode(pkcs8_document.as_ref()),
                key_id: identity.key_id.clone(),
                created_at: now_secs(),
            };
            entry
                .set_password(&serde_json::to_string(&stored)?)
                .context("failed to store the device identity in the OS keychain")?;
            Ok(identity)
        }
        Err(err) => Err(err).context("failed to read the device identity from the OS keychain"),
    }
}

fn identity_from_pkcs8(device_id: &str, pkcs8: &[u8]) -> Result<DeviceIdentity> {
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| anyhow::anyhow!("stored device identity key material is invalid"))?;
    let public_key_bytes = keypair.public_key().as_ref();
    if public_key_bytes.len() != 32 {
        bail!("device identity public key is not 32 bytes");
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(public_key_bytes);
    Ok(DeviceIdentity {
        key_id: key_id_for(&public_key),
        device_id: device_id.to_string(),
        public_key,
        keypair,
    })
}

impl DeviceIdentity {
    /// Hex-encoded raw public key (64 chars), as embedded in a manifest.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Grouped fingerprint a human can compare when pairing.
    pub fn fingerprint(&self) -> String {
        display_fingerprint(&fingerprint_hex(&self.public_key))
    }

    /// Sign a fresh message for one payload. The message id is generated
    /// here; the envelope lifetime is clamped to the protocol maximum.
    /// Nothing is published — the caller decides where signed bytes go.
    pub fn sign_message(
        &self, kind: MessageKind, payload: Vec<u8>, now: i64, ttl_secs: i64,
    ) -> Result<SignedDeviceMessage> {
        if now <= 0 {
            bail!("message issue time must be positive");
        }
        if payload.len() > 1024 * 1024 {
            bail!("message payload exceeds the protocol size limit");
        }
        let ttl = ttl_secs.clamp(1, MAX_LIFETIME_SECS);
        let prefix = match kind {
            MessageKind::Command => "cmd",
            MessageKind::Receipt => "rcp",
            MessageKind::LibraryReport => "rpt",
        };
        let envelope = DeviceEnvelope {
            version: 1,
            kind,
            message_id: format!("{}-{}", prefix, uuid::Uuid::new_v4().simple()),
            device_id: self.device_id.clone(),
            key_id: self.key_id.clone(),
            issued_at: now,
            expires_at: now.checked_add(ttl).context("message expiry overflows")?,
            payload_sha256: hex::encode(Sha256::digest(&payload)),
        };
        let signature = self
            .keypair
            .sign(&device_envelope::signing_bytes(&envelope)?)
            .as_ref()
            .to_vec();
        Ok(SignedDeviceMessage { envelope, signature, payload })
    }
}

/// One signed message, ready to be published to a channel by the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDeviceMessage {
    pub envelope: DeviceEnvelope,
    /// Raw Ed25519 signature over the domain-separated envelope bytes.
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
}

/// What one device hands to another so its key can be paired. Contains only
/// public material; the fingerprint must be compared by a human.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PairingManifest {
    pub version: u8,
    pub device_id: String,
    pub key_id: String,
    /// Raw Ed25519 public key, hex-encoded (64 chars).
    pub public_key_hex: String,
    /// First 16 hex chars of SHA-256 over the raw public key bytes.
    pub fingerprint: String,
    /// Message kinds this key signs.
    pub purposes: Vec<MessageKind>,
    pub created_at: i64,
}

impl DeviceIdentity {
    /// Build a pairing manifest for the given purposes.
    pub fn pairing_manifest(&self, purposes: &[MessageKind]) -> Result<PairingManifest> {
        if purposes.is_empty() {
            bail!("a pairing manifest must declare at least one purpose");
        }
        Ok(PairingManifest {
            version: 1,
            device_id: self.device_id.clone(),
            key_id: self.key_id.clone(),
            public_key_hex: self.public_key_hex(),
            fingerprint: fingerprint_hex(&self.public_key),
            purposes: purposes.to_vec(),
            created_at: now_secs(),
        })
    }
}

/// A parsed, locally re-validated manifest. The fingerprint was recomputed
/// from the key bytes, so matching here only proves the manifest is
/// self-consistent — the human comparison against the sending device still
/// happens outside this function.
#[derive(Debug, Clone, Serialize)]
pub struct PairingPreview {
    pub device_id: String,
    pub key_id: String,
    pub fingerprint: String,
    pub purposes: Vec<MessageKind>,
}

fn parse_manifest(json: &str) -> Result<(PairingManifest, [u8; 32])> {
    let manifest: PairingManifest = serde_json::from_str(json)
        .context("pairing manifest is not valid JSON or has unexpected fields")?;
    if manifest.version != 1 {
        bail!("unsupported pairing manifest version {}", manifest.version);
    }
    if !device_envelope::identifier(&manifest.device_id) || !valid_key_id(&manifest.key_id) {
        bail!("pairing manifest carries an invalid device or key id");
    }
    if manifest.purposes.is_empty() {
        bail!("pairing manifest must declare at least one purpose");
    }
    let public_key = hex::decode(&manifest.public_key_hex)
        .context("pairing manifest public key is not valid hex")?;
    if public_key.len() != 32 {
        bail!("pairing manifest public key is not 32 bytes");
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&public_key);
    if fingerprint_hex(&key_bytes) != manifest.fingerprint {
        bail!("pairing manifest fingerprint does not match its public key");
    }
    Ok((manifest, key_bytes))
}

/// Validate a manifest for display: recompute the fingerprint locally and
/// return what the user must confirm before `approve_pairing_manifest`.
pub fn preview_pairing_manifest(json: &str) -> Result<PairingPreview> {
    let (manifest, key_bytes) = parse_manifest(json)?;
    Ok(PairingPreview {
        device_id: manifest.device_id,
        key_id: manifest.key_id,
        fingerprint: display_fingerprint(&fingerprint_hex(&key_bytes)),
        purposes: manifest.purposes,
    })
}

/// Register a manifest's key after the user explicitly approved the
/// fingerprint shown by `preview_pairing_manifest`. Idempotent for the same
/// key material; refuses to replace an existing key and refuses to revive a
/// revoked one (a revoked key must never come back through re-pairing).
pub fn approve_pairing_manifest(store: &SkillStore, json: &str) -> Result<PairingPreview> {
    let (manifest, key_bytes) = parse_manifest(json)?;
    store.with_conn(|conn| {
        for kind in &manifest.purposes {
            match device_pairing::trusted_public_key(
                conn, &manifest.device_id, &manifest.key_id, *kind,
            )? {
                // Already paired with the same key: nothing to change.
                Some((existing, true)) if existing == key_bytes.to_vec() => {}
                Some((_existing, true)) => bail!(
                    "device {} key {} is already paired with different key material; \
                     pairing a new key requires explicit revocation first",
                    manifest.device_id, manifest.key_id
                ),
                Some((_existing, false)) => bail!(
                    "device {} key {} was revoked; re-pairing requires a new key id",
                    manifest.device_id, manifest.key_id
                ),
                None => {
                    device_pairing::register_approved_key(
                        conn, &manifest.device_id, &manifest.key_id, *kind, &key_bytes,
                    )?;
                }
            }
        }
        Ok(())
    })?;
    Ok(PairingPreview {
        device_id: manifest.device_id,
        key_id: manifest.key_id,
        fingerprint: display_fingerprint(&fingerprint_hex(&key_bytes)),
        purposes: manifest.purposes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::git_credentials;

    fn test_store() -> (tempfile::TempDir, SkillStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillStore::new(&dir.path().join("test.db")).unwrap();
        (dir, store)
    }

    fn command_only() -> Vec<MessageKind> {
        vec![MessageKind::Command]
    }

    #[test]
    fn device_identity_survives_reload_per_device() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let first = ensure_identity(&store).unwrap();
        let second = ensure_identity(&store).unwrap();
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.key_id, second.key_id);
        assert_eq!(first.public_key_hex(), second.public_key_hex());

        // A different device id gets its own independent identity entry.
        store.set_setting(super::devices::SETTING_DEVICE_LOCAL_ID, "dev-other").unwrap();
        let other = ensure_identity(&store).unwrap();
        assert_eq!(other.device_id, "dev-other");
        assert_ne!(other.key_id, first.key_id);
    }

    #[test]
    fn device_identity_signed_message_verifies_through_pairing() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let payload = b"do the thing".to_vec();
        let signed = identity
            .sign_message(MessageKind::Command, payload.clone(), 1000, 300)
            .unwrap();
        assert!(signed.envelope.message_id.starts_with("cmd-"));
        assert_eq!(signed.envelope.expires_at - signed.envelope.issued_at, 300);

        // Pair this machine with itself, exactly as a peer would after the
        // user compares fingerprints, then verify the signed message.
        let manifest = identity.pairing_manifest(&command_only()).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        let preview = preview_pairing_manifest(&json).unwrap();
        assert_eq!(preview.fingerprint, identity.fingerprint());
        approve_pairing_manifest(&store, &json).unwrap();
        let key_bytes = hex::decode(&manifest.public_key_hex).unwrap();

        // Verify against an independent trust store holding the approved
        // key, mirroring the receiving device's side of the protocol.
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        device_pairing::initialize_trust_store(&conn).unwrap();
        device_pairing::register_approved_key(
            &conn, &identity.device_id, &identity.key_id, MessageKind::Command, &key_bytes,
        ).unwrap();

        let claimed = device_pairing::verify_and_claim_paired(
            &mut conn, &signed.envelope, &signed.signature, &signed.payload,
            &identity.device_id, MessageKind::Command, 1100,
        ).unwrap().unwrap();
        assert_eq!(claimed.payload(), payload.as_slice());
        assert_eq!(claimed.envelope().message_id, signed.envelope.message_id);

        // A replay of the same message is recognized, not re-accepted.
        assert!(device_pairing::verify_and_claim_paired(
            &mut conn, &signed.envelope, &signed.signature, &signed.payload,
            &identity.device_id, MessageKind::Command, 1101,
        ).unwrap().is_none());

        // Approving really did register this device's key in the app store.
        let paired = store.with_conn(|conn| {
            device_pairing::trusted_public_key(
                conn, &identity.device_id, &identity.key_id, MessageKind::Command,
            )
        }).unwrap();
        assert_eq!(paired.unwrap().0, key_bytes);
    }

    #[test]
    fn device_identity_tampered_payload_is_rejected() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let signed = identity
            .sign_message(MessageKind::Command, b"real payload".to_vec(), 1000, 300)
            .unwrap();
        let manifest = identity.pairing_manifest(&command_only()).unwrap();
        approve_pairing_manifest(&store, &serde_json::to_string(&manifest).unwrap()).unwrap();
        let key_bytes = hex::decode(&manifest.public_key_hex).unwrap();
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        device_pairing::initialize_trust_store(&conn).unwrap();
        device_pairing::register_approved_key(
            &conn, &identity.device_id, &identity.key_id, MessageKind::Command, &key_bytes,
        ).unwrap();
        let mut tampered = signed.clone();
        tampered.payload = b"evil payload".to_vec();
        assert!(device_pairing::verify_and_claim_paired(
            &mut conn, &tampered.envelope, &tampered.signature, &tampered.payload,
            &identity.device_id, MessageKind::Command, 1100,
        ).is_err());
    }

    #[test]
    fn device_identity_sign_clamps_ttl_and_rejects_bad_time() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        assert!(identity.sign_message(MessageKind::Receipt, b"x".to_vec(), 0, 300).is_err());
        assert!(identity.sign_message(MessageKind::Receipt, b"x".to_vec(), -5, 300).is_err());
        let long = identity
            .sign_message(MessageKind::Receipt, b"x".to_vec(), 1000, 100_000)
            .unwrap();
        assert!(long.envelope.message_id.starts_with("rcp-"));
        assert_eq!(long.envelope.expires_at - long.envelope.issued_at, MAX_LIFETIME_SECS);
    }

    #[test]
    fn device_identity_manifest_preview_rejects_tampering() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let json = serde_json::to_string(&identity.pairing_manifest(&command_only()).unwrap()).unwrap();

        // Unknown fields are refused outright.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["note"] = serde_json::json!("hello");
        assert!(preview_pairing_manifest(&value.to_string()).is_err());

        // A swapped public key breaks the self-consistency check.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["public_key_hex"] = serde_json::json!(hex::encode([7u8; 32]));
        assert!(preview_pairing_manifest(&value.to_string()).is_err());

        // A forged fingerprint cannot hide a mismatched key.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["public_key_hex"] = serde_json::json!(hex::encode([9u8; 32]));
        value["fingerprint"] = serde_json::json!(identity.fingerprint().replace(' ', ""));
        assert!(preview_pairing_manifest(&value.to_string()).is_err());

        assert!(preview_pairing_manifest("not json").is_err());
    }

    #[test]
    fn device_identity_approve_is_idempotent_but_never_replaces() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let manifest = identity.pairing_manifest(&command_only()).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        approve_pairing_manifest(&store, &json).unwrap();
        // Same key again: a no-op, not an error.
        approve_pairing_manifest(&store, &json).unwrap();

        // A different key claiming the same key id is refused, and the
        // originally paired key still verifies messages afterwards.
        let forged = PairingManifest {
            public_key_hex: hex::encode([8u8; 32]),
            fingerprint: fingerprint_hex(&[8u8; 32]),
            ..manifest.clone()
        };
        let err = approve_pairing_manifest(&store, &serde_json::to_string(&forged).unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("different key material"));
    }

    #[test]
    fn device_identity_revoked_key_cannot_return_through_repairing() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let manifest = identity.pairing_manifest(&command_only()).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        approve_pairing_manifest(&store, &json).unwrap();
        let revoked = store.with_conn(|conn| {
            device_pairing::revoke_key(conn, &identity.device_id, &identity.key_id, MessageKind::Command)
        }).unwrap();
        assert!(revoked);
        let err = approve_pairing_manifest(&store, &json).unwrap_err();
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn device_identity_multi_purpose_manifest_registers_each_slot() {
        git_credentials::use_mock_keyring();
        let (_dir, store) = test_store();
        let identity = ensure_identity(&store).unwrap();
        let purposes = vec![MessageKind::Command, MessageKind::LibraryReport];
        let json = serde_json::to_string(&identity.pairing_manifest(&purposes).unwrap()).unwrap();
        approve_pairing_manifest(&store, &json).unwrap();
        let paired = store.with_conn(|conn| {
            Ok((
                device_pairing::trusted_public_key(
                    conn, &identity.device_id, &identity.key_id, MessageKind::Command,
                )?,
                device_pairing::trusted_public_key(
                    conn, &identity.device_id, &identity.key_id, MessageKind::Receipt,
                )?,
            ))
        }).unwrap();
        assert!(paired.0.map(|(_, active)| active).unwrap_or(false));
        assert!(paired.1.is_none(), "undeclared purposes must stay unpaired");
    }

    #[test]
    fn device_identity_fingerprint_display_groups_hex() {
        let fp = "1234abcdef0123456789";
        assert_eq!(display_fingerprint(fp), "1234abcd ef012345 6789");
        assert_eq!(display_fingerprint(""), "");
    }
}

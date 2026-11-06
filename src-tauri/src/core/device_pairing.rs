//! Local device trust ledger. It is not yet connected to remote execution.
//! Callers must obtain explicit local approval before registering a key.
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use super::device_envelope::{self, DeviceEnvelope, MessageKind};

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn purpose(kind: MessageKind) -> &'static str {
    match kind {
        MessageKind::Command => "command",
        MessageKind::Receipt => "receipt",
        MessageKind::LibraryReport => "library_report",
    }
}

/// Create local trust and replay tables in the caller's chosen database.
pub fn initialize_trust_store(conn: &Connection) -> Result<()> {
    device_envelope::initialize_claim_store(conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_trusted_keys_v1 (
            device_id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            purpose TEXT NOT NULL,
            public_key BLOB NOT NULL CHECK(length(public_key) = 32),
            active INTEGER NOT NULL CHECK(active IN (0, 1)),
            PRIMARY KEY(device_id, key_id, purpose)
        );
        CREATE TABLE IF NOT EXISTS verified_message_bindings_v1 (
            device_id TEXT NOT NULL, message_id TEXT NOT NULL, key_id TEXT NOT NULL,
            purpose TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
            issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            prepared INTEGER NOT NULL DEFAULT 0 CHECK(prepared IN (0, 1)),
            PRIMARY KEY(device_id, message_id)
        );",
    )?;
    Ok(())
}

/// Register a public key only after explicit local pairing approval.
/// Existing keys are never silently replaced or reactivated.
pub fn register_approved_key(
    conn: &Connection, device_id: &str, key_id: &str,
    kind: MessageKind, public_key: &[u8],
) -> Result<()> {
    if !valid_id(device_id) || !valid_id(key_id) || public_key.len() != 32 {
        bail!("invalid local pairing");
    }
    conn.execute(
        "INSERT INTO device_trusted_keys_v1 (device_id, key_id, purpose, public_key, active)
         VALUES (?1, ?2, ?3, ?4, 1)",
        params![device_id, key_id, purpose(kind), public_key],
    )?;
    Ok(())
}

pub fn revoke_key(conn: &Connection, device_id: &str, key_id: &str, kind: MessageKind) -> Result<bool> {
    Ok(conn.execute(
        "UPDATE device_trusted_keys_v1 SET active = 0
         WHERE device_id = ?1 AND key_id = ?2 AND purpose = ?3 AND active = 1",
        params![device_id, key_id, purpose(kind)],
    )? == 1)
}

/// An owned copy of the exact envelope and payload that were verified and
/// claimed. This is not authorization to execute; revalidate local approval
/// and key revocation at the action boundary.
pub struct ClaimedDeviceMessage {
    envelope: DeviceEnvelope,
    payload: Vec<u8>,
}

impl ClaimedDeviceMessage {
    pub fn envelope(&self) -> &DeviceEnvelope { &self.envelope }
    pub fn payload(&self) -> &[u8] { &self.payload }
}

/// Atomically check locally paired identity and claim the message ID. The
/// caller must perform a fresh authorization check before any side effect;
/// revocation after this transaction is not an execution authorization.
pub fn verify_and_claim_paired(
    conn: &mut Connection, envelope: &DeviceEnvelope, signature: &[u8], payload: &[u8],
    expected_device: &str, expected_kind: MessageKind, now: i64,
) -> Result<Option<ClaimedDeviceMessage>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let public_key: Option<Vec<u8>> = tx.query_row(
        "SELECT public_key FROM device_trusted_keys_v1
         WHERE device_id = ?1 AND key_id = ?2 AND purpose = ?3 AND active = 1",
        params![expected_device, envelope.key_id, purpose(expected_kind)],
        |row| row.get(0),
    ).optional()?;
    let public_key = public_key.context("device key is not locally paired or has been revoked")?;
    let verified = device_envelope::verify_envelope(envelope, signature, payload, &public_key,
        expected_device, &envelope.key_id, expected_kind, now)?;
    let accepted = device_envelope::claim_verified_once(&tx, &verified, now)?;
    let claimed = if accepted {
        tx.execute(
            "INSERT INTO verified_message_bindings_v1
             (device_id, message_id, key_id, purpose, payload_sha256, issued_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![envelope.device_id, envelope.message_id, envelope.key_id, purpose(envelope.kind),
                envelope.payload_sha256, envelope.issued_at, envelope.expires_at],
        )?;
        Some(ClaimedDeviceMessage { envelope: envelope.clone(), payload: payload.to_vec() })
    } else { None };
    tx.commit()?;
    Ok(claimed)
}

/// A command whose signature, replay claim, current local trust, and time
/// window were checked. This does not approve any agent/root or perform work.
pub struct PreparedDeviceCommand { claimed: ClaimedDeviceMessage }

impl PreparedDeviceCommand {
    pub fn envelope(&self) -> &DeviceEnvelope { self.claimed.envelope() }
    pub fn payload(&self) -> &[u8] { self.claimed.payload() }
}

/// Atomically recheck trust and consume the preparation slot exactly once.
/// Agent/root approval and crash-safe execution are still required separately.
pub fn prepare_claimed_command(
    conn: &mut Connection, claimed: ClaimedDeviceMessage, now: i64,
) -> Result<PreparedDeviceCommand> {
    let env = claimed.envelope();
    if env.kind != MessageKind::Command { bail!("message is not a command"); }
    let digest = hex::encode(Sha256::digest(claimed.payload()));
    if digest != env.payload_sha256 { bail!("claimed message payload changed"); }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let rows = tx.execute(
        "UPDATE verified_message_bindings_v1 SET prepared = 1
         WHERE device_id = ?1 AND message_id = ?2 AND key_id = ?3 AND purpose = 'command'
           AND payload_sha256 = ?4 AND issued_at = ?5 AND expires_at = ?6
           AND ?7 >= issued_at AND ?7 < expires_at AND prepared = 0
           AND EXISTS (SELECT 1 FROM device_trusted_keys_v1
                       WHERE device_id = ?1 AND key_id = ?3 AND purpose = 'command' AND active = 1)",
        params![env.device_id, env.message_id, env.key_id, digest, env.issued_at, env.expires_at, now],
    )?;
    if rows != 1 { bail!("claim missing, expired, already prepared, or key revoked"); }
    tx.commit()?;
    Ok(PreparedDeviceCommand { claimed })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
    use sha2::{Digest, Sha256};

    fn fixture() -> (Ed25519KeyPair, DeviceEnvelope, Vec<u8>, Vec<u8>) {
        let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
        let payload = b"fixture".to_vec();
        let env = DeviceEnvelope {
            version: 1, kind: MessageKind::LibraryReport,
            message_id: "msg-1".into(), device_id: "device-1".into(), key_id: "key-1".into(),
            issued_at: 1000, expires_at: 1100, payload_sha256: hex::encode(Sha256::digest(&payload)),
        };
        let sig = key.sign(&device_envelope::signing_bytes(&env).unwrap()).as_ref().to_vec();
        (key, env, payload, sig)
    }

    #[test]
    fn device_pairing_accepts_only_locally_approved_key_and_once() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, env, payload, sig) = fixture();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).is_err());
        register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        assert!(register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).is_err());
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "other-device", MessageKind::LibraryReport, 1050).is_err());
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::Command, 1050).is_err());
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, b"changed",
            "device-1", MessageKind::LibraryReport, 1050).is_err());
        let claimed = verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).unwrap().unwrap();
        assert_eq!(claimed.payload(), payload.as_slice());
        assert_eq!(claimed.envelope().message_id, env.message_id);
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).unwrap().is_none());
    }

    #[test]
    fn device_pairing_claimed_message_owns_verified_content() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, mut env, mut payload, sig) = fixture();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        let claimed = verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).unwrap().unwrap();
        payload[0] ^= 1;
        env.message_id = "different".into();
        assert_eq!(claimed.payload(), b"fixture");
        assert_eq!(claimed.envelope().message_id, "msg-1");
    }

    #[test]
    fn device_pairing_revoke_persists_and_rejects_new_messages() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trust.db");
        let mut conn = Connection::open(&path).unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, env, payload, sig) = fixture();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        assert!(revoke_key(&conn, "device-1", "key-1", MessageKind::LibraryReport).unwrap());
        drop(conn);
        conn = Connection::open(&path).unwrap();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).is_err());
        assert!(register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).is_err());
    }
    #[test]
    fn device_pairing_revocation_commits_before_waiting_claim() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("trust.db");
        let mut admin = Connection::open(&path).unwrap();
        initialize_trust_store(&admin).unwrap();
        let (key, env, payload, sig) = fixture();
        register_approved_key(&admin, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        let tx = admin.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
        assert!(revoke_key(&tx, "device-1", "key-1", MessageKind::LibraryReport).unwrap());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut conn = Connection::open(path).unwrap();
            conn.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
            ready_tx.send(()).unwrap();
            verify_and_claim_paired(&mut conn, &env, &sig, &payload,
                "device-1", MessageKind::LibraryReport, 1050).is_err()
        });
        ready_rx.recv().unwrap();
        tx.commit().unwrap();
        assert!(worker.join().unwrap());
        let count: i64 = admin.query_row("SELECT COUNT(*) FROM verified_message_claims_v1", [],
            |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

}

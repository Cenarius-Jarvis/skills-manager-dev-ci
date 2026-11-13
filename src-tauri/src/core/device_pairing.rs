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
        );
        CREATE TABLE IF NOT EXISTS verified_message_inbox_v1 (
            device_id TEXT NOT NULL, message_id TEXT NOT NULL,
            envelope BLOB NOT NULL, signature BLOB NOT NULL, payload BLOB NOT NULL,
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

/// The public key currently paired for one (device, key, purpose) slot, if
/// any. Callers compare it against a manifest to decide whether re-pairing
/// would replace existing key material.
pub fn trusted_public_key(
    conn: &Connection, device_id: &str, key_id: &str, kind: MessageKind,
) -> Result<Option<(Vec<u8>, bool)>> {
    let row = conn.query_row(
        "SELECT public_key, active FROM device_trusted_keys_v1
         WHERE device_id = ?1 AND key_id = ?2 AND purpose = ?3",
        params![device_id, key_id, purpose(kind)],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)? == 1)),
    ).optional()?;
    Ok(row)
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
        // Inbox and replay claim commit together. A crash after verification
        // cannot silently lose the signed bytes while making replay impossible.
        tx.execute(
            "INSERT INTO verified_message_inbox_v1 (device_id, message_id, envelope, signature, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![envelope.device_id, envelope.message_id, serde_json::to_vec(envelope)?, signature, payload],
        )?;
        Some(ClaimedDeviceMessage { envelope: envelope.clone(), payload: payload.to_vec() })
    } else { None };
    tx.commit()?;
    Ok(claimed)
}

/// Recover signed bytes only for a claim that has not entered preparation.
/// Re-check current local trust, signature, payload, message kind, and expiry.
/// A prepared operation is deliberately not replayed: its outcome is unknown.
pub fn resume_unprepared_claim(
    conn: &mut Connection, expected_device: &str, message_id: &str,
    expected_kind: MessageKind, now: i64,
) -> Result<Option<ClaimedDeviceMessage>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String, String, i64, i64)> = tx.query_row(
        "SELECT i.envelope, i.signature, i.payload, k.public_key,
                b.key_id, b.payload_sha256, b.issued_at, b.expires_at
         FROM verified_message_inbox_v1 i
         JOIN verified_message_bindings_v1 b ON b.device_id = i.device_id AND b.message_id = i.message_id
         JOIN device_trusted_keys_v1 k ON k.device_id = b.device_id
             AND k.key_id = b.key_id AND k.purpose = b.purpose
         WHERE i.device_id = ?1 AND i.message_id = ?2 AND b.purpose = ?3
               AND b.prepared = 0 AND k.active = 1
               AND length(i.envelope) <= 8192 AND length(i.signature) = 64
               AND length(i.payload) <= 1048576 AND length(k.public_key) = 32",
        params![expected_device, message_id, purpose(expected_kind)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                   row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
    ).optional()?;
    let Some((encoded, signature, payload, public_key, key_id, digest, issued_at, expires_at)) = row else {
        tx.commit()?;
        return Ok(None);
    };
    let envelope: DeviceEnvelope = serde_json::from_slice(&encoded)?;
    if envelope.message_id != message_id || envelope.payload_sha256 != digest
        || envelope.issued_at != issued_at || envelope.expires_at != expires_at {
        bail!("stored message does not match its replay binding");
    }
    device_envelope::verify_envelope(&envelope, &signature, &payload,
        &public_key, expected_device, &key_id, expected_kind, now)?;
    tx.commit()?;
    Ok(Some(ClaimedDeviceMessage { envelope, payload }))
}


/// Informational only: pending messages still require full verification.
#[derive(Debug, PartialEq, Eq)]
pub struct InboxRecoveryEntry { pub message_id: String, pub state: InboxRecoveryState }
#[derive(Debug, PartialEq, Eq)]
pub enum InboxRecoveryState { PendingVerification, Expired, TrustUnavailable, PreparedOutcomeUnknown }

/// Inspect up to 256 commands for one device; prepared never implies replay.
pub fn list_command_recovery(conn: &Connection, device_id: &str, now: i64) -> Result<Vec<InboxRecoveryEntry>> {
    if !valid_id(device_id) { bail!("invalid device id"); }
    let mut stmt = conn.prepare(
        "SELECT b.message_id, b.prepared, b.expires_at,
                EXISTS(SELECT 1 FROM device_trusted_keys_v1 k
                    WHERE k.device_id=b.device_id AND k.key_id=b.key_id
                    AND k.purpose=b.purpose AND k.active=1)
         FROM verified_message_bindings_v1 b
         JOIN verified_message_inbox_v1 i ON i.device_id=b.device_id AND i.message_id=b.message_id
         WHERE b.device_id=?1 AND b.purpose='command'
         ORDER BY b.issued_at, b.message_id LIMIT 257")?;
    let rows = stmt.query_map(params![device_id], |row| {
        let prepared: i64 = row.get(1)?;
        let expires_at: i64 = row.get(2)?;
        let trusted: bool = row.get(3)?;
        let state = if prepared != 0 { InboxRecoveryState::PreparedOutcomeUnknown }
            else if !trusted { InboxRecoveryState::TrustUnavailable }
            else if now >= expires_at { InboxRecoveryState::Expired }
            else { InboxRecoveryState::PendingVerification };
        Ok(InboxRecoveryEntry { message_id: row.get(0)?, state })
    })?;
    let entries = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if entries.len() > 256 { bail!("recovery inventory exceeds limit; pagination required"); }
    Ok(entries)
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
    prepare_inner(conn, claimed, now, |_| Ok(()))
}

/// Atomically consume the preparation slot AND run `extra` inside the same
/// transaction. The executor uses this to create its execution ledger entry
/// with the prepared state, so a crash can never land between "the command
/// may no longer be replayed" and "the command is recorded as in flight":
/// either both committed (a restart reports it unknown) or neither did (the
/// claim stays recoverable as unprepared). `extra` failing rolls the whole
/// transaction back.
pub fn prepare_claimed_command_with<F>(
    conn: &mut Connection, claimed: ClaimedDeviceMessage, now: i64,
    extra: F,
) -> Result<PreparedDeviceCommand>
where
    F: FnOnce(&rusqlite::Transaction) -> Result<()>,
{
    prepare_inner(conn, claimed, now, extra)
}

fn prepare_inner<F>(
    conn: &mut Connection, claimed: ClaimedDeviceMessage, now: i64,
    extra: F,
) -> Result<PreparedDeviceCommand>
where
    F: FnOnce(&rusqlite::Transaction) -> Result<()>,
{
    let env = claimed.envelope().clone();
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
    extra(&tx)?;
    tx.commit()?;
    Ok(PreparedDeviceCommand { claimed })
}

/// Commands that were claimed (their replay slot is taken) but never
/// entered preparation — the state a crash between claim and prepare
/// leaves behind. They were never executed, so recovery may run them once.
/// Bound mirrors the recovery inventory; expired claims are excluded (they
/// can no longer be verified, and `list_command_recovery` surfaces them).
/// Claims from every locally paired manager whose command was received but
/// never prepared — the state a crash between claim and prepare leaves
/// behind. The bindings' device id is the SIGNING manager (the envelope's
/// device id), not the receiving device, so the query keys off paired
/// managers rather than one id. Returned as (manager device id, message id);
/// expired claims are excluded (`list_command_recovery` surfaces them).
pub fn list_unprepared_claims(conn: &Connection, now: i64) -> Result<Vec<(String, String)>> {
    #[cfg(test)]
    {
        let count = |sql: &str| -> i64 {
            let mut stmt = conn.prepare(sql).unwrap_or_else(|e| {
                eprintln!("claim list diag: prepare failed for {sql}: {e}");
                return conn.prepare("SELECT COUNT(*) FROM verified_message_bindings_v1").unwrap_or_else(|e2| {
                    eprintln!("claim list diag: fallback prepare failed too: {e2}");
                    std::process::exit(201);
                });
            });
            let n = stmt.query_row([], |row| row.get::<_, i64>(0)).unwrap_or(-1);
            eprintln!("claim list diag: {sql} => {n}");
            n
        };
        eprintln!(
            "claim list diag: bindings_cmd={} bindings_cmd_unprepared_future={} inbox={} active_mgr_keys={}",
            count("SELECT COUNT(*) FROM verified_message_bindings_v1 WHERE purpose = 'command'"),
            count(&format!("SELECT COUNT(*) FROM verified_message_bindings_v1 WHERE purpose = 'command' AND prepared = 0 AND expires_at > {now}")),
            count("SELECT COUNT(*) FROM verified_message_inbox_v1"),
            count("SELECT COUNT(*) FROM device_trusted_keys_v1 WHERE purpose = 'command' AND active = 1"),
        );
    }
    let mut stmt = conn.prepare(
        "SELECT b.device_id, b.message_id FROM verified_message_bindings_v1 b
         JOIN verified_message_inbox_v1 i
           ON i.device_id = b.device_id AND i.message_id = b.message_id
         WHERE b.purpose = 'command' AND b.prepared = 0 AND b.expires_at > ?1
               AND EXISTS (SELECT 1 FROM device_trusted_keys_v1 k
                           WHERE k.device_id = b.device_id AND k.purpose = 'command'
                                 AND k.active = 1)
         ORDER BY b.issued_at, b.message_id LIMIT 257",
    )?;
    let rows = stmt
        .query_map(params![now], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() > 256 { bail!("unprepared claim list exceeds limit; pagination required"); }
    Ok(rows)
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

    fn claimed_command_fixture() -> (Connection, ClaimedDeviceMessage) {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, mut env, payload, _) = fixture();
        env.kind = MessageKind::Command;
        let sig = key.sign(&device_envelope::signing_bytes(&env).unwrap()).as_ref().to_vec();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::Command,
            key.public_key().as_ref()).unwrap();
        let claimed = verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::Command, 1050).unwrap().unwrap();
        (conn, claimed)
    }

    #[test]
    fn device_pairing_preparation_requires_current_trust_and_time() {
        let (mut conn, claimed) = claimed_command_fixture();
        assert!(revoke_key(&conn, "device-1", "key-1", MessageKind::Command).unwrap());
        assert!(prepare_claimed_command(&mut conn, claimed, 1051).is_err());

        let (mut conn, claimed) = claimed_command_fixture();
        assert!(prepare_claimed_command(&mut conn, claimed, 1100).is_err());
    }

    #[test]
    fn device_pairing_preparation_consumes_the_exact_claim_once() {
        let (mut conn, claimed) = claimed_command_fixture();
        let duplicate = ClaimedDeviceMessage {
            envelope: claimed.envelope().clone(), payload: claimed.payload().to_vec(),
        };
        let prepared = prepare_claimed_command(&mut conn, claimed, 1051).unwrap();
        assert_eq!(prepared.payload(), b"fixture");
        assert_eq!(prepared.envelope().message_id, "msg-1");
        assert!(prepare_claimed_command(&mut conn, duplicate, 1051).is_err());
    }

    #[test]
    fn device_pairing_preparation_refuses_a_different_ledger_and_report() {
        let (_, claimed) = claimed_command_fixture();
        let mut other = Connection::open_in_memory().unwrap();
        initialize_trust_store(&other).unwrap();
        assert!(prepare_claimed_command(&mut other, claimed, 1051).is_err());

        let mut conn = Connection::open_in_memory().unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, env, payload, sig) = fixture();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        let report = verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).unwrap().unwrap();
        assert!(prepare_claimed_command(&mut conn, report, 1051).is_err());
    }

    #[test]
    fn device_pairing_pending_inbox_survives_restart_and_prepares_once() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("inbox.db");
        let mut conn = Connection::open(&path).unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, mut env, payload, _) = fixture();
        env.kind = MessageKind::Command;
        let sig = key.sign(&device_envelope::signing_bytes(&env).unwrap()).as_ref().to_vec();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::Command,
            key.public_key().as_ref()).unwrap();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::Command, 1050).unwrap().is_some());
        drop(conn);
        let mut conn = Connection::open(&path).unwrap();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::Command, 1051).unwrap().is_none());
        let first = resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1051).unwrap().unwrap();
        let second = resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1051).unwrap().unwrap();
        assert_eq!(first.payload(), payload.as_slice());
        prepare_claimed_command(&mut conn, first, 1051).unwrap();
        assert!(prepare_claimed_command(&mut conn, second, 1051).is_err());
        drop(conn);
        let mut conn = Connection::open(&path).unwrap();
        assert!(resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1052).unwrap().is_none());
    }

    #[test]
    fn device_pairing_pending_inbox_rechecks_trust_expiry_and_content() {
        let (mut conn, _) = claimed_command_fixture();
        assert!(resume_unprepared_claim(&mut conn, "other", "msg-1",
            MessageKind::Command, 1051).unwrap().is_none());
        assert!(resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::LibraryReport, 1051).unwrap().is_none());
        assert!(resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1100).is_err());
        conn.execute("UPDATE verified_message_inbox_v1 SET payload = ?1",
            params![b"tampered".as_slice()]).unwrap();
        assert!(resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1051).is_err());

        let (mut conn, _) = claimed_command_fixture();
        assert!(revoke_key(&conn, "device-1", "key-1", MessageKind::Command).unwrap());
        assert!(resume_unprepared_claim(&mut conn, "device-1", "msg-1",
            MessageKind::Command, 1051).unwrap().is_none());
    }

    #[test]
    fn device_pairing_inbox_failure_rolls_back_replay_claim() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_trust_store(&conn).unwrap();
        let (key, env, payload, sig) = fixture();
        register_approved_key(&conn, "device-1", "key-1", MessageKind::LibraryReport,
            key.public_key().as_ref()).unwrap();
        conn.execute_batch("CREATE TRIGGER fail_inbox BEFORE INSERT ON verified_message_inbox_v1
            BEGIN SELECT RAISE(FAIL, 'fixture failure'); END;").unwrap();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).is_err());
        conn.execute_batch("DROP TRIGGER fail_inbox;").unwrap();
        assert!(verify_and_claim_paired(&mut conn, &env, &sig, &payload,
            "device-1", MessageKind::LibraryReport, 1050).unwrap().is_some());
    }

    #[test]
    fn device_pairing_recovery_inventory_never_treats_prepared_as_retryable() {
        let (mut conn, claimed) = claimed_command_fixture();
        assert_eq!(list_command_recovery(&conn, "device-1", 1051).unwrap()[0].state,
            InboxRecoveryState::PendingVerification);
        assert!(list_command_recovery(&conn, "other", 1051).unwrap().is_empty());
        assert_eq!(list_command_recovery(&conn, "device-1", 1100).unwrap()[0].state,
            InboxRecoveryState::Expired);
        prepare_claimed_command(&mut conn, claimed, 1051).unwrap();
        revoke_key(&conn, "device-1", "key-1", MessageKind::Command).unwrap();
        assert_eq!(list_command_recovery(&conn, "device-1", 1100).unwrap()[0].state,
            InboxRecoveryState::PreparedOutcomeUnknown);
        let (conn, _) = claimed_command_fixture();
        revoke_key(&conn, "device-1", "key-1", MessageKind::Command).unwrap();
        assert_eq!(list_command_recovery(&conn, "device-1", 1051).unwrap()[0].state,
            InboxRecoveryState::TrustUnavailable);
        assert!(list_command_recovery(&conn, "../bad", 1051).is_err());
    }

}

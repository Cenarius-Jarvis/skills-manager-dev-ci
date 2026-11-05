//! Test-only protocol experiment. No production handler calls this code.
//! It verifies a signed command and records a one-time claim; it never deploys.
use anyhow::{bail, Context, Result};
use ring::signature::{self, UnparsedPublicKey};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_TTL_SECONDS: i64 = 900;
const MAX_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandV1 {
    version: u32,
    key_id: String,
    command_id: String,
    device_id: String,
    operation: String,
    skill_id: String,
    source_hash: String,
    agent_key: String,
    root_fingerprint: String,
    issued_at: i64,
    expires_at: i64,
}

struct TrustedKey {
    key_id: String,
    device_id: String,
    public_key: [u8; 32],
}

fn bounded_identifier(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn digest_string(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Binary framing prevents ambiguity between field boundaries or JSON ordering.
fn canonical(cmd: &CommandV1) -> Result<Vec<u8>> {
    let mut out = b"skills-manager-device-command-v1\0".to_vec();
    out.extend_from_slice(&cmd.version.to_be_bytes());
    for value in [&cmd.key_id, &cmd.command_id, &cmd.device_id, &cmd.operation,
        &cmd.skill_id, &cmd.source_hash, &cmd.agent_key, &cmd.root_fingerprint] {
        let length = u32::try_from(value.len()).context("field too long")?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out.extend_from_slice(&cmd.issued_at.to_be_bytes());
    out.extend_from_slice(&cmd.expires_at.to_be_bytes());
    Ok(out)
}

/// Validate a signed envelope before any claim or deployment.
fn validate_signed_command(cmd: &CommandV1, signature: &[u8],
    trusted: &TrustedKey, expected_device: &str, now: i64) -> Result<String> {
    if cmd.version != 1 || cmd.operation != "deploy_existing_skill_v1"
        || !bounded_identifier(&cmd.key_id, 64)
        || uuid::Uuid::parse_str(&cmd.command_id).map(|id| id.to_string() != cmd.command_id).unwrap_or(true)
        || !bounded_identifier(&cmd.device_id, 128)
        || !bounded_identifier(&cmd.skill_id, 128)
        || !bounded_identifier(&cmd.agent_key, 64)
        || !digest_string(&cmd.source_hash) || !digest_string(&cmd.root_fingerprint)
        || cmd.key_id != trusted.key_id || cmd.device_id != expected_device
        || cmd.device_id != trusted.device_id
    { bail!("invalid command identity or fields"); }
    let ttl = cmd.expires_at.checked_sub(cmd.issued_at).context("invalid lifetime")?;
    if cmd.issued_at <= 0 || ttl <= 0 || ttl > MAX_TTL_SECONDS
        || cmd.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || cmd.expires_at <= now { bail!("command lifetime is invalid"); }
    let payload = canonical(cmd)?;
    UnparsedPublicKey::new(&signature::ED25519, &trusted.public_key)
        .verify(&payload, signature).map_err(|_| anyhow::anyhow!("invalid signature"))?;
    Ok(hex::encode(Sha256::digest(&payload)))
}

fn insert_claim(conn: &Connection, cmd: &CommandV1, payload_hash: &str) -> Result<()> {
    let inserted = conn.execute(
        "INSERT INTO fixture_command_claims (command_id, device_id, payload_hash, state)
         VALUES (?1, ?2, ?3, 'claimed')
         ON CONFLICT(command_id) DO NOTHING",
        params![cmd.command_id, cmd.device_id, payload_hash],
    )?;
    if inserted != 1 { bail!("command already claimed"); }
    Ok(())
}

/// Verify before claiming; an already claimed ID is never re-executed.
/// The caller supplies an isolated, pre-initialized fixture database.
fn verify_and_claim(conn: &mut Connection, cmd: &CommandV1, signature: &[u8],
    trusted: &TrustedKey, expected_device: &str, now: i64) -> Result<()> {
    let payload_hash = validate_signed_command(cmd, signature, trusted, expected_device, now)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_claim(&tx, cmd, &payload_hash)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
    use std::time::Duration;

    fn fixture() -> (CommandV1, TrustedKey, Ed25519KeyPair) {
        let rng = SystemRandom::new();
        let bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(signer.public_key().as_ref());
        let trusted = TrustedKey { key_id: "controller-key".into(), device_id: "dev-fixture".into(), public_key };
        let cmd = CommandV1 {
            version: 1, key_id: trusted.key_id.clone(), command_id: uuid::Uuid::new_v4().to_string(),
            device_id: trusted.device_id.clone(), operation: "deploy_existing_skill_v1".into(),
            skill_id: "skill-one".into(), source_hash: "a".repeat(64), agent_key: "codex".into(),
            root_fingerprint: "b".repeat(64), issued_at: 100, expires_at: 300,
        };
        (cmd, trusted, signer)
    }

    fn open_fixture(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        conn.execute_batch("CREATE TABLE IF NOT EXISTS fixture_command_claims (
            command_id TEXT PRIMARY KEY, device_id TEXT NOT NULL,
            payload_hash TEXT NOT NULL, state TEXT NOT NULL
                CHECK(state IN ('claimed', 'revoked_after_claim', 'consuming', 'blocked_recovery'))
        ); CREATE TABLE IF NOT EXISTS fixture_recovery_cases (
            command_id TEXT PRIMARY KEY, classification TEXT NOT NULL
        ); CREATE TABLE IF NOT EXISTS fixture_trusted_keys (
            device_id TEXT NOT NULL, key_id TEXT NOT NULL,
            public_key BLOB NOT NULL CHECK(length(public_key) = 32),
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            PRIMARY KEY(device_id, key_id)
        ); CREATE TABLE IF NOT EXISTS fixture_authorized_roots (
            device_id TEXT NOT NULL, agent_key TEXT NOT NULL,
            fingerprint TEXT NOT NULL CHECK(length(fingerprint) = 64),
            state TEXT NOT NULL CHECK(state IN ('active', 'revoked')),
            PRIMARY KEY(device_id, agent_key)
        );").unwrap();
        conn
    }

    struct LocalFixtureApproval {
        device_id: String,
        agent_key: String,
        root_fingerprint: String,
    }

    fn local_fixture_approval() -> LocalFixtureApproval {
        LocalFixtureApproval {
            device_id: "dev-fixture".into(), agent_key: "codex".into(), root_fingerprint: "b".repeat(64),
        }
    }

    /// This local fixture is independent of remote command data.
    fn initialize_pairing(conn: &mut Connection, trust: &TrustedKey, approval: &LocalFixtureApproval) -> Result<()> {
        if trust.device_id != approval.device_id || approval.device_id != "dev-fixture"
            || !bounded_identifier(&trust.key_id, 64) || !bounded_identifier(&approval.agent_key, 64)
            || !digest_string(&approval.root_fingerprint) {
            bail!("invalid local pairing");
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO fixture_trusted_keys VALUES (?1, ?2, ?3, 'active')",
            params![trust.device_id, trust.key_id, trust.public_key.as_slice()])?;
        tx.execute("INSERT INTO fixture_authorized_roots VALUES (?1, ?2, ?3, 'active')",
            params![approval.device_id, approval.agent_key, approval.root_fingerprint])?;
        tx.commit()?;
        Ok(())
    }

    /// Caller must hold an immediate transaction during the whole operation.
    fn validate_pairing(conn: &Connection, cmd: &CommandV1, signature: &[u8], local_device: &str, now: i64) -> Result<String> {
        use rusqlite::OptionalExtension;
        if cmd.device_id != local_device { bail!("wrong local device"); }
        let key: Option<Vec<u8>> = conn.query_row(
            "SELECT public_key FROM fixture_trusted_keys WHERE device_id = ?1 AND key_id = ?2 AND state = 'active'",
            params![cmd.device_id, cmd.key_id], |row| row.get(0)).optional()?;
        let bytes = key.context("key not trusted")?;
        let public_key: [u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("invalid public key"))?;
        let fingerprint: Option<String> = conn.query_row(
            "SELECT fingerprint FROM fixture_authorized_roots WHERE device_id = ?1 AND agent_key = ?2 AND state = 'active'",
            params![cmd.device_id, cmd.agent_key], |row| row.get(0)).optional()?;
        if fingerprint.as_deref() != Some(cmd.root_fingerprint.as_str()) { bail!("root not authorized"); }
        let trust = TrustedKey { key_id: cmd.key_id.clone(), device_id: cmd.device_id.clone(), public_key };
        validate_signed_command(cmd, signature, &trust, local_device, now)
    }

    fn paired_claim(conn: &mut Connection, cmd: &CommandV1, signature: &[u8], local_device: &str, now: i64) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hash = validate_pairing(&tx, cmd, signature, local_device, now)?;
        insert_claim(&tx, cmd, &hash)?;
        tx.commit()?;
        Ok(())
    }

    /// Fixture only: recheck authorization before marking work as started.
    /// This transition does not perform any filesystem action.
    fn paired_begin(conn: &mut Connection, cmd: &CommandV1, signature: &[u8], local_device: &str, now: i64) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hash = validate_pairing(&tx, cmd, signature, local_device, now)?;
        let changed = tx.execute(
            "UPDATE fixture_command_claims SET state = 'consuming'
             WHERE command_id = ?1 AND device_id = ?2 AND payload_hash = ?3 AND state = 'claimed'",
            params![cmd.command_id, cmd.device_id, hash])?;
        if changed != 1 { bail!("claim cannot begin"); }
        tx.commit()?;
        Ok(())
    }

    /// Fixture-only recovery observation. Never follows or writes the target,
    /// never restarts work, and only classifies what is visible at this instant.
    fn block_interrupted_fixture(conn: &mut Connection, command_id: &str, approved_root: &std::path::Path) -> Result<String> {
        fn is_link_or_reparse(meta: &std::fs::Metadata) -> bool {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                meta.file_type().is_symlink() || meta.file_attributes() & 0x400 != 0
            }
            #[cfg(not(windows))]
            { meta.file_type().is_symlink() }
        }
        let classification = match std::fs::symlink_metadata(approved_root) {
            Ok(meta) if is_link_or_reparse(&meta) || !meta.is_dir() => "unsafe_root",
            Ok(_) => match std::fs::symlink_metadata(approved_root.join("sample")) {
                Ok(meta) if is_link_or_reparse(&meta) => "unsafe_target",
                Ok(_) => "target_exists",
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => "no_target",
                Err(_) => "unknown",
            },
            Err(_) => "unknown",
        };
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE fixture_command_claims SET state = 'blocked_recovery' WHERE command_id = ?1 AND state = 'consuming'",
            params![command_id])?;
        if changed != 1 { bail!("no interrupted consuming claim"); }
        tx.execute("INSERT INTO fixture_recovery_cases (command_id, classification) VALUES (?1, ?2)",
            params![command_id, classification])?;
        tx.commit()?;
        Ok(classification.into())
    }

    /// Revocation conservatively invalidates every pending claim on that fixture device.
    fn revoke_fixture_key(conn: &mut Connection, device_id: &str, key_id: &str) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE fixture_trusted_keys SET state = 'revoked' WHERE device_id = ?1 AND key_id = ?2",
            params![device_id, key_id])?;
        if changed != 1 { bail!("unknown trusted key"); }
        tx.execute("UPDATE fixture_command_claims SET state = 'revoked_after_claim' WHERE device_id = ?1 AND state = 'claimed'",
            params![device_id])?;
        tx.commit()?;
        Ok(())
    }

    fn revoke_fixture_root(conn: &mut Connection, device_id: &str, agent_key: &str) -> Result<()> {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE fixture_authorized_roots SET state = 'revoked' WHERE device_id = ?1 AND agent_key = ?2",
            params![device_id, agent_key])?;
        if changed != 1 { bail!("unknown agent root"); }
        tx.execute("UPDATE fixture_command_claims SET state = 'revoked_after_claim' WHERE device_id = ?1 AND state = 'claimed'",
            params![device_id])?;
        tx.commit()?;
        Ok(())
    }

    #[test]
    fn remote_auth_prototype_revoked_agent_root_rejects_new_claim() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        revoke_fixture_root(&mut conn, &cmd.device_id, &cmd.agent_key).unwrap();
        assert!(paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_command_claims", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_auth_prototype_pairing_rolls_back_if_root_already_exists() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (_, trust, _) = fixture();
        conn.execute("INSERT INTO fixture_authorized_roots VALUES (?1, ?2, ?3, 'active')",
            params!["dev-fixture", "codex", "b".repeat(64)]).unwrap();
        assert!(initialize_pairing(&mut conn, &trust, &local_fixture_approval()).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_trusted_keys", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0, "failed pairing must not retain a key");
    }

    #[test]
    fn remote_auth_prototype_pairing_rejects_other_local_device() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (_, mut trust, _) = fixture();
        trust.device_id = "not-the-local-device".into();
        assert!(initialize_pairing(&mut conn, &trust, &local_fixture_approval()).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_trusted_keys", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_auth_prototype_pairing_requires_matching_local_trust_and_root() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        let mut changed = cmd.clone();
        changed.root_fingerprint = "c".repeat(64);
        let changed_signature = signer.sign(&canonical(&changed).unwrap());
        assert!(paired_claim(&mut conn, &changed, changed_signature.as_ref(), "dev-fixture", 200).is_err());
        assert!(paired_claim(&mut conn, &cmd, &[], "dev-fixture", 200).is_err());
        assert!(paired_claim(&mut conn, &cmd, signature.as_ref(), "different-local-device", 200).is_err());
        paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        assert!(paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        revoke_fixture_key(&mut conn, &cmd.device_id, &cmd.key_id).unwrap();
        let state: String = conn.query_row("SELECT state FROM fixture_command_claims WHERE command_id = ?1",
            params![cmd.command_id], |row| row.get(0)).unwrap();
        assert_eq!(state, "revoked_after_claim");
        let mut new_cmd = cmd.clone();
        new_cmd.command_id = uuid::Uuid::new_v4().to_string();
        let new_signature = signer.sign(&canonical(&new_cmd).unwrap());
        assert!(paired_claim(&mut conn, &new_cmd, new_signature.as_ref(), "dev-fixture", 200).is_err());
    }

    #[test]
    fn remote_auth_prototype_root_revocation_invalidates_pending_claim() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        revoke_fixture_root(&mut conn, &cmd.device_id, &cmd.agent_key).unwrap();
        let state: String = conn.query_row("SELECT state FROM fixture_command_claims WHERE command_id = ?1",
            params![cmd.command_id], |row| row.get(0)).unwrap();
        assert_eq!(state, "revoked_after_claim");
    }

    #[test]
    fn remote_auth_prototype_untrusted_key_does_not_create_claim() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (mut cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        cmd.key_id = "unregistered".into();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        assert!(paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_command_claims", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_auth_prototype_begin_requires_same_claim_and_current_approval() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        let mut altered = cmd.clone();
        altered.source_hash = "c".repeat(64);
        let altered_signature = signer.sign(&canonical(&altered).unwrap());
        assert!(paired_begin(&mut conn, &altered, altered_signature.as_ref(), "dev-fixture", 200).is_err());
        paired_begin(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        assert!(paired_begin(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        // Revocation cannot promise to cancel a transition that already started.
        revoke_fixture_key(&mut conn, &cmd.device_id, &cmd.key_id).unwrap();
        let state: String = conn.query_row("SELECT state FROM fixture_command_claims WHERE command_id = ?1",
            params![cmd.command_id], |row| row.get(0)).unwrap();
        assert_eq!(state, "consuming");
    }

    #[test]
    fn remote_auth_prototype_begin_refuses_revocation_after_claim() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        revoke_fixture_root(&mut conn, &cmd.device_id, &cmd.agent_key).unwrap();
        assert!(paired_begin(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        let state: String = conn.query_row("SELECT state FROM fixture_command_claims WHERE command_id = ?1",
            params![cmd.command_id], |row| row.get(0)).unwrap();
        assert_eq!(state, "revoked_after_claim");
    }

    #[test]
    fn remote_auth_prototype_begin_and_revocation_have_defined_order() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("commands.db");
        let mut conn = open_fixture(&db);
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap()).as_ref().to_vec();
        paired_claim(&mut conn, &cmd, &signature, "dev-fixture", 200).unwrap();
        drop(conn);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let db_a = db.clone();
        let cmd_a = cmd.clone();
        let gate_a = barrier.clone();
        let begin = std::thread::spawn(move || {
            let mut conn = open_fixture(&db_a);
            gate_a.wait();
            paired_begin(&mut conn, &cmd_a, &signature, "dev-fixture", 200).is_ok()
        });
        let db_b = db.clone();
        let cmd_b = cmd.clone();
        let gate_b = barrier.clone();
        let revoke = std::thread::spawn(move || {
            let mut conn = open_fixture(&db_b);
            gate_b.wait();
            revoke_fixture_key(&mut conn, &cmd_b.device_id, &cmd_b.key_id).unwrap();
        });
        let began = begin.join().unwrap();
        revoke.join().unwrap();
        let conn = open_fixture(&db);
        let state: String = conn.query_row("SELECT state FROM fixture_command_claims WHERE command_id = ?1",
            params![cmd.command_id], |row| row.get(0)).unwrap();
        assert_eq!(state, if began { "consuming" } else { "revoked_after_claim" });
    }

    fn interrupted_fixture(temp: &std::path::Path) -> (Connection, CommandV1, Vec<u8>) {
        let mut conn = open_fixture(&temp.join("commands.db"));
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        let signature = signer.sign(&canonical(&cmd).unwrap()).as_ref().to_vec();
        paired_claim(&mut conn, &cmd, &signature, "dev-fixture", 200).unwrap();
        paired_begin(&mut conn, &cmd, &signature, "dev-fixture", 200).unwrap();
        (conn, cmd, signature)
    }

    #[test]
    fn remote_auth_prototype_recovery_blocks_without_replay_when_target_absent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fake-agent");
        std::fs::create_dir_all(&root).unwrap();
        let (mut conn, cmd, signature) = interrupted_fixture(temp.path());
        assert_eq!(block_interrupted_fixture(&mut conn, &cmd.command_id, &root).unwrap(), "no_target");
        assert!(!root.join("sample").exists());
        assert!(paired_begin(&mut conn, &cmd, &signature, "dev-fixture", 200).is_err());
        assert!(paired_claim(&mut conn, &cmd, &signature, "dev-fixture", 200).is_err());
        drop(conn);
        let conn = open_fixture(&temp.path().join("commands.db"));
        let (state, class): (String, String) = conn.query_row(
            "SELECT c.state, r.classification FROM fixture_command_claims c JOIN fixture_recovery_cases r USING(command_id) WHERE c.command_id = ?1",
            params![cmd.command_id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!((state.as_str(), class.as_str()), ("blocked_recovery", "no_target"));
    }

    #[test]
    fn remote_auth_prototype_recovery_preserves_existing_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fake-agent");
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("sample");
        std::fs::write(&target, b"do-not-modify").unwrap();
        let (mut conn, cmd, signature) = interrupted_fixture(temp.path());
        assert_eq!(block_interrupted_fixture(&mut conn, &cmd.command_id, &root).unwrap(), "target_exists");
        assert_eq!(std::fs::read(&target).unwrap().as_slice(), b"do-not-modify");
        assert!(paired_begin(&mut conn, &cmd, &signature, "dev-fixture", 200).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn remote_auth_prototype_recovery_refuses_target_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fake-agent");
        let external = temp.path().join("sentinel");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("safe.txt"), b"safe").unwrap();
        std::os::unix::fs::symlink(&external, root.join("sample")).unwrap();
        let (mut conn, cmd, _) = interrupted_fixture(temp.path());
        assert_eq!(block_interrupted_fixture(&mut conn, &cmd.command_id, &root).unwrap(), "unsafe_target");
        assert_eq!(std::fs::read(external.join("safe.txt")).unwrap().as_slice(), b"safe");
    }

    #[cfg(windows)]
    #[test]
    fn remote_auth_prototype_recovery_refuses_target_junction() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fake-agent");
        let external = temp.path().join("sentinel");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("safe.txt"), b"safe").unwrap();
        junction::create(&external, root.join("sample")).unwrap();
        let (mut conn, cmd, _) = interrupted_fixture(temp.path());
        assert_eq!(block_interrupted_fixture(&mut conn, &cmd.command_id, &root).unwrap(), "unsafe_target");
        assert_eq!(std::fs::read(external.join("safe.txt")).unwrap().as_slice(), b"safe");
    }

    #[test]
    fn remote_auth_prototype_pairing_revoke_and_claim_serialize() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("commands.db");
        let mut conn = open_fixture(&db);
        let (cmd, trust, signer) = fixture();
        initialize_pairing(&mut conn, &trust, &local_fixture_approval()).unwrap();
        drop(conn);
        let signature = signer.sign(&canonical(&cmd).unwrap()).as_ref().to_vec();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let db_a = db.clone();
        let cmd_a = cmd.clone();
        let gate_a = barrier.clone();
        let claim = std::thread::spawn(move || {
            let mut conn = open_fixture(&db_a);
            gate_a.wait();
            paired_claim(&mut conn, &cmd_a, &signature, "dev-fixture", 200).is_ok()
        });
        let db_b = db.clone();
        let cmd_b = cmd.clone();
        let gate_b = barrier.clone();
        let revoke = std::thread::spawn(move || {
            let mut conn = open_fixture(&db_b);
            gate_b.wait();
            revoke_fixture_key(&mut conn, &cmd_b.device_id, &cmd_b.key_id).unwrap();
        });
        let claimed = claim.join().unwrap();
        revoke.join().unwrap();
        let conn = open_fixture(&db);
        let mut stmt = conn.prepare("SELECT state FROM fixture_command_claims WHERE command_id = ?1").unwrap();
        let mut rows = stmt.query(params![cmd.command_id]).unwrap();
        match rows.next().unwrap() {
            Some(row) => { assert!(claimed); assert_eq!(row.get::<_, String>(0).unwrap(), "revoked_after_claim"); }
            None => assert!(!claimed),
        }
    }

    #[test]
    fn remote_auth_prototype_accepts_once_even_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("commands.db");
        let (cmd, trust, signer) = fixture();
        let sig = signer.sign(&canonical(&cmd).unwrap());
        let mut conn = open_fixture(&db);
        verify_and_claim(&mut conn, &cmd, sig.as_ref(), &trust, "dev-fixture", 200).unwrap();
        drop(conn);
        let mut reopened = open_fixture(&db);
        assert!(verify_and_claim(&mut reopened, &cmd, sig.as_ref(), &trust, "dev-fixture", 200).is_err());
        let count: i64 = reopened.query_row("SELECT COUNT(*) FROM fixture_command_claims", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn remote_auth_prototype_rejects_tampering_wrong_device_key_and_expiry() {
        let temp = tempfile::tempdir().unwrap();
        let mut conn = open_fixture(&temp.path().join("commands.db"));
        let (cmd, trust, signer) = fixture();
        let sig = signer.sign(&canonical(&cmd).unwrap());
        let mut altered = cmd.clone();
        altered.source_hash = "c".repeat(64);
        assert!(verify_and_claim(&mut conn, &altered, sig.as_ref(), &trust, "dev-fixture", 200).is_err());
        assert!(verify_and_claim(&mut conn, &cmd, sig.as_ref(), &trust, "other-device", 200).is_err());
        let (_, other_key, _) = fixture();
        assert!(verify_and_claim(&mut conn, &cmd, sig.as_ref(), &other_key, "dev-fixture", 200).is_err());
        assert!(verify_and_claim(&mut conn, &cmd, sig.as_ref(), &trust, "dev-fixture", 300).is_err());
        assert!(verify_and_claim(&mut conn, &cmd, &[], &trust, "dev-fixture", 200).is_err());
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_command_claims", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_auth_prototype_subprocess_worker() {
        let fixture_path = match std::env::var_os("SM_AUTH_FIXTURE") {
            Some(value) => std::path::PathBuf::from(value),
            None => return,
        };
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(fixture_path).unwrap()).unwrap();
        let cmd: CommandV1 = serde_json::from_value(value["command"].clone()).unwrap();
        let public = hex::decode(value["public_key"].as_str().unwrap()).unwrap();
        let signature = hex::decode(value["signature"].as_str().unwrap()).unwrap();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&public);
        let trust = TrustedKey { key_id: cmd.key_id.clone(), device_id: cmd.device_id.clone(), public_key };
        let mut conn = open_fixture(std::path::Path::new(value["database"].as_str().unwrap()));
        let accepted = verify_and_claim(&mut conn, &cmd, &signature, &trust, "dev-fixture", 200).is_ok();
        assert_eq!(accepted, std::env::var("SM_AUTH_EXPECT").unwrap() == "accept");
    }

    #[test]
    fn remote_auth_prototype_replay_is_rejected_across_processes() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("commands.db");
        drop(open_fixture(&db));
        let (cmd, trust, signer) = fixture();
        let signature = signer.sign(&canonical(&cmd).unwrap());
        let payload = serde_json::json!({
            "command": cmd, "public_key": hex::encode(trust.public_key),
            "signature": hex::encode(signature.as_ref()), "database": db.to_str().unwrap()
        });
        let fixture_path = temp.path().join("fixture.json");
        std::fs::write(&fixture_path, serde_json::to_vec(&payload).unwrap()).unwrap();
        for expectation in ["accept", "reject"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "core::remote_auth_prototype::tests::remote_auth_prototype_subprocess_worker"])
                .env("SM_AUTH_FIXTURE", &fixture_path)
                .env("SM_AUTH_EXPECT", expectation)
                .output().unwrap();
            assert!(status.status.success(), "independent verifier process failed");
            assert!(String::from_utf8_lossy(&status.stdout).contains("1 passed"),
                "verifier process did not run exactly one worker test");
        }
        let conn = open_fixture(&db);
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM fixture_command_claims", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    /// End-to-end fixture only: signed claim -> managed library -> fake agent.
    #[test]
    fn remote_auth_prototype_signed_managed_fixture_deploys_only_once() {
        use crate::core::{central_repo, content_hash, native_managed_executor, skill_store::{SkillRecord, SkillStore}};
        let _guard = central_repo::test_base_dir_lock();
        struct ResetBase;
        impl Drop for ResetBase {
            fn drop(&mut self) { central_repo::set_test_base_dir_override(None); }
        }
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("manager");
        let source = base.join("skills").join("sample");
        let agent = temp.path().join("fake-agent");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(source.join("SKILL.md"), "# fake fixture").unwrap();
        central_repo::set_test_base_dir_override(Some(base.clone()));
        let _reset = ResetBase;
        let store = SkillStore::new(&base.join("manager.db")).unwrap();
        let hash = content_hash::hash_directory(&source).unwrap();
        store.insert_skill(&SkillRecord {
            id: "fixture-skill".into(), name: "sample".into(), description: None,
            source_type: "git".into(), source_ref: Some("https://example.invalid/repo.git".into()),
            source_ref_resolved: None, source_subpath: None, source_branch: None,
            source_revision: None, remote_revision: None, central_path: source.to_string_lossy().into_owned(),
            content_hash: Some(hash.clone()), enabled: true, created_at: 1, updated_at: 1,
            status: "ok".into(), update_status: "up_to_date".into(), last_checked_at: None, last_check_error: None,
        }).unwrap();
        let (mut cmd, trust, signer) = fixture();
        cmd.skill_id = "fixture-skill".into();
        cmd.source_hash = hash.clone();
        let approved = std::fs::canonicalize(&agent).unwrap();
        // This local fingerprint is a test placeholder, not a Windows path-identity solution.
        let local_approval = LocalFixtureApproval {
            device_id: "dev-fixture".into(), agent_key: "codex".into(),
            root_fingerprint: hex::encode(Sha256::digest(approved.to_string_lossy().as_bytes())),
        };
        cmd.root_fingerprint = local_approval.root_fingerprint.clone();
        let signature = signer.sign(&canonical(&cmd).unwrap());

        // The native fixture must refuse bytes that changed after signing.
        std::fs::write(source.join("SKILL.md"), "# modified fixture").unwrap();
        let error = native_managed_executor::deploy_new_slot(&store, &cmd.skill_id, &cmd.agent_key, &approved).unwrap_err();
        assert!(error.to_string().contains("managed library content changed"),
            "modified content must be rejected for the expected reason");
        assert!(!agent.join("sample").exists());
        std::fs::write(source.join("SKILL.md"), "# fake fixture").unwrap();

        let mut conn = open_fixture(&temp.path().join("claims.db"));
        initialize_pairing(&mut conn, &trust, &local_approval).unwrap();
        assert_eq!(cmd.source_hash, store.get_skill_by_id(&cmd.skill_id).unwrap().unwrap().content_hash.unwrap());
        paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        paired_begin(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).unwrap();
        let target = native_managed_executor::deploy_new_slot(&store, &cmd.skill_id, &cmd.agent_key, &approved).unwrap();
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(), "# fake fixture");
        assert_eq!(store.get_targets_for_skill(&cmd.skill_id).unwrap().len(), 1);
        assert!(paired_claim(&mut conn, &cmd, signature.as_ref(), "dev-fixture", 200).is_err());
        assert_eq!(store.get_targets_for_skill(&cmd.skill_id).unwrap().len(), 1);
    }

    #[test]
    fn remote_auth_prototype_one_concurrent_claim_wins() {
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("commands.db");
        drop(open_fixture(&db));
        let (cmd, trust, signer) = fixture();
        let sig = signer.sign(&canonical(&cmd).unwrap()).as_ref().to_vec();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = vec![];
        for _ in 0..2 {
            let (db, cmd, signature, barrier) = (db.clone(), cmd.clone(), sig.clone(), barrier.clone());
            let trust = TrustedKey { key_id: trust.key_id.clone(), device_id: trust.device_id.clone(), public_key: trust.public_key };
            threads.push(std::thread::spawn(move || {
                let mut conn = open_fixture(&db);
                barrier.wait();
                verify_and_claim(&mut conn, &cmd, &signature, &trust, "dev-fixture", 200).is_ok()
            }));
        }
        assert_eq!(threads.into_iter().map(|thread| thread.join().unwrap()).filter(|ok| *ok).count(), 1);
    }
}

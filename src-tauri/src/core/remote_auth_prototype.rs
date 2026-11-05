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

/// Verify before claiming; an already claimed ID is never re-executed.
/// The caller supplies an isolated, pre-initialized fixture database.
fn verify_and_claim(conn: &mut Connection, cmd: &CommandV1, signature: &[u8],
    trusted: &TrustedKey, expected_device: &str, now: i64) -> Result<()> {
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
    let payload_hash = hex::encode(Sha256::digest(&payload));
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO fixture_command_claims (command_id, device_id, payload_hash, state)
         VALUES (?1, ?2, ?3, 'claimed')",
        params![cmd.command_id, cmd.device_id, payload_hash],
    )?;
    if inserted != 1 { bail!("command already claimed"); }
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
        );").unwrap();
        conn
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

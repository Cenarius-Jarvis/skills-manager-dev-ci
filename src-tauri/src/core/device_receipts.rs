//! Manager-side projection of signed deployment results.

use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use super::device_envelope::{self, MessageKind};
use super::device_pairing;
use super::device_signed_executor::{
    SignedReceiptPayload, RECEIPT_SCHEMA, RECEIPT_STATUS_FAILED, RECEIPT_STATUS_REJECTED,
    RECEIPT_STATUS_SUCCESS, RECEIPT_STATUS_UNKNOWN,
};
use super::devices::{self, DeviceInstructionRow};
use super::signed_channel::SignedChannelMessage;
use super::skill_store::SkillStore;

pub(crate) fn channel_scope(url: &str, branch: &str) -> String {
    hex::encode(Sha256::digest(format!("{url}\0{branch}").as_bytes()))
}

fn request_key(id: &str) -> String {
    format!("device.signed-request.v1.{id}")
}

fn receipt_key(id: &str) -> String {
    format!("device.verified-receipt.v1.{id}")
}

/// Only a successful local publication can create this association.
pub(crate) fn remember_publication(
    store: &SkillStore,
    id: &str,
    url: &str,
    branch: &str,
    commit: &str,
) -> Result<()> {
    store.with_conn_mut(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute(
            "UPDATE device_instructions SET instruction_commit = ?2
             WHERE id = ?1 AND instruction_commit IS NULL AND receipt_status IS NULL",
            params![id, commit],
        )? != 1 {
            bail!("could not associate the published command with a pending local request");
        }
        tx.execute("INSERT INTO settings(key, value) VALUES (?1, ?2)",
            params![request_key(id), channel_scope(url, branch)])?;
        tx.commit()?;
        Ok(())
    })
}

pub(crate) fn published_requests(store: &SkillStore) -> Result<Vec<DeviceInstructionRow>> {
    let Some(url) = devices::channel_url(store) else { return Ok(Vec::new()); };
    let scope = channel_scope(&url, &devices::channel_branch(store));
    let mut result = Vec::new();
    for row in store.get_device_instructions(None)? {
        if store.get_setting(&request_key(&row.id))?.as_deref() == Some(scope.as_str()) {
            result.push(row);
        }
    }
    Ok(result)
}

/// Project at most one outcome per locally published request. The trust
/// check, replay/conflict check and DB writes share a transaction.
pub(crate) fn import(
    store: &SkillStore,
    scope: &str,
    directory_device: &str,
    message: &SignedChannelMessage,
    now: i64,
) -> Result<bool> {
    let payload: SignedReceiptPayload = serde_json::from_str(&message.payload_json)?;
    devices::validate_instruction_id(&payload.instruction_id)?;
    let envelope = &message.envelope;
    if payload.schema != RECEIPT_SCHEMA
        || !matches!(payload.status.as_str(), RECEIPT_STATUS_SUCCESS | RECEIPT_STATUS_FAILED | RECEIPT_STATUS_REJECTED | RECEIPT_STATUS_UNKNOWN)
        || payload.finished_at <= 0
        || payload.finished_at > envelope.issued_at
        || envelope.issued_at > now
    {
        bail!("invalid signed receipt metadata");
    }
    store.with_conn_mut(|conn| {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request: Option<(String, String, Option<String>, i64, String)> = tx.query_row(
            "SELECT i.device_id, i.agent_key, i.skill_name, i.created_at, i.instruction_commit
             FROM device_instructions i JOIN settings s ON s.key = ?2 AND s.value = ?3
             WHERE i.id = ?1 AND i.instruction_commit IS NOT NULL",
            params![&payload.instruction_id, request_key(&payload.instruction_id), scope],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional()?;
        // Another manager's requests can share this channel.
        let Some((device, agent, skill, created_at, commit)) = request else { return Ok(false); };
        if directory_device != device || payload.finished_at < created_at
            || payload.agent_key.as_ref().is_some_and(|key| key != &agent)
            || (payload.status == RECEIPT_STATUS_SUCCESS
                && (payload.agent_key.as_deref() != Some(agent.as_str()) || payload.skill_name != skill))
        {
            bail!("signed receipt does not match the published request");
        }
        let (public_key, active) = device_pairing::trusted_public_key(
            &tx, &device, &envelope.key_id, MessageKind::Receipt,
        )?.context("receipt signing key is not paired")?;
        if !active { bail!("receipt signing key is revoked"); }
        // A finished result can be read after the manager was offline. Verify
        // the original signing window and reject future timestamps above.
        device_envelope::verify_envelope(
            envelope, &hex::decode(&message.signature)?, message.payload_json.as_bytes(),
            &public_key, &device, &envelope.key_id, MessageKind::Receipt, envelope.issued_at,
        )?;
        let key = receipt_key(&payload.instruction_id);
        let accepted: Option<String> = tx.query_row(
            "SELECT value FROM settings WHERE key = ?1", params![&key], |row| row.get(0),
        ).optional()?;
        if let Some(accepted) = accepted {
            if accepted == envelope.payload_sha256 { return Ok(false); }
            bail!("conflicting signed result for an already verified request");
        }
        let state = match payload.status.as_str() {
            RECEIPT_STATUS_SUCCESS => devices::TASK_STATE_SUCCESS,
            RECEIPT_STATUS_UNKNOWN => devices::TASK_STATE_UNKNOWN,
            _ => devices::TASK_STATE_FAILED,
        };
        let detail = payload.reason.as_ref().map(|reason| reason.chars().take(500).collect::<String>());
        tx.execute(
            "UPDATE device_instructions SET receipt_status = ?2, receipt_reason = NULL,
             receipt_detail = ?3, receipt_commit = ?4, receipt_at = ?5, executor_version = ?6,
             state = ?7 WHERE id = ?1",
            params![&payload.instruction_id, &payload.status, detail, commit,
                    payload.finished_at, &payload.executor_version, state],
        )?;
        tx.execute("INSERT INTO settings(key, value) VALUES (?1, ?2)", params![key, &envelope.payload_sha256])?;
        tx.commit()?;
        Ok(true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{device_identity::{self, DeviceIdentity}, signed_channel};

    fn signed_result(
        identity: &DeviceIdentity,
        instruction_id: &str,
        status: &str,
        finished_at: i64,
    ) -> SignedChannelMessage {
        let payload_json = serde_json::to_string(&SignedReceiptPayload {
            schema: RECEIPT_SCHEMA, instruction_id: instruction_id.into(), status: status.into(),
            reason: None, skill_name: Some("demo-skill".into()), agent_key: Some("codex".into()),
            target_path: None, executor_version: "test".into(), finished_at,
        }).unwrap();
        let sign = identity.sign_message(MessageKind::Receipt, payload_json.as_bytes().to_vec(),
            finished_at, 600).unwrap();
        SignedChannelMessage { envelope: sign.envelope, signature: hex::encode(sign.signature), payload_json }
    }

    fn request(store: &SkillStore, target: &str, id: &str, created_at: i64) {
        store.upsert_device_instruction(&DeviceInstructionRow {
            id: id.into(), device_id: target.into(), action: "deploy".into(), skill_url: None,
            skill_branch: None, skill_subpath: None, skill_name: Some("demo-skill".into()),
            agent_key: "codex".into(), created_at, expires_at: None, created_by: None,
            instruction_commit: None, receipt_commit: None, state: devices::TASK_STATE_PENDING.into(),
            receipt_status: None, receipt_reason: None, receipt_detail: None, receipt_at: None,
            executor_version: None,
        }).unwrap();
    }

    #[test]
    fn signed_receipt_roundtrip_requires_published_request_and_paired_device() {
        let temp = tempfile::tempdir().unwrap();
        let manager = SkillStore::new(&temp.path().join("manager.db")).unwrap();
        let target_store = SkillStore::new(&temp.path().join("target.db")).unwrap();
        let identity = device_identity::ensure_identity(&target_store).unwrap();
        let target = &identity.device_id;
        let now = chrono::Utc::now().timestamp();
        manager.upsert_device(&devices::DeviceRow {
            id: target.clone(), name: "test".into(), platform: None, created_at: now,
            last_seen_at: None, last_state_commit: None,
        }).unwrap();
        let remote = temp.path().join("channel.git");
        assert!(std::process::Command::new("git").args(["init", "--bare"])
            .arg(&remote).output().unwrap().status.success());
        let url = remote.to_str().unwrap();
        let branch = "receipts-test";
        let scope = channel_scope(url, branch);
        let id = "cmd-signed-receipt";
        request(&manager, target, id, now - 7200);
        // The manager was offline past the short signing window.
        let valid = signed_result(&identity, id, RECEIPT_STATUS_SUCCESS, now - 3600);
        assert!(!import(&manager, &scope, target, &valid, now).unwrap());
        remember_publication(&manager, id, url, branch, "test-commit").unwrap();
        assert!(import(&manager, &scope, target, &valid, now).is_err());
        let manifest = identity.pairing_manifest(&[MessageKind::Receipt]).unwrap();
        device_identity::approve_pairing_manifest(&manager, &serde_json::to_string(&manifest).unwrap()).unwrap();
        assert!(!import(&manager, &channel_scope(url, "wrong-branch"), target, &valid, now).unwrap());
        assert!(import(&manager, &scope, "wrong-device", &valid, now).is_err());
        let mut altered = valid.clone();
        altered.payload_json.push(' ');
        assert!(import(&manager, &scope, target, &altered, now).is_err());
        assert!(manager.get_device_instruction(id).unwrap().unwrap().receipt_status.is_none());

        signed_channel::publish_signed_receipt(&target_store, url, branch, target, &valid).unwrap();
        let snapshot = devices::fetch_channel_snapshot(url, branch).unwrap();
        assert_eq!(devices::import_snapshot(&manager, &snapshot).unwrap().receipts, 1);
        assert_eq!(devices::import_snapshot(&manager, &snapshot).unwrap().receipts, 0);
        let conflicting = signed_result(&identity, id, RECEIPT_STATUS_UNKNOWN, now);
        assert!(import(&manager, &scope, target, &conflicting, now).is_err());
        let result = manager.get_device_instruction(id).unwrap().unwrap();
        assert_eq!(result.state, devices::TASK_STATE_SUCCESS);
        assert_eq!(result.receipt_commit.as_deref(), Some("test-commit"));

        let unknown_id = "cmd-unknown-result";
        request(&manager, target, unknown_id, now - 1);
        remember_publication(&manager, unknown_id, url, branch, "unknown-commit").unwrap();
        let unknown = signed_result(&identity, unknown_id, RECEIPT_STATUS_UNKNOWN, now);
        assert!(import(&manager, &scope, target, &unknown, now).unwrap());
        assert_eq!(manager.get_device_instruction(unknown_id).unwrap().unwrap().state, devices::TASK_STATE_UNKNOWN);

        manager.with_conn(|conn| device_pairing::revoke_key(conn, target, &identity.key_id, MessageKind::Receipt)).unwrap();
        let revoked_id = "cmd-revoked-key";
        request(&manager, target, revoked_id, now - 1);
        remember_publication(&manager, revoked_id, url, branch, "revoked-commit").unwrap();
        let revoked = signed_result(&identity, revoked_id, RECEIPT_STATUS_SUCCESS, now);
        assert!(import(&manager, &scope, target, &revoked, now).is_err());
    }
}

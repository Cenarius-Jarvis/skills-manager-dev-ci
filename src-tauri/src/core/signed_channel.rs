//! Signed instructions on the device channel.
//!
//! A signed command travels as one JSON file per message under
//! `devices/{device_id}/signed-commands/{message_id}.json`. The wire format
//! preserves the exact payload bytes that were signed, so the receiving
//! device verifies without re-serializing anything.
//!
//! Publishing a signed command is still not executing one: the target device
//! must verify the signature against its locally paired key, claim the
//! message id against replay, and pass its own local authorization before
//! any effect. Nothing in this module runs anything.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::device_envelope::{self, DeviceEnvelope, MessageKind};
use super::device_identity::{self, DeviceIdentity, SignedDeviceMessage};
use super::devices;
use super::skill_store::SkillStore;

pub const SIGNED_COMMAND_SCHEMA: u32 = 1;
/// Operators publish instructions for devices that may be offline for days;
/// the envelope default mirrors that expectation.
pub const DEFAULT_COMMAND_TTL_SECS: i64 = 7 * 24 * 3600;
/// One channel file, before the envelope and payload are even counted.
const MAX_CHANNEL_FILE_BYTES: usize = 1024 * 1024;
/// Per-device bound mirroring the recovery inventory: beyond this a device
/// cannot make sense of its queue, so publishing refuses loudly.
const MAX_PENDING_COMMANDS_PER_DEVICE: usize = 256;

/// The operator-meaningful content of one instruction. This is what gets
/// signed — everything the device needs to decide what would be executed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedCommandPayload {
    pub schema: u32,
    pub action: String,
    pub skill_url: Option<String>,
    pub skill_branch: Option<String>,
    pub skill_subpath: Option<String>,
    pub skill_name: Option<String>,
    pub agent_key: String,
    /// The publishing manager's device id; also the envelope's device_id,
    /// because the manager is the signer.
    pub issued_by: String,
    pub issued_by_name: Option<String>,
    /// The device this command is addressed to. Carried inside the signed
    /// payload — a device never trusts a directory path alone.
    pub target_device: String,
}

/// Channel wire format: the exact signed payload bytes are carried as a
/// string, so verification hashes those bytes directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedChannelMessage {
    pub envelope: DeviceEnvelope,
    /// Ed25519 signature over the domain-separated envelope bytes, hex.
    pub signature: String,
    /// Exact payload bytes the envelope's payload_sha256 covers.
    pub payload_json: String,
}

/// Validate everything the device will later re-check, at creation time, so
/// a malformed instruction fails at the operator's screen rather than on the
/// device after the fact.
pub fn validate_signed_command_payload(payload: &SignedCommandPayload) -> Result<()> {
    if payload.schema != SIGNED_COMMAND_SCHEMA {
        bail!("unsupported signed command schema {}", payload.schema);
    }
    match payload.action.as_str() {
        devices::ACTION_DEPLOY | devices::ACTION_UNDEPLOY => {}
        other => bail!("unsupported signed command action {other:?}"),
    }
    devices::validate_device_id(&payload.issued_by)?;
    devices::validate_device_id(&payload.target_device)?;
    devices::validate_agent_key(&payload.agent_key)?;
    match payload.action.as_str() {
        devices::ACTION_DEPLOY => devices::validate_skill_url(payload.skill_url.as_deref())?,
        // An undeploy names the skill directly; a URL would be ignored.
        devices::ACTION_UNDEPLOY => {
            if payload.skill_url.is_some() {
                bail!("undeploy commands must not carry a skill_url");
            }
        }
        _ => unreachable!("action validated above"),
    }
    devices::validate_skill_subpath(payload.skill_subpath.as_deref())?;
    match (&payload.action[..], &payload.skill_name) {
        (_, Some(name)) => devices::validate_skill_name(name)?,
        (devices::ACTION_UNDEPLOY, None) => {
            bail!("undeploy commands must name a skill");
        }
        _ => {}
    }
    if let Some(name) = &payload.issued_by_name {
        if name.len() > 100 || name.chars().any(|c| c.is_control()) {
            bail!("invalid issuer name");
        }
    }
    Ok(())
}

/// Sign one command payload with this machine's identity. The command id is
/// the envelope's message id and stays stable across channel round trips.
pub fn create_signed_command(
    identity: &DeviceIdentity,
    target_device_id: &str,
    payload: &SignedCommandPayload,
    now: i64,
    ttl_secs: i64,
) -> Result<SignedChannelMessage> {
    validate_signed_command_payload(payload)?;
    devices::validate_device_id(target_device_id)?;
    if payload.issued_by != identity.device_id {
        bail!("payload issuer does not match the signing identity");
    }
    if payload.target_device != target_device_id {
        bail!("payload target does not match the requested device");
    }
    let payload_json = serde_json::to_string(payload)?;
    let signed = identity.sign_message(
        MessageKind::Command,
        payload_json.clone().into_bytes(),
        now,
        ttl_secs,
    )?;
    Ok(into_channel_message(signed, &payload_json))
}

fn into_channel_message(signed: SignedDeviceMessage, payload_json: &str) -> SignedChannelMessage {
    SignedChannelMessage {
        envelope: signed.envelope,
        signature: hex::encode(signed.signature),
        payload_json: payload_json.to_string(),
    }
}

/// Full receiver-side verification against the locally paired key of the
/// signing manager. Returns the validated payload; the caller must still
/// claim the message id via `device_pairing` and run its own authorization
/// before any effect.
pub fn verify_channel_command(
    message: &SignedChannelMessage,
    trusted_public_key: &[u8],
    expected_signing_device: &str,
    own_device_id: &str,
    now: i64,
) -> Result<SignedCommandPayload> {
    if message.envelope.kind != MessageKind::Command
        || message.envelope.device_id != expected_signing_device
    {
        bail!("signed command is not signed by a paired manager");
    }
    if message.payload_json.len() > 1024 * 1024 {
        bail!("signed command payload exceeds the protocol size limit");
    }
    let signature = hex::decode(&message.signature)
        .ok()
        .filter(|bytes| bytes.len() == 64)
        .context("signed command signature is not 64 bytes of hex")?;
    let digest = hex::encode(Sha256::digest(message.payload_json.as_bytes()));
    if digest != message.envelope.payload_sha256 {
        bail!("signed command payload does not match its hash");
    }
    device_envelope::verify_envelope(
        &message.envelope,
        &signature,
        message.payload_json.as_bytes(),
        trusted_public_key,
        expected_signing_device,
        &message.envelope.key_id,
        MessageKind::Command,
        now,
    )?;
    let payload: SignedCommandPayload = serde_json::from_str(&message.payload_json)
        .context("signed command payload is not valid JSON")?;
    validate_signed_command_payload(&payload)?;
    if payload.target_device != own_device_id {
        bail!("signed command is not addressed to this device");
    }
    Ok(payload)
}

/// Encode the on-disk channel file.
pub fn encode_channel_file(message: &SignedChannelMessage) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(message)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Decode and structurally check one channel file. This does not verify the
/// signature — verification needs the locally paired key.
pub fn decode_channel_file(bytes: &[u8]) -> Result<SignedChannelMessage> {
    if bytes.len() > MAX_CHANNEL_FILE_BYTES {
        bail!("signed command file exceeds the size limit");
    }
    let message: SignedChannelMessage = serde_json::from_slice(bytes)
        .context("signed command file is not valid JSON")?;
    if hex::decode(&message.signature).map(|s| s.len() == 64) != Ok(true) {
        bail!("signed command signature is not 64 bytes of hex");
    }
    if message.envelope.kind != MessageKind::Command {
        bail!("signed command file carries a non-command message");
    }
    Ok(message)
}

/// Publish one signed command to the channel in its own commit. The channel
/// configuration and its credentials are the manager's existing ones.
pub fn publish_signed_command(
    store: &SkillStore,
    url: &str,
    branch: &str,
    target_device_id: &str,
    message: &SignedChannelMessage,
) -> Result<String> {
    devices::validate_device_id(target_device_id)?;
    // The envelope's device_id is the signing manager; the addressed device
    // lives inside the signed payload. Both must line up with the request.
    let payload: SignedCommandPayload = serde_json::from_str(&message.payload_json)
        .context("signed command payload is not valid JSON")?;
    if payload.target_device != target_device_id {
        bail!("signed command does not target the requested device");
    }
    let (_tmp, dir) = devices::prepare_working_copy(url, branch)?;
    devices::ensure_protocol_file(&dir)?;
    let base = dir
        .join(devices::device_dir_name(target_device_id)?)
        .join("signed-commands");
    std::fs::create_dir_all(&base)?;
    let path = base.join(format!("{}.json", message.envelope.message_id));
    if path.exists() {
        bail!("a signed command with this id already exists on the channel");
    }
    std::fs::write(&path, encode_channel_file(message)?)?;
    let author = store
        .get_setting(super::devices::SETTING_DEVICE_LOCAL_NAME)
        .ok()
        .flatten()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "Skills Manager".to_string());
    devices::commit_and_push(&dir, url, branch, &author, "devices: publish signed command")
}

/// Read every signed command currently queued for one device. Bounds mirror
/// the recovery inventory: an unbounded queue is an error, not a surprise.
pub fn fetch_signed_commands(
    url: &str,
    branch: &str,
    target_device_id: &str,
) -> Result<Vec<SignedChannelMessage>> {
    devices::validate_device_id(target_device_id)?;
    let (_tmp, dir) = devices::prepare_working_copy(url, branch)?;
    let base = dir
        .join(devices::device_dir_name(target_device_id)?)
        .join("signed-commands");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut messages = Vec::new();
    for entry in std::fs::read_dir(&base)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            bail!("unexpected non-file entry in signed-commands");
        }
        let bytes = std::fs::read(&path)?;
        messages.push(decode_channel_file(&bytes).with_context(|| {
            format!(
                "signed command file {}: invalid",
                path.file_name().unwrap_or_default().to_string_lossy()
            )
        })?);
        if messages.len() > MAX_PENDING_COMMANDS_PER_DEVICE {
            bail!("signed command queue exceeds the per-device limit");
        }
    }
    messages.sort_by(|a, b| {
        a.envelope
            .issued_at
            .cmp(&b.envelope.issued_at)
            .then_with(|| a.envelope.message_id.cmp(&b.envelope.message_id))
    });
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        store: SkillStore,
        identity: DeviceIdentity,
        pubkey: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillStore::new(&dir.path().join("test.db")).unwrap();
        let identity = device_identity::ensure_identity(&store).unwrap();
        let pubkey = hex::decode(identity.public_key_hex()).unwrap();
        Fixture { _dir: dir, store, identity, pubkey }
    }

    fn payload(issued_by: &str) -> SignedCommandPayload {
        SignedCommandPayload {
            schema: SIGNED_COMMAND_SCHEMA,
            action: devices::ACTION_DEPLOY.to_string(),
            skill_url: Some("https://github.com/example/skills.git".to_string()),
            skill_branch: Some("main".to_string()),
            skill_subpath: Some("skills/demo".to_string()),
            skill_name: Some("demo-skill".to_string()),
            agent_key: "codex".to_string(),
            issued_by: issued_by.to_string(),
            issued_by_name: Some("workstation".to_string()),
            target_device: "dev-target".to_string(),
        }
    }

    #[test]
    fn signed_command_round_trips_through_verify() {
        let fx = fixture();
        let message = create_signed_command(
            &fx.identity, "dev-target", &payload(&fx.identity.device_id),
            1000, DEFAULT_COMMAND_TTL_SECS,
        ).unwrap();
        assert!(message.envelope.message_id.starts_with("cmd-"));
        let verified = verify_channel_command(
            &message, &fx.pubkey, &fx.identity.device_id, "dev-target", 2000,
        ).unwrap();
        assert_eq!(verified, payload(&fx.identity.device_id));
        assert_eq!(verified.agent_key, "codex");
    }

    #[test]
    fn signed_command_rejects_tampering() {
        let fx = fixture();
        let message = create_signed_command(
            &fx.identity, "dev-target", &payload(&fx.identity.device_id),
            1000, DEFAULT_COMMAND_TTL_SECS,
        ).unwrap();

        // One payload character flipped: the hash check must fail first.
        let mut tampered = message.clone();
        tampered.payload_json = tampered.payload_json.replace("deploy", "depl0y");
        assert!(verify_channel_command(
            &tampered, &fx.pubkey, &fx.identity.device_id, "dev-target", 2000,
        ).is_err());

        // A forged envelope timestamp cannot move the validity window.
        let mut shifted = message.clone();
        shifted.envelope.expires_at += 86_400;
        assert!(verify_channel_command(
            &shifted, &fx.pubkey, &fx.identity.device_id, "dev-target", 2000,
        ).is_err());

        // A foreign key is not trusted.
        let other = fixture();
        assert!(verify_channel_command(
            &message, &other.pubkey, &fx.identity.device_id, "dev-target", 2000,
        ).is_err());

        // A command addressed to another device is refused even when the
        // signature is valid.
        let mut retargeted = message.clone();
        retargeted.payload_json = retargeted.payload_json.replace(
            &format!(""target_device":"dev-target"",),
            ""target_device":"dev-other"",
        );
        assert!(verify_channel_command(
            &retargeted, &fx.pubkey, &fx.identity.device_id, "dev-other", 2000,
        ).is_err());
    }

    #[test]
    fn signed_command_validation_rejects_bad_fields() {
        let base = payload("dev-manager");
        let mut payload = base.clone();
        payload.action = "upgrade".to_string();
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base.clone();
        payload.action = devices::ACTION_UNDEPLOY.to_string();
        payload.skill_url = Some("https://example.com/x.git".to_string());
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base.clone();
        payload.action = devices::ACTION_UNDEPLOY.to_string();
        payload.skill_url = None;
        payload.skill_name = None;
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base.clone();
        payload.agent_key = "Main Agent".to_string();
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base.clone();
        payload.skill_url = Some("file:///etc".to_string());
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base.clone();
        payload.skill_name = Some("../escape".to_string());
        assert!(validate_signed_command_payload(&payload).is_err());

        let mut payload = base;
        payload.schema = 99;
        assert!(validate_signed_command_payload(&payload).is_err());
    }

    #[test]
    fn signed_command_ttl_is_bounded_by_the_command_limit() {
        let fx = fixture();
        let message = create_signed_command(
            &fx.identity, "dev-target", &payload(&fx.identity.device_id),
            1000, 10_000_000,
        ).unwrap();
        assert_eq!(
            message.envelope.expires_at - message.envelope.issued_at,
            device_envelope::max_lifetime(MessageKind::Command)
        );
        // Receipts stay on the short window even though commands span days.
        assert!(device_envelope::max_lifetime(MessageKind::Command)
            > device_envelope::max_lifetime(MessageKind::Receipt));
    }

    #[test]
    fn signed_command_publish_and_fetch_round_trip() {
        let fx = fixture();
        let remote = fx._dir.path().join("channel.git");
        assert!(std::process::Command::new("git")
            .args(["init", "--bare"])
            .arg(&remote)
            .output()
            .unwrap()
            .status
            .success());
        let url = remote.to_string_lossy().to_string();
        let branch = "skills-manager-devices";

        let message = create_signed_command(
            &fx.identity, "dev-target", &payload(&fx.identity.device_id),
            1000, DEFAULT_COMMAND_TTL_SECS,
        ).unwrap();
        publish_signed_command(&fx.store, &url, branch, "dev-target", &message).unwrap();

        // The same id again must not overwrite what is on the channel.
        assert!(publish_signed_command(&fx.store, &url, branch, "dev-target", &message).is_err());

        let fetched = fetch_signed_commands(&url, branch, "dev-target").unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0], message);

        // A fetched command still verifies end to end.
        verify_channel_command(
            &fetched[0], &fx.pubkey, &fx.identity.device_id, "dev-target", 2000,
        ).unwrap();

        // Another device's queue is empty.
        assert!(fetch_signed_commands(&url, branch, "dev-other").unwrap().is_empty());
    }
}

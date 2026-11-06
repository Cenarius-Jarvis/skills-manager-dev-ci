//! End-to-end simulation only. Every repository, database, key and agent
//! directory is temporary. No production executor is enabled by these tests.
use anyhow::{bail, Result};
use git2::{IndexAddOption, Repository, Signature};
use ring::{rand::SystemRandom, signature::{Ed25519KeyPair, KeyPair}};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use super::{
    central_repo, content_hash,
    device_envelope::{self, DeviceEnvelope, MessageKind},
    device_pairing, native_managed_executor,
    skill_store::{SkillRecord, SkillStore},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    envelope: DeviceEnvelope,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCommand {
    skill_id: String,
    source_hash: String,
    agent: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureReceipt {
    message_id: String,
    skill_id: String,
    result: String,
}

fn keypair() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}

fn signed(key: &Ed25519KeyPair, kind: MessageKind, key_id: &str, id: &str, payload: Vec<u8>) -> Wire {
    let envelope = DeviceEnvelope {
        version: 1, kind, message_id: id.into(), device_id: "fixture-device".into(),
        key_id: key_id.into(), issued_at: 1000, expires_at: 1100,
        payload_sha256: hex::encode(Sha256::digest(&payload)),
    };
    let signature = key.sign(&device_envelope::signing_bytes(&envelope).unwrap()).as_ref().to_vec();
    Wire { envelope, payload, signature }
}

fn commit_all(repo: &Repository, message: &str) -> Result<()> {
    let mut index = repo.index()?;
    index.add_all(["*"].iter(), IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repo.find_tree(tree_id)?;
    let sig = Signature::now("fixture", "fixture@example.invalid")?;
    let parent = repo.find_reference("refs/heads/main").ok()
        .and_then(|r| r.target()).map(|id| repo.find_commit(id)).transpose()?;
    let parents: Vec<_> = parent.iter().collect();
    repo.commit(Some("refs/heads/main"), &sig, &sig, message, &tree, &parents)?;
    repo.set_head("refs/heads/main")?;
    Ok(())
}

fn push(repo: &Repository, destination: &Path) -> Result<()> {
    let url = destination.to_str().ok_or_else(|| anyhow::anyhow!("non-UTF8 fixture path"))?;
    let mut remote = repo.remote_anonymous(url)?;
    remote.push(&["refs/heads/main:refs/heads/main"], None)?;
    Ok(())
}

fn write_wire(repo: &Repository, name: &str, wire: &Wire) -> Result<()> {
    std::fs::write(repo.workdir().ok_or_else(|| anyhow::anyhow!("fixture has no worktree"))?.join(name),
        serde_json::to_vec(wire)?)?;
    Ok(())
}

fn read_wire(repo: &Repository, name: &str) -> Result<Wire> {
    let path = repo.workdir().ok_or_else(|| anyhow::anyhow!("fixture has no worktree"))?.join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

struct ResetBase;
impl Drop for ResetBase {
    fn drop(&mut self) { central_repo::set_test_base_dir_override(None); }
}

/// Reproduces Git delivery and a managed deployment on a fake agent. The
/// receipt is a test fixture, not the as-yet-unimplemented production channel.
fn scenario(offline_receipt: bool) -> Result<()> {
    let _guard = central_repo::test_base_dir_lock();
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let remote_path = root.join("channel.git");
    let remote = Repository::init_bare(&remote_path)?;
    let controller = Repository::init(root.join("controller"))?;
    let device_base = root.join("fake-device-manager");
    let source = device_base.join("skills").join("sample");
    let agent_root = root.join("fake-agent");
    std::fs::create_dir_all(&source)?;
    std::fs::create_dir_all(&agent_root)?;
    std::fs::write(source.join("SKILL.md"), b"# fixture skill")?;
    central_repo::set_test_base_dir_override(Some(device_base.clone()));
    let _reset = ResetBase;
    let store = SkillStore::new(&device_base.join("skills-manager.db"))?;
    let source_hash = content_hash::hash_directory(&source)?;
    store.insert_skill(&SkillRecord {
        id: "fixture-skill".into(), name: "sample".into(), description: None,
        source_type: "git".into(), source_ref: Some("https://example.invalid/fixture.git".into()),
        source_ref_resolved: None, source_subpath: None, source_branch: None,
        source_revision: None, remote_revision: None,
        central_path: source.to_string_lossy().into_owned(),
        content_hash: Some(source_hash.clone()), enabled: true, created_at: 1, updated_at: 1,
        status: "ok".into(), update_status: "up_to_date".into(), last_checked_at: None,
        last_check_error: None,
    })?;

    let controller_key = keypair();
    let device_key = keypair();
    let payload = serde_json::to_vec(&FixtureCommand {
        skill_id: "fixture-skill".into(), source_hash: source_hash.clone(), agent: "codex".into(),
    })?;
    let request = signed(&controller_key, MessageKind::Command, "controller-key", "command-1", payload);
    write_wire(&controller, "command.json", &request)?;
    commit_all(&controller, "fixture request")?;
    push(&controller, &remote_path)?;
    remote.set_head("refs/heads/main")?;

    let device = Repository::clone(remote_path.to_str().unwrap(), root.join("device-work"))?;
    let received = read_wire(&device, "command.json")?;
    let mut device_trust = Connection::open(root.join("device-trust.db"))?;
    device_pairing::initialize_trust_store(&device_trust)?;
    device_pairing::register_approved_key(&device_trust, "fixture-device", "controller-key",
        MessageKind::Command, controller_key.public_key().as_ref())?;

    // Tampering must not claim or deploy anything.
    let mut changed = received.payload.clone();
    changed[0] ^= 1;
    assert!(device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &changed, "fixture-device", MessageKind::Command, 1050).is_err());
    assert!(!agent_root.join("sample").exists());

    let claimed = device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1050)?
        .ok_or_else(|| anyhow::anyhow!("fixture request was unexpectedly replayed"))?;
    let prepared = device_pairing::prepare_claimed_command(&mut device_trust, claimed, 1051)?;
    let action: FixtureCommand = serde_json::from_slice(prepared.payload())?;
    if action.skill_id != "fixture-skill" || action.agent != "codex" || action.source_hash != source_hash {
        bail!("fixture action does not match the independently approved test target");
    }
    // The root comes from the fixture's local setup, not from the Git payload.
    let target = native_managed_executor::deploy_new_slot(&store, &action.skill_id, &action.agent, &agent_root)?;
    assert_eq!(std::fs::read(target.join("SKILL.md"))?, b"# fixture skill");
    assert_eq!(store.get_targets_for_skill("fixture-skill")?.len(), 1);
    assert!(device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1052)?.is_none());

    let receipt = signed(&device_key, MessageKind::Receipt, "device-key", "receipt-1",
        serde_json::to_vec(&FixtureReceipt { message_id: "command-1".into(),
            skill_id: action.skill_id, result: "success".into() })?);
    write_wire(&device, "receipt.json", &receipt)?;
    commit_all(&device, "fixture receipt")?;
    if offline_receipt {
        assert!(push(&device, &root.join("missing-channel.git")).is_err());
        // A failed push does not erase the local deployment or fabricate a
        // remotely visible success. Recovery must reconcile rather than replay.
        let observer = Repository::clone(remote_path.to_str().unwrap(), root.join("offline-observer"))?;
        assert!(!observer.workdir().unwrap().join("receipt.json").exists());
        assert_eq!(store.get_targets_for_skill("fixture-skill")?.len(), 1);
        return Ok(());
    }
    push(&device, &remote_path)?;
    let observer = Repository::clone(remote_path.to_str().unwrap(), root.join("controller-observer"))?;
    let received_receipt = read_wire(&observer, "receipt.json")?;
    let mut controller_trust = Connection::open(root.join("controller-trust.db"))?;
    device_pairing::initialize_trust_store(&controller_trust)?;
    device_pairing::register_approved_key(&controller_trust, "fixture-device", "device-key",
        MessageKind::Receipt, device_key.public_key().as_ref())?;
    let accepted = device_pairing::verify_and_claim_paired(&mut controller_trust,
        &received_receipt.envelope, &received_receipt.signature, &received_receipt.payload,
        "fixture-device", MessageKind::Receipt, 1053)?
        .ok_or_else(|| anyhow::anyhow!("receipt was unexpectedly replayed"))?;
    let result: FixtureReceipt = serde_json::from_slice(accepted.payload())?;
    assert_eq!(result.message_id, "command-1");
    assert_eq!(result.result, "success");
    Ok(())
}

#[test]
fn two_device_simulation_signed_git_round_trip() -> Result<()> { scenario(false) }

#[test]
fn two_device_simulation_offline_receipt_preserves_uncertainty() -> Result<()> { scenario(true) }

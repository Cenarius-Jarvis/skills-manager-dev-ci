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
    device_pairing, installer, native_managed_executor,
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedInstallCommand {
    skill_id: String,
    agent: String,
    source_commit: String,
    source_hash: String,
}

// Fixture-only preflight. Production installation still needs stronger
// no-clobber, link/race, provenance, metadata and crash-recovery protections.
fn checked_fixture_source(repo: &Repository, command: &PinnedInstallCommand) -> Result<std::path::PathBuf> {
    let actual = repo.head()?.peel_to_commit()?.id().to_string();
    if actual != command.source_commit { bail!("fixture source commit differs from signed command"); }
    let source = repo.workdir().ok_or_else(|| anyhow::anyhow!("fixture worktree missing"))?.join("sample");
    if content_hash::hash_directory(&source)? != command.source_hash {
        bail!("fixture source content differs from signed command");
    }
    Ok(source)
}

#[test]
fn two_device_simulation_installs_pinned_skill_and_reports_receipt() -> Result<()> {
    let _guard = central_repo::test_base_dir_lock();
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();

    // A separate synthetic skill repository has a single committed skill.
    let source_remote_path = root.join("skill-source.git");
    let source_remote = Repository::init_bare(&source_remote_path)?;
    let source_author = Repository::init(root.join("skill-author"))?;
    let source_skill = source_author.workdir().unwrap().join("sample");
    std::fs::create_dir_all(&source_skill)?;
    std::fs::write(source_skill.join("SKILL.md"), b"# fixture install")?;
    let expected_hash = content_hash::hash_directory(&source_skill)?;
    commit_all(&source_author, "fixture skill v1")?;
    let expected_commit = source_author.head()?.peel_to_commit()?.id().to_string();
    push(&source_author, &source_remote_path)?;
    source_remote.set_head("refs/heads/main")?;

    let channel_path = root.join("channel.git");
    let channel = Repository::init_bare(&channel_path)?;
    let controller = Repository::init(root.join("controller"))?;
    let controller_key = keypair();
    let device_key = keypair();
    let command = PinnedInstallCommand {
        skill_id: "fixture-new-skill".into(), agent: "codex".into(),
        source_commit: expected_commit, source_hash: expected_hash,
    };
    let request = signed(&controller_key, MessageKind::Command, "controller-key",
        "install-1", serde_json::to_vec(&command)?);
    write_wire(&controller, "command.json", &request)?;
    commit_all(&controller, "fixture install request")?;
    push(&controller, &channel_path)?;
    channel.set_head("refs/heads/main")?;

    let device = Repository::clone(channel_path.to_str().unwrap(), root.join("device-work"))?;
    let received = read_wire(&device, "command.json")?;
    let mut device_trust = Connection::open(root.join("device-trust.db"))?;
    device_pairing::initialize_trust_store(&device_trust)?;
    device_pairing::register_approved_key(&device_trust, "fixture-device", "controller-key",
        MessageKind::Command, controller_key.public_key().as_ref())?;
    let claim = device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1050)?
        .ok_or_else(|| anyhow::anyhow!("unexpected fixture replay"))?;
    let prepared = device_pairing::prepare_claimed_command(&mut device_trust, claim, 1051)?;
    let action: PinnedInstallCommand = serde_json::from_slice(prepared.payload())?;
    if action.skill_id != "fixture-new-skill" || action.agent != "codex" {
        bail!("fixture target not locally approved");
    }

    let fetched = Repository::clone(source_remote_path.to_str().unwrap(), root.join("source-work"))?;
    // Refuse a modified checkout and a wrong immutable commit before installing.
    let fetched_skill = fetched.workdir().unwrap().join("sample");
    std::fs::write(fetched_skill.join("SKILL.md"), b"tampered")?;
    assert!(checked_fixture_source(&fetched, &action).is_err());
    std::fs::write(fetched_skill.join("SKILL.md"), b"# fixture install")?;
    let mut wrong_commit = action.source_commit.clone();
    let replacement = if wrong_commit.starts_with('0') { "1" } else { "0" };
    wrong_commit.replace_range(0..1, replacement);
    let wrong = PinnedInstallCommand { skill_id: action.skill_id.clone(), agent: action.agent.clone(),
        source_commit: wrong_commit, source_hash: action.source_hash.clone() };
    assert!(checked_fixture_source(&fetched, &wrong).is_err());
    let checked_source = checked_fixture_source(&fetched, &action)?;

    let device_base = root.join("fake-device-manager");
    let agent_root = root.join("fake-agent");
    std::fs::create_dir_all(device_base.join("skills"))?;
    std::fs::create_dir_all(&agent_root)?;
    central_repo::set_test_base_dir_override(Some(device_base.clone()));
    let _reset = ResetBase;
    let store = SkillStore::new(&device_base.join("skills-manager.db"))?;
    let destination = device_base.join("skills").join("sample");
    assert!(!destination.exists());
    let installed = installer::install_from_local_to_destination(&checked_source, Some("sample"), &destination)?;
    assert_eq!(installed.content_hash, action.source_hash);
    store.insert_skill(&SkillRecord {
        id: action.skill_id.clone(), name: installed.name, description: installed.description,
        source_type: "git".into(), source_ref: Some("https://example.invalid/fixture.git".into()),
        source_ref_resolved: None, source_subpath: Some("sample".into()), source_branch: None,
        source_revision: Some(action.source_commit), remote_revision: None,
        central_path: installed.central_path.to_string_lossy().into_owned(),
        content_hash: Some(installed.content_hash), enabled: true, created_at: 1, updated_at: 1,
        status: "ok".into(), update_status: "up_to_date".into(), last_checked_at: None,
        last_check_error: None,
    })?;
    let target = native_managed_executor::deploy_new_slot(&store, &action.skill_id, &action.agent, &agent_root)?;
    assert_eq!(std::fs::read(target.join("SKILL.md"))?, b"# fixture install");
    assert_eq!(store.get_targets_for_skill("fixture-new-skill")?.len(), 1);
    assert!(device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1052)?.is_none());

    let receipt = signed(&device_key, MessageKind::Receipt, "device-key", "receipt-install-1",
        serde_json::to_vec(&FixtureReceipt { message_id: "install-1".into(),
            skill_id: action.skill_id, result: "success".into() })?);
    write_wire(&device, "receipt.json", &receipt)?;
    commit_all(&device, "fixture install receipt")?;
    push(&device, &channel_path)?;
    let observer = Repository::clone(channel_path.to_str().unwrap(), root.join("observer"))?;
    let received_receipt = read_wire(&observer, "receipt.json")?;
    let mut controller_trust = Connection::open(root.join("controller-trust.db"))?;
    device_pairing::initialize_trust_store(&controller_trust)?;
    device_pairing::register_approved_key(&controller_trust, "fixture-device", "device-key",
        MessageKind::Receipt, device_key.public_key().as_ref())?;
    let verified = device_pairing::verify_and_claim_paired(&mut controller_trust,
        &received_receipt.envelope, &received_receipt.signature, &received_receipt.payload,
        "fixture-device", MessageKind::Receipt, 1053)?
        .ok_or_else(|| anyhow::anyhow!("unexpected receipt replay"))?;
    let receipt: FixtureReceipt = serde_json::from_slice(verified.payload())?;
    assert_eq!(receipt.message_id, "install-1");
    assert_eq!(receipt.result, "success");
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedUpdateCommand {
    skill_id: String,
    agent: String,
    source_commit: String,
    source_hash: String,
    expected_old_hash: String,
}

/// Fixture-only preflight. It is not safe against external filesystem races
/// and is deliberately not connected to production remote execution.
fn checked_fixture_update(current: &Path, candidate: &Path, old_hash: &str, new_hash: &str) -> Result<()> {
    if content_hash::hash_directory(current)? != old_hash {
        bail!("fixture installed skill has local modifications");
    }
    if content_hash::hash_directory(candidate)? != new_hash {
        bail!("fixture update content differs from signed hash");
    }
    let old: std::collections::HashSet<_> = content_hash::list_content_files_strict(current)?
        .into_iter().map(|entry| entry.relative_path).collect();
    let new: std::collections::HashSet<_> = content_hash::list_content_files_strict(candidate)?
        .into_iter().map(|entry| entry.relative_path).collect();
    if !old.is_subset(&new) { bail!("fixture update would remove existing files"); }
    Ok(())
}

#[test]
fn two_device_simulation_updates_pinned_skill_and_protects_local_edits() -> Result<()> {
    use crate::commands::skills::{resync_copy_targets, staged_path_for, swap_skill_directory};
    use super::repo_lock::RepoLock;
    let _guard = central_repo::test_base_dir_lock();
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let source_remote_path = root.join("skill-source.git");
    let source_remote = Repository::init_bare(&source_remote_path)?;
    let source_author = Repository::init(root.join("skill-author"))?;
    let source_skill = source_author.workdir().unwrap().join("sample");
    std::fs::create_dir_all(&source_skill)?;
    std::fs::write(source_skill.join("SKILL.md"), b"# fixture version 1")?;
    std::fs::write(source_skill.join("keep.md"), b"keep")?;
    let old_hash = content_hash::hash_directory(&source_skill)?;
    commit_all(&source_author, "fixture skill v1")?;
    let old_commit = source_author.head()?.peel_to_commit()?.id().to_string();
    push(&source_author, &source_remote_path)?;
    source_remote.set_head("refs/heads/main")?;

    let device_base = root.join("fake-device-manager");
    let current = device_base.join("skills").join("sample");
    let agent_root = root.join("fake-agent");
    std::fs::create_dir_all(device_base.join("skills"))?;
    std::fs::create_dir_all(&agent_root)?;
    central_repo::set_test_base_dir_override(Some(device_base.clone()));
    let _reset = ResetBase;
    let store = SkillStore::new(&device_base.join("skills-manager.db"))?;
    assert!(!current.exists());
    let installed = installer::install_from_local_to_destination(&source_skill, Some("sample"), &current)?;
    assert_eq!(installed.content_hash, old_hash);
    store.insert_skill(&SkillRecord {
        id: "fixture-existing".into(), name: installed.name, description: installed.description,
        source_type: "git".into(), source_ref: Some("https://example.invalid/fixture.git".into()),
        source_ref_resolved: None, source_subpath: Some("sample".into()), source_branch: Some("main".into()),
        source_revision: Some(old_commit), remote_revision: None,
        central_path: installed.central_path.to_string_lossy().into_owned(),
        content_hash: Some(installed.content_hash), enabled: true, created_at: 1, updated_at: 1,
        status: "ok".into(), update_status: "up_to_date".into(), last_checked_at: None,
        last_check_error: None,
    })?;
    let agent_target = native_managed_executor::deploy_new_slot(&store, "fixture-existing", "codex", &agent_root)?;
    assert_eq!(std::fs::read(agent_target.join("SKILL.md"))?, b"# fixture version 1");

    // The author publishes a new immutable commit, then the controller signs
    // both its commit ID and the expected current and replacement hashes.
    std::fs::write(source_skill.join("SKILL.md"), b"# fixture version 2")?;
    let new_hash = content_hash::hash_directory(&source_skill)?;
    commit_all(&source_author, "fixture skill v2")?;
    let new_commit = source_author.head()?.peel_to_commit()?.id().to_string();
    push(&source_author, &source_remote_path)?;
    let controller_key = keypair();
    let device_key = keypair();
    let update = PinnedUpdateCommand { skill_id: "fixture-existing".into(), agent: "codex".into(),
        source_commit: new_commit, source_hash: new_hash, expected_old_hash: old_hash.clone() };
    let request = signed(&controller_key, MessageKind::Command, "controller-key",
        "update-1", serde_json::to_vec(&update)?);
    let channel_path = root.join("channel.git");
    let channel = Repository::init_bare(&channel_path)?;
    let controller = Repository::init(root.join("controller"))?;
    write_wire(&controller, "command.json", &request)?;
    commit_all(&controller, "fixture update request")?;
    push(&controller, &channel_path)?;
    channel.set_head("refs/heads/main")?;

    let device = Repository::clone(channel_path.to_str().unwrap(), root.join("device-work"))?;
    let received = read_wire(&device, "command.json")?;
    let mut device_trust = Connection::open(root.join("device-trust.db"))?;
    device_pairing::initialize_trust_store(&device_trust)?;
    device_pairing::register_approved_key(&device_trust, "fixture-device", "controller-key",
        MessageKind::Command, controller_key.public_key().as_ref())?;
    let claimed = device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1050)?
        .ok_or_else(|| anyhow::anyhow!("fixture command replayed"))?;
    let prepared = device_pairing::prepare_claimed_command(&mut device_trust, claimed, 1051)?;
    let action: PinnedUpdateCommand = serde_json::from_slice(prepared.payload())?;
    if action.skill_id != "fixture-existing" || action.agent != "codex" {
        bail!("fixture target not locally approved");
    }
    let fetched = Repository::clone(source_remote_path.to_str().unwrap(), root.join("source-work"))?;
    let pin = PinnedInstallCommand { skill_id: action.skill_id.clone(), agent: action.agent.clone(),
        source_commit: action.source_commit.clone(), source_hash: action.source_hash.clone() };
    let candidate = checked_fixture_source(&fetched, &pin)?;

    // Refuse local modifications without changing or deleting them.
    std::fs::write(current.join("SKILL.md"), b"# local user edit")?;
    assert!(checked_fixture_update(&current, &candidate, &action.expected_old_hash, &action.source_hash).is_err());
    assert_eq!(std::fs::read(current.join("SKILL.md"))?, b"# local user edit");
    std::fs::write(current.join("SKILL.md"), b"# fixture version 1")?;
    assert_eq!(content_hash::hash_directory(&current)?, old_hash);

    // Refuse an update that would remove a file. This candidate is a local
    // test fixture; no actual source repository or user data is changed.
    let missing_candidate = root.join("candidate-with-removal");
    std::fs::create_dir_all(&missing_candidate)?;
    std::fs::write(missing_candidate.join("SKILL.md"), b"# fixture version 2")?;
    let missing_hash = content_hash::hash_directory(&missing_candidate)?;
    assert!(checked_fixture_update(&current, &missing_candidate, &action.expected_old_hash, &missing_hash).is_err());
    assert_eq!(std::fs::read(current.join("keep.md"))?, b"keep");

    // Isolated fixture uses the existing stage/swap and copy-resync primitives.
    // This does not establish production safety against filesystem races.
    let _lock = RepoLock::acquire_foreground("fixture pinned update")?;
    checked_fixture_update(&current, &candidate, &action.expected_old_hash, &action.source_hash)?;
    let stage = staged_path_for(current.to_str().unwrap());
    assert!(!stage.exists());
    let staged = installer::install_from_local_to_destination(&candidate, Some("sample"), &stage)?;
    assert_eq!(staged.content_hash, action.source_hash);
    swap_skill_directory(&stage, &current)?;
    store.update_skill_source_metadata(&action.skill_id, Some("https://example.invalid/fixture.git"),
        Some("sample"), Some("main"), Some(&action.source_commit))?;
    store.update_skill_after_install(&action.skill_id, "sample", staged.description.as_deref(),
        Some(&action.source_commit), Some(&action.source_commit), Some(&staged.content_hash), "up_to_date")?;
    resync_copy_targets(&store, &action.skill_id)?;
    super::sync_metadata::write_all_from_db_unlocked(&store)?;
    assert_eq!(std::fs::read(current.join("SKILL.md"))?, b"# fixture version 2");
    assert_eq!(std::fs::read(current.join("keep.md"))?, b"keep");
    assert_eq!(std::fs::read(agent_target.join("SKILL.md"))?, b"# fixture version 2");
    assert_eq!(store.get_targets_for_skill("fixture-existing")?.len(), 1);
    drop(_lock);

    assert!(device_pairing::verify_and_claim_paired(&mut device_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1052)?.is_none());
    let receipt = signed(&device_key, MessageKind::Receipt, "device-key", "receipt-update-1",
        serde_json::to_vec(&FixtureReceipt { message_id: "update-1".into(),
            skill_id: action.skill_id, result: "success".into() })?);
    write_wire(&device, "receipt.json", &receipt)?;
    commit_all(&device, "fixture update receipt")?;
    push(&device, &channel_path)?;
    let observer = Repository::clone(channel_path.to_str().unwrap(), root.join("observer"))?;
    let received_receipt = read_wire(&observer, "receipt.json")?;
    let mut controller_trust = Connection::open(root.join("controller-trust.db"))?;
    device_pairing::initialize_trust_store(&controller_trust)?;
    device_pairing::register_approved_key(&controller_trust, "fixture-device", "device-key",
        MessageKind::Receipt, device_key.public_key().as_ref())?;
    let verified = device_pairing::verify_and_claim_paired(&mut controller_trust,
        &received_receipt.envelope, &received_receipt.signature, &received_receipt.payload,
        "fixture-device", MessageKind::Receipt, 1053)?
        .ok_or_else(|| anyhow::anyhow!("unexpected receipt replay"))?;
    let result: FixtureReceipt = serde_json::from_slice(verified.payload())?;
    assert_eq!(result.message_id, "update-1");
    assert_eq!(result.result, "success");
    Ok(())
}


/// A child process used only in this test suite. Both exits intentionally skip
/// destructors to model abrupt termination. It operates under a verified
/// temporary fixture directory and cannot address user-chosen agent paths.
#[test]
fn two_device_simulation_crash_worker() {
    let Some(root) = std::env::var_os("SM_TEST_CRASH_ROOT") else { return; };
    let root = std::path::PathBuf::from(root);
    let temp = std::env::temp_dir().canonicalize().unwrap();
    let canonical = root.canonicalize().unwrap();
    assert_eq!(canonical.parent(), Some(temp.as_path()));
    assert!(canonical.file_name().unwrap().to_string_lossy().starts_with("skills-two-device-crash-"));
    let phase = std::env::var("SM_TEST_CRASH_PHASE").unwrap();
    if phase == "before" { std::process::exit(23); }
    assert_eq!(phase, "after");
    let _guard = central_repo::test_base_dir_lock();
    let base = canonical.join("fake-device-manager");
    central_repo::set_test_base_dir_override(Some(base.clone()));
    let store = SkillStore::new(&base.join("skills-manager.db")).unwrap();
    let target = native_managed_executor::deploy_new_slot(
        &store, "fixture-skill", "codex", &canonical.join("fake-agent")
    ).unwrap();
    assert_eq!(std::fs::read(target.join("SKILL.md")).unwrap(), b"# fixture crash");
    // Abrupt exit after deployment, before generating a receipt.
    std::process::exit(23);
}

fn crash_scenario(phase: &str) -> Result<()> {
    let tmp = tempfile::Builder::new().prefix("skills-two-device-crash-").tempdir()?;
    let root = tmp.path();
    let channel_path = root.join("channel.git");
    let channel = Repository::init_bare(&channel_path)?;
    let controller = Repository::init(root.join("controller"))?;
    let key = keypair();
    let request = signed(&key, MessageKind::Command, "controller-key", "crash-command",
        b"fixture command".to_vec());
    write_wire(&controller, "command.json", &request)?;
    commit_all(&controller, "fixture crash request")?;
    push(&controller, &channel_path)?;
    channel.set_head("refs/heads/main")?;

    let device = Repository::clone(channel_path.to_str().unwrap(), root.join("device-work"))?;
    let received = read_wire(&device, "command.json")?;
    let db_path = root.join("device-trust.db");
    let mut trust = Connection::open(&db_path)?;
    device_pairing::initialize_trust_store(&trust)?;
    device_pairing::register_approved_key(&trust, "fixture-device", "controller-key",
        MessageKind::Command, key.public_key().as_ref())?;
    let claimed = device_pairing::verify_and_claim_paired(&mut trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1050)?
        .ok_or_else(|| anyhow::anyhow!("unexpected fixture replay"))?;
    let prepared = device_pairing::prepare_claimed_command(&mut trust, claimed, 1051)?;
    assert_eq!(prepared.payload(), b"fixture command");
    drop(prepared);
    drop(trust);

    let base = root.join("fake-device-manager");
    let source = base.join("skills").join("sample");
    let agent = root.join("fake-agent");
    std::fs::create_dir_all(&source)?;
    std::fs::create_dir_all(&agent)?;
    std::fs::write(source.join("SKILL.md"), b"# fixture crash")?;
    let store = SkillStore::new(&base.join("skills-manager.db"))?;
    let hash = content_hash::hash_directory(&source)?;
    store.insert_skill(&SkillRecord {
        id: "fixture-skill".into(), name: "sample".into(), description: None,
        source_type: "git".into(), source_ref: Some("https://example.invalid/fixture.git".into()),
        source_ref_resolved: None, source_subpath: None, source_branch: None,
        source_revision: None, remote_revision: None,
        central_path: source.to_string_lossy().into_owned(), content_hash: Some(hash),
        enabled: true, created_at: 1, updated_at: 1, status: "ok".into(),
        update_status: "up_to_date".into(), last_checked_at: None, last_check_error: None,
    })?;
    drop(store);

    let child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "core::two_device_simulation::two_device_simulation_crash_worker", "--nocapture"])
        .env("SM_TEST_CRASH_ROOT", root)
        .env("SM_TEST_CRASH_PHASE", phase)
        .output()?;
    assert_eq!(child.status.code(), Some(23), "crash worker did not reach intended exit; stdout: {} ; stderr: {}", String::from_utf8_lossy(&child.stdout), String::from_utf8_lossy(&child.stderr));

    // On restart a previously prepared command cannot be blindly replayed,
    // and no remote receipt means the controller must treat outcome as unknown.
    let mut reopened_trust = Connection::open(&db_path)?;
    assert!(device_pairing::verify_and_claim_paired(&mut reopened_trust, &received.envelope,
        &received.signature, &received.payload, "fixture-device", MessageKind::Command, 1052)?.is_none());
    let observer = Repository::clone(channel_path.to_str().unwrap(), root.join("controller-observer"))?;
    assert!(!observer.workdir().unwrap().join("receipt.json").exists());
    let reopened_store = SkillStore::new(&base.join("skills-manager.db"))?;
    let rows = reopened_store.get_targets_for_skill("fixture-skill")?;
    if phase == "after" {
        assert_eq!(rows.len(), 1);
        assert_eq!(std::fs::read(agent.join("sample").join("SKILL.md"))?, b"# fixture crash");
    } else {
        assert!(rows.is_empty());
        assert!(!agent.join("sample").exists());
    }
    Ok(())
}

#[test]
fn two_device_simulation_crash_before_deploy_is_not_replayed() -> Result<()> {
    crash_scenario("before")
}

#[test]
fn two_device_simulation_crash_after_deploy_is_not_replayed() -> Result<()> {
    crash_scenario("after")
}

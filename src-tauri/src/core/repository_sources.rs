//! Independent read-only repository sources. This module does not install
//! skills, write the central library, deploy to an agent, or push to a remote.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use super::devices;
use super::git_command::git_command;
use super::git_credentials::credential_env_for_url;
use super::skill_store::SkillStore;

const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: usize = 20;
const CLONE_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySource {
    pub id: String,
    pub name: String,
    pub device_id: Option<String>,
    /// User-supplied URL, accepted only after rejecting embedded credentials.
    pub url: String,
    pub branch: String,
    pub skills_root: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositorySkill {
    pub name: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub source_id: String,
    pub head_commit: String,
    pub fetched_at: i64,
    /// Monotonic ordering by the start of a refresh, to stop a slower older
    /// refresh overwriting the result of a later successful refresh.
    pub observed_at: i64,
    pub skills: Vec<RepositorySkill>,
}

fn valid_host(host: &str) -> bool {
    !host.is_empty() && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

/// Do not accept HTTPS userinfo, query strings, fragments, control characters,
/// local paths, unknown transports or arbitrary credential-bearing SSH forms.
pub fn validate_source_url(url: &str) -> Result<()> {
    if url.is_empty() || url.len() > 2048 || url.trim() != url
        || url.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '?' | '#' | '\\'))
    { bail!("invalid repository URL"); }
    let (host, repo_path) = if let Some(rest) = url.strip_prefix("https://") {
        let (host, path) = rest.split_once('/').context("repository URL needs a path")?;
        if host.contains('@') { bail!("credentials in repository URLs are not allowed"); }
        (host, path)
    } else if let Some(rest) = url.strip_prefix("ssh://git@") {
        rest.split_once('/').context("SSH repository URL needs a path")?
    } else if let Some(rest) = url.strip_prefix("git@") {
        rest.split_once(':').context("SSH repository URL needs a host and path")?
    } else {
        bail!("only HTTPS or git SSH repository URLs are allowed");
    };
    if !valid_host(host) || repo_path.is_empty() || repo_path.starts_with('-')
        || repo_path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || repo_path.contains('@') || repo_path.contains(':')
    { bail!("invalid repository URL"); }
    Ok(())
}

pub fn normalize_skills_root(value: &str) -> Result<String> {
    if value.is_empty() || value == "." { return Ok(String::new()); }
    if value.len() > 1024 || value.starts_with('/') || value.contains('\\')
        || value.contains(':') || value.chars().any(char::is_control)
        || value.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.eq_ignore_ascii_case(".git"))
    { bail!("invalid skills root: use a relative repository path"); }
    Ok(value.to_string())
}

pub fn add_source(store: &SkillStore, name: &str, device_id: Option<String>, url: &str, branch: &str, skills_root: &str) -> Result<RepositorySource> {
    let name = name.trim();
    if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
        bail!("invalid repository source name");
    }
    if let Some(id) = device_id.as_deref() { devices::validate_device_id(id)?; }
    validate_source_url(url)?;
    devices::validate_branch_name(branch)?;
    let source = RepositorySource {
        id: format!("repo-{}", uuid::Uuid::new_v4().simple()),
        name: name.to_string(), device_id, url: url.to_string(),
        branch: branch.to_string(), skills_root: normalize_skills_root(skills_root)?,
        created_at: chrono::Utc::now().timestamp(),
    };
    store.insert_repository_source(&source)?;
    Ok(source)
}

fn clone_bare(url: &str, branch: &str, path: &Path) -> Result<()> {
    let mut cmd = git_command();
    cmd.args(["clone", "--quiet", "--bare", "--single-branch", "--depth", "1", "--branch", branch, "--"])
        .arg(url).arg(path)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=15")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    for (key, value) in credential_env_for_url(url) { cmd.env(key, value); }
    let mut child = cmd.spawn().context("could not start Git")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("could not read Git status")? {
            if status.success() { return Ok(()); }
            // Do not echo URL, stderr, token, helper command or repository name.
            bail!("repository fetch failed; check access and branch");
        }
        if started.elapsed() >= CLONE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            bail!("repository fetch timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn scan_tree(repo: &git2::Repository, tree: &git2::Tree<'_>, path: &str,
             out: &mut Vec<RepositorySkill>, visited: &mut usize, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH { bail!("repository inventory exceeded the depth limit"); }
    let mut has_manifest = false;
    for entry in tree.iter() {
        *visited += 1;
        if *visited > MAX_ENTRIES { bail!("repository inventory exceeded the entry limit"); }
        let name = entry.name().context("repository contains a non-UTF-8 path")?;
        if name == "." || name == ".." || name.contains('/') || name.contains('\\') || name.chars().any(char::is_control) {
            bail!("repository contains an unsafe tree entry");
        }
        if entry.filemode() == 0o120000 || entry.kind() == Some(git2::ObjectType::Commit) {
            bail!("repository inventory contains a link or submodule; cannot publish an incomplete snapshot");
        }
        if name == "SKILL.md" {
            if entry.kind() != Some(git2::ObjectType::Blob) { bail!("SKILL.md is not a regular file"); }
            has_manifest = true;
        }
    }
    if has_manifest {
        let name = path.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or(".");
        out.push(RepositorySkill { name: name.to_string(), relative_path: if path.is_empty() { ".".into() } else { path.to_string() } });
    }
    for entry in tree.iter() {
        let name = entry.name().context("repository contains a non-UTF-8 path")?;
        if name.eq_ignore_ascii_case(".git") || name == ".hub" { continue; }
        if entry.kind() == Some(git2::ObjectType::Tree) {
            let child = repo.find_tree(entry.id())?;
            let child_path = if path.is_empty() { name.to_string() } else { format!("{path}/{name}") };
            scan_tree(repo, &child, &child_path, out, visited, depth + 1)?;
        }
    }
    Ok(())
}

fn read_snapshot(url: &str, source: &RepositorySource, observed_at: i64) -> Result<RepositorySnapshot> {
    let tmp = tempfile::tempdir().context("could not create temporary repository")?;
    let path = tmp.path().join("repository.git");
    clone_bare(url, &source.branch, &path)?;
    let repo = git2::Repository::open_bare(path).context("could not read fetched repository")?;
    let head = repo.head()?.peel_to_commit()?;
    let commit = head.id().to_string();
    let root = head.tree()?;
    let skills_tree = if source.skills_root.is_empty() {
        root
    } else {
        let entry = root.get_path(Path::new(&source.skills_root))
            .context("configured skills root does not exist")?;
        if entry.kind() != Some(git2::ObjectType::Tree) { bail!("configured skills root is not a directory"); }
        repo.find_tree(entry.id())?
    };
    let mut skills = Vec::new();
    let mut visited = 0;
    scan_tree(&repo, &skills_tree, &source.skills_root, &mut skills, &mut visited, 0)?;
    skills.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(RepositorySnapshot { source_id: source.id.clone(), head_commit: commit,
        fetched_at: chrono::Utc::now().timestamp(), observed_at, skills })
}

/// A failed/incomplete fetch returns an error and leaves the last verified
/// snapshot unchanged. This operation does not publish anything.
pub fn refresh_source(store: &SkillStore, source_id: &str) -> Result<RepositorySnapshot> {
    let source = store.get_repository_source(source_id)?.context("repository source not found")?;
    validate_source_url(&source.url)?;
    devices::validate_branch_name(&source.branch)?;
    let root = normalize_skills_root(&source.skills_root)?;
    if root != source.skills_root { bail!("invalid stored skills root"); }
    fetch_and_save(store, &source, &source.url)
}

fn fetch_and_save(store: &SkillStore, source: &RepositorySource, url: &str) -> Result<RepositorySnapshot> {
    let start = store.reserve_repository_refresh(&source.id)?;
    let snapshot = read_snapshot(url, source, start)?;
    store.save_repository_snapshot(&snapshot)?;
    store.get_repository_snapshot(&source.id)?.context("source removed during refresh")
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn repository_sources_sequence_prevents_out_of_order_and_preserves_old_cache() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = SkillStore::new(&tmp.path().join("state.db"))?;
        let source = RepositorySource {
            id: "repo-a".into(), name: "A".into(), device_id: None,
            url: "https://github.com/example/fixture.git".into(), branch: "main".into(),
            skills_root: "skills".into(), created_at: 1,
        };
        store.insert_repository_source(&source)?;
        let snapshot = |seq: i64, head: &str| RepositorySnapshot {
            source_id: source.id.clone(), head_commit: head.into(),
            fetched_at: 1, observed_at: seq, skills: vec![],
        };
        let old_wall_clock = 1_800_000_000_000_000_000i64;
        store.save_repository_snapshot(&snapshot(old_wall_clock, "legacy"))?;
        let first = store.reserve_repository_refresh(&source.id)?;
        let second = store.reserve_repository_refresh(&source.id)?;
        assert!(first > old_wall_clock && second > first);
        store.save_repository_snapshot(&snapshot(second, "newer"))?;
        store.save_repository_snapshot(&snapshot(first, "older"))?;
        store.save_repository_snapshot(&snapshot(second, "equal"))?;
        assert_eq!(store.get_repository_snapshot(&source.id)?.unwrap().head_commit, "newer");
        assert!(store.delete_repository_source(&source.id)?);
        assert!(store.reserve_repository_refresh(&source.id).is_err());
        Ok(())
    }

    fn write_fake_repository(path: &Path, names: &[&str], symlink: bool) -> Result<String> {
        let repo = if path.exists() { git2::Repository::open_bare(path)? }
            else { git2::Repository::init_bare(path)? };
        let blob = repo.blob(b"fixture contents")?;
        let mut skills = repo.treebuilder(None)?;
        for name in names {
            let mut skill = repo.treebuilder(None)?;
            skill.insert("SKILL.md", blob, 0o100644)?;
            skills.insert(name, skill.write()?, 0o040000)?;
        }
        if symlink { skills.insert("unsafe-link", blob, 0o120000)?; }
        let skills_id = skills.write()?;
        let mut root = repo.treebuilder(None)?;
        root.insert("skills", skills_id, 0o040000)?;
        let root_id = root.write()?;
        let tree = repo.find_tree(root_id)?;
        let sig = git2::Signature::now("fixture", "fixture@example.invalid")?;
        let old = repo.find_reference("refs/heads/main").ok()
            .and_then(|r| r.target())
            .map(|oid| repo.find_commit(oid)).transpose()?;
        let parents: Vec<&git2::Commit<'_>> = old.iter().collect();
        let commit = repo.commit(Some("refs/heads/main"), &sig, &sig, "fixture", &tree, &parents)?;
        repo.set_head("refs/heads/main")?;
        Ok(commit.to_string())
    }

    #[test]
    fn clone_fetches_only_latest_commit_over_transport() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let remote = temp.path().join("remote.git");
        write_fake_repository(&remote, &["old"], false)?;
        let head = write_fake_repository(&remote, &["latest"], false)?;
        let url = reqwest::Url::from_directory_path(&remote)
            .map_err(|_| anyhow::anyhow!("fixture path is not a file URL"))?;
        let dest = temp.path().join("clone.git");
        clone_bare(url.as_str(), "main", &dest)?;
        let cloned = git2::Repository::open_bare(dest)?;
        assert!(cloned.is_shallow());
        assert_eq!(cloned.head()?.peel_to_commit()?.id().to_string(), head);
        Ok(())
    }

    #[test]
    fn repository_sources_validate_urls_and_roots() {
        assert!(validate_source_url("https://github.com/example/example.git").is_ok());
        assert!(validate_source_url("git@github-alias:example/example.git").is_ok());
        assert!(validate_source_url("ssh://git@github.com/example/example.git").is_ok());
        for url in ["https://token@github.com/a/b", "https://u:p@github.com/a/b",
            "https://github.com/a/b?token=secret", "file:///tmp/repo", "-unsafe", "git@host:../secret"] {
            assert!(validate_source_url(url).is_err());
        }
        for root in ["../other", "/abs", "x/../y", "x\\\\y", "x//y", ".git", "x:y"] {
            assert!(normalize_skills_root(root).is_err(), "{root}");
        }
        assert_eq!(normalize_skills_root("skills/example").unwrap(), "skills/example");
    }

    #[test]
    fn repository_sources_read_only_committed_root_and_nested_skills() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let work = tmp.path().join("work");
        let repo = git2::Repository::init(&work)?;
        for folder in ["direct", "layer/nested"] {
            std::fs::create_dir_all(work.join(folder))?;
            std::fs::write(work.join(folder).join("SKILL.md"), b"committed")?;
        }
        let mut index = repo.index()?;
        for path in ["direct/SKILL.md", "layer/nested/SKILL.md"] {
            index.add_path(Path::new(path))?;
        }
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let sig = git2::Signature::now("fixture", "fixture@example.invalid")?;
        let oid = repo.commit(Some("refs/heads/main"), &sig, &sig, "fixture", &tree, &[])?;
        repo.set_head("refs/heads/main")?;
        // Neither the newly untracked skill nor this dirty edit is a commit.
        std::fs::create_dir_all(work.join("untracked"))?;
        std::fs::write(work.join("untracked/SKILL.md"), b"not committed")?;
        std::fs::write(work.join("direct/SKILL.md"), b"modified")?;
        let mut source = RepositorySource {
            id: "repo-fixture".into(), name: "fixture".into(), device_id: None,
            url: "https://github.com/example/fixture.git".into(),
            branch: "main".into(), skills_root: "".into(), created_at: 1,
        };
        let snapshot = read_snapshot(work.to_str().unwrap(), &source, 1)?;
        assert_eq!(snapshot.head_commit, oid.to_string());
        assert_eq!(snapshot.skills.iter().map(|s| s.relative_path.as_str()).collect::<Vec<_>>(),
            ["direct", "layer/nested"]);
        source.skills_root = "layer".into();
        let subroot = read_snapshot(work.to_str().unwrap(), &source, 2)?;
        assert_eq!(subroot.skills.iter().map(|s| s.relative_path.as_str()).collect::<Vec<_>>(),
            ["layer/nested"]);
        source.skills_root = "missing".into();
        assert!(read_snapshot(work.to_str().unwrap(), &source, 3).is_err());
        Ok(())
    }

    #[test]
    fn repository_sources_two_repos_are_isolated_and_failure_preserves_cache() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let repo_a = tmp.path().join("one.git");
        let repo_b = tmp.path().join("two.git");
        let head_a = write_fake_repository(&repo_a, &["shared", "only-a"], false)?;
        let head_b = write_fake_repository(&repo_b, &["shared", "only-b"], false)?;
        let db = tmp.path().join("state.db");
        let store = SkillStore::new(&db)?;
        let source = |id: &str| RepositorySource {
            id: id.to_string(), name: id.to_string(), device_id: None,
            url: "https://github.com/example/fixture.git".into(), branch: "main".into(),
            skills_root: "skills".into(), created_at: 1,
        };
        let a = source("repo-a");
        let b = source("repo-b");
        store.insert_repository_source(&a)?;
        store.insert_repository_source(&b)?;
        let first = fetch_and_save(&store, &a, repo_a.to_str().unwrap())?;
        let second = fetch_and_save(&store, &b, repo_b.to_str().unwrap())?;
        assert_eq!(first.head_commit, head_a);
        assert_eq!(second.head_commit, head_b);
        assert_eq!(first.skills.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["only-a", "shared"]);
        assert_eq!(second.skills.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["only-b", "shared"]);
        let new_head_a = write_fake_repository(&repo_a, &["new-a", "shared"], false)?;
        let updated = fetch_and_save(&store, &a, repo_a.to_str().unwrap())?;
        assert_eq!(updated.head_commit, new_head_a);
        assert_eq!(store.get_repository_snapshot(&b.id)?.unwrap().head_commit, head_b);
        write_fake_repository(&repo_a, &["shared"], true)?;
        assert!(fetch_and_save(&store, &a, repo_a.to_str().unwrap()).is_err());
        assert_eq!(store.get_repository_snapshot(&a.id)?.unwrap().head_commit, new_head_a);
        assert!(fetch_and_save(&store, &a, tmp.path().join("unavailable.git").to_str().unwrap()).is_err());
        assert_eq!(store.get_repository_snapshot(&a.id)?.unwrap().head_commit, new_head_a);
        drop(store);
        let reopened = SkillStore::new(&db)?;
        assert_eq!(reopened.list_repository_sources()?.len(), 2);
        assert_eq!(reopened.get_repository_snapshot(&a.id)?.unwrap().head_commit, new_head_a);
        assert!(reopened.delete_repository_source(&a.id)?);
        assert!(reopened.get_repository_snapshot(&a.id)?.is_none());
        assert!(reopened.get_repository_snapshot(&b.id)?.is_some());
        assert!(repo_a.exists() && repo_b.exists());
        Ok(())
    }
}

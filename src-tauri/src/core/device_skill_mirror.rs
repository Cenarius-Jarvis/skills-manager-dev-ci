//! A device-bound, persistent Git object cache and local drafts.
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use git2::{Commit, ObjectType, Oid, Repository, Tree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use super::{central_repo, devices, git_command::git_command, git_credentials::credential_env_for_url,
    repository_sources::{self, RepositorySource}, skill_metadata, skill_store::SkillStore};

const MAX_DOCUMENT: usize = 512 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MirrorSnapshot {
    pub head_commit: Option<String>,
    pub synced_at: Option<i64>,
    pub skills: Vec<MirrorEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MirrorEntry {
    pub path: String,
    pub name: String,
    pub description: Option<String>,
    pub has_draft: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Draft {
    pub content: String,
    pub head_commit: String,
    pub has_draft: bool,
}

pub fn bound_source(store: &SkillStore, device: &str, id: &str) -> Result<RepositorySource> {
    devices::validate_device_id(device)?;
    let source = store.get_repository_source(id)?.context("repository source is unavailable")?;
    if source.device_id.as_deref() != Some(device) || source.id != id {
        bail!("repository source belongs to a different device");
    }
    if !id.starts_with("repo-") {
        bail!("invalid repository source id");
    }
    devices::validate_device_id(id)?;
    repository_sources::validate_source_url(&source.url)?;
    devices::validate_branch_name(&source.branch)?;
    let root = repository_sources::normalize_skills_root(&source.skills_root)?;
    if root != source.skills_root {
        bail!("invalid repository skills root");
    }
    Ok(source)
}

pub fn cache(source: &RepositorySource) -> PathBuf {
    central_repo::home_base_dir().join("cache").join("device-skill-mirrors").join(&source.id)
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let dir = path.parent().context("cache path has no parent")?;
    fs::create_dir_all(dir)?;
    let mut staged = tempfile::NamedTempFile::new_in(dir)?;
    serde_json::to_writer(&mut staged, value)?;
    staged.flush()?;
    staged.as_file().sync_all()?;
    staged.persist(path)?;
    Ok(())
}

pub fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match File::open(path) {
        Ok(file) => Ok(Some(serde_json::from_reader(file)?)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn lock(source: &RepositorySource) -> Result<File> {
    let dir = cache(source);
    fs::create_dir_all(&dir)?;
    let lock = OpenOptions::new().write(true).create(true).truncate(false).open(dir.join("operation.lock"))?;
    FileExt::try_lock_exclusive(&lock).context("this device repository is busy")?;
    Ok(lock)
}

fn snapshot_file(source: &RepositorySource) -> PathBuf {
    cache(source).join("snapshot.json")
}

pub fn draft_file(source: &RepositorySource, path: &str) -> PathBuf {
    let key = hex::encode(Sha256::digest(path.as_bytes()));
    cache(source).join("drafts").join(format!("{key}.json"))
}

pub fn list(source: &RepositorySource) -> Result<MirrorSnapshot> {
    let mut snapshot = load_json::<MirrorSnapshot>(&snapshot_file(source))?.unwrap_or_default();
    for skill in &mut snapshot.skills {
        skill.has_draft = draft_file(source, &skill.path).is_file();
    }
    Ok(snapshot)
}

pub fn open_repo(source: &RepositorySource) -> Result<Repository> {
    Repository::open_bare(cache(source).join("objects.git")).context("refresh the repository cache first")
}

pub fn network_git(repo: &Repository, source: &RepositorySource, args: &[&str]) -> Result<()> {
    let mut cmd = git_command();
    cmd.current_dir(repo.path()).args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=15")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    for (key, value) in credential_env_for_url(&source.url) {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().context("could not start Git")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() { return Ok(()); }
            bail!("repository Git operation failed; check access, branch and network");
        }
        if start.elapsed() >= Duration::from_secs(90) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("repository Git operation timed out");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Requires the source lock. Only advertised objects are fetched; no checkout,
/// clean/smudge filters, hooks or skill code are run.
pub fn fetch(source: &RepositorySource) -> Result<(Repository, Oid)> {
    let dir = cache(source).join("objects.git");
    let repo = if dir.exists() { Repository::open_bare(&dir)? } else { Repository::init_bare(&dir)? };
    let refspec = format!("+refs/heads/{}:refs/heads/cached-source", source.branch);
    network_git(&repo, source, &["fetch", "--no-tags", "--depth", "2", "--", &source.url, &refspec])?;
    let tip = repo.refname_to_id("refs/heads/cached-source")?;
    Ok((repo, tip))
}

fn document_path(path: &str) -> PathBuf {
    if path == "." { PathBuf::from("SKILL.md") } else { Path::new(path).join("SKILL.md") }
}

pub fn document_blob(repo: &Repository, commit: &Commit<'_>, path: &str) -> Result<Vec<u8>> {
    let entry = commit.tree()?.get_path(&document_path(path))?;
    if !matches!(entry.filemode(), 0o100644 | 0o100755) {
        bail!("skill document is not a regular Git file");
    }
    let blob = repo.find_blob(entry.id())?;
    if blob.size() > MAX_DOCUMENT {
        bail!("SKILL.md exceeds the editor size limit");
    }
    Ok(blob.content().to_vec())
}

pub fn refresh(source: &RepositorySource) -> Result<MirrorSnapshot> {
    let _lock = lock(source)?;
    let (repo, tip) = fetch(source)?;
    save_snapshot(source, &repo, tip)
}

pub fn save_snapshot(source: &RepositorySource, repo: &Repository, tip: Oid) -> Result<MirrorSnapshot> {
    let commit = repo.find_commit(tip)?;
    let tree = commit.tree()?;
    let skill_tree = if source.skills_root.is_empty() {
        tree
    } else {
        let entry = tree.get_path(Path::new(&source.skills_root)).context("skills root is missing")?;
        repo.find_tree(entry.id()).context("skills root is not a directory")?
    };
    let mut skills = Vec::new();
    repository_sources::scan_tree(repo, &skill_tree, &source.skills_root, &mut skills, &mut 0, 0)?;
    let skills = skills.into_iter().map(|skill| {
        let path = skill.relative_path;
        let meta = document_blob(repo, &commit, &path).ok()
            .and_then(|content| String::from_utf8(content).ok()).map(|content| skill_metadata::parse_frontmatter(&content));
        MirrorEntry {
            has_draft: draft_file(source, &path).is_file(),
            name: meta.as_ref().and_then(|m| m.name.clone()).unwrap_or(skill.name),
            description: meta.and_then(|m| m.description),
            path,
        }
    }).collect();
    let snapshot = MirrorSnapshot {
        head_commit: Some(tip.to_string()), synced_at: Some(chrono::Utc::now().timestamp()), skills,
    };
    write_json(&snapshot_file(source), &snapshot)?;
    Ok(snapshot)
}

fn checked_skill(source: &RepositorySource, path: &str) -> Result<MirrorSnapshot> {
    if path != "." {
        if path.is_empty() || repository_sources::normalize_skills_root(path)? != path {
            bail!("invalid skill path");
        }
    }
    let snapshot = list(source)?;
    if !snapshot.skills.iter().any(|skill| skill.path == path) {
        bail!("skill is absent from the saved repository snapshot");
    }
    Ok(snapshot)
}

pub fn read(source: &RepositorySource, path: &str) -> Result<Draft> {
    let snapshot = checked_skill(source, path)?;
    if let Some(draft) = load_json(&draft_file(source, path))? {
        return Ok(draft);
    }
    let head_commit = snapshot.head_commit.context("repository is not cached")?;
    let repo = open_repo(source)?;
    let commit = repo.find_commit(Oid::from_str(&head_commit)?)?;
    let content = String::from_utf8(document_blob(&repo, &commit, path)?).context("SKILL.md is not UTF-8")?;
    Ok(Draft { content, head_commit, has_draft: false })
}

pub fn save(source: &RepositorySource, path: &str, base: &str, content: String) -> Result<Draft> {
    let _lock = lock(source)?;
    let previous = read(source, path)?;
    if previous.head_commit != base {
        bail!("skill changed since it was opened");
    }
    if content.trim().is_empty() || content.len() > MAX_DOCUMENT {
        bail!("SKILL.md is empty or exceeds the editor size limit");
    }
    let draft = Draft { content, head_commit: base.into(), has_draft: true };
    write_json(&draft_file(source, path), &draft)?;
    Ok(draft)
}

pub fn edited_tree(repo: &Repository, tree: &Tree<'_>, path: &Path, bytes: &[u8]) -> Result<Oid> {
    let first = path.components().next().context("empty document path")?;
    let name = first.as_os_str().to_str().context("non-UTF-8 document path")?;
    let tail = path.strip_prefix(first.as_os_str())?;
    let entry = tree.get_name(name).context("document path no longer exists")?;
    let mut builder = repo.treebuilder(Some(tree))?;
    if tail.as_os_str().is_empty() {
        if entry.kind() != Some(ObjectType::Blob) || !matches!(entry.filemode(), 0o100644 | 0o100755) {
            bail!("can only edit a regular SKILL.md file");
        }
        builder.insert(name, repo.blob(bytes)?, entry.filemode())?;
    } else {
        let subtree = repo.find_tree(entry.id())?;
        builder.insert(name, edited_tree(repo, &subtree, tail, bytes)?, entry.filemode())?;
    }
    Ok(builder.write()?)
}

pub fn edited_document_tree(repo: &Repository, tree: &Tree<'_>, path: &str, bytes: &[u8]) -> Result<Oid> {
    edited_tree(repo, tree, &document_path(path), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_skill_mirror_keeps_offline_files_and_drafts_at_their_original_base() -> Result<()> {
        let _guard = central_repo::test_base_dir_lock();
        let home = tempfile::tempdir()?;
        central_repo::set_test_home_dir_override(Some(home.path().to_owned()));
        struct ResetPath;
        impl Drop for ResetPath {
            fn drop(&mut self) { central_repo::set_test_home_dir_override(None); }
        }
        let _reset = ResetPath;
        let source = RepositorySource {
            id: "repo-offline".into(), name: "Offline fixture".into(), device_id: Some("dev-copy".into()),
            url: "https://github.com/example/test.git".into(), branch: "main".into(), skills_root: "demo".into(),
            created_at: 1,
        };
        fs::create_dir_all(cache(&source))?;
        let repo = Repository::init_bare(cache(&source).join("objects.git"))?;
        let mut builder = repo.treebuilder(None)?;
        builder.insert("SKILL.md", repo.blob(b"---\nname: demo\n---\noriginal\n")?, 0o100644)?;
        builder.insert("notes.txt", repo.blob(b"cached supporting file")?, 0o100644)?;
        let mut root = repo.treebuilder(None)?;
        root.insert("demo", builder.write()?, 0o040000)?;
        let tree = repo.find_tree(root.write()?)?;
        let author = git2::Signature::now("Test", "test@example.invalid")?;
        let base = repo.commit(None, &author, &author, "base", &tree, &[])?;
        save_snapshot(&source, &repo, base)?;
        assert!(read(&source, "demo")?.content.contains("original"));
        let draft = save(&source, "demo", &base.to_string(), "my offline draft\n".into())?;
        assert!(draft.has_draft);

        let edited = repo.find_tree(edited_document_tree(&repo, &tree, "demo", b"published version\n")?)?;
        let head = repo.commit(None, &author, &author, "second", &edited, &[&repo.find_commit(base)?])?;
        save_snapshot(&source, &repo, head)?;
        let offline = read(&source, "demo")?;
        assert_eq!(offline.head_commit, base.to_string());
        assert_eq!(offline.content, "my offline draft\n");
        let notes = edited.get_path(Path::new("demo/notes.txt"))?;
        assert_eq!(repo.find_blob(notes.id())?.content(), b"cached supporting file");
        assert!(read(&source, "../demo").is_err());
        assert!(save(&source, "demo", &head.to_string(), "stale writer".into()).is_err());
        Ok(())
    }
}

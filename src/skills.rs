use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Cursor, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tar::Archive;
use tokio::task;
use uuid::Uuid;
use zip::ZipArchive;

use crate::config::Config;

const SKILLS_DIR_NAME: &str = "skills";
const ROOT_SKILL_MD: &str = "SKILL.md";
const MACOS_METADATA_DIR: &str = "__MACOSX";
const MACOS_METADATA_FILE: &str = ".DS_Store";
const DIST_DIR: &str = "dist";
const MAX_ARCHIVE_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SkillSyncState {
    Synced,
    MissingOnSomeAccounts,
    ContentMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillListSnapshot {
    pub skills: Vec<SkillListItemSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillListItemSnapshot {
    pub name: String,
    pub description: Option<String>,
    pub sync_state: SkillSyncState,
    pub installed_accounts: usize,
    pub total_accounts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillPreviewSnapshot {
    pub name: String,
    pub description: Option<String>,
    pub sync_state: SkillSyncState,
    pub canonical_path: String,
    pub skill_markdown: String,
    pub file_paths: Vec<String>,
    pub accounts: Vec<SkillAccountSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillAccountSnapshot {
    pub account_name: String,
    pub installed: bool,
    pub root_path: Option<String>,
    pub matches_canonical: bool,
}

#[derive(Debug, Clone)]
pub struct SkillsManager {
    inner: Arc<SkillsManagerInner>,
}

#[derive(Debug, Clone)]
struct SkillsManagerInner {
    accounts: Vec<ManagedSkillAccount>,
}

#[derive(Debug, Clone)]
struct ManagedSkillAccount {
    name: String,
    codex_home: PathBuf,
}

#[derive(Debug, Clone, Default)]
struct SkillMetadata {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillManifest {
    files: Vec<SkillManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillManifestFile {
    path: String,
    size_bytes: u64,
    digest: u64,
}

#[derive(Debug, Clone)]
struct SkillInstallLocation {
    account_name: String,
    root_path: PathBuf,
    metadata: SkillMetadata,
    manifest: SkillManifest,
}

#[derive(Debug, Clone)]
struct SkillAggregate {
    name: String,
    locations: Vec<SkillInstallLocation>,
}

#[derive(Debug)]
struct PreparedSkillArchive {
    resolved_name: String,
    stage_root: PathBuf,
}

#[derive(Debug)]
struct ArchiveFileEntry {
    relative_path: PathBuf,
    bytes: Vec<u8>,
    unix_mode: Option<u32>,
}

impl SkillsManager {
    pub fn new(config: &Config) -> Self {
        let mut accounts = vec![ManagedSkillAccount {
            name: "primary".to_string(),
            codex_home: PathBuf::from(&config.codex.auth_host_path),
        }];
        accounts.extend(config.codex.fallback_auth_accounts.iter().map(|account| {
            ManagedSkillAccount {
                name: account.name.clone(),
                codex_home: PathBuf::from(&account.auth_host_path),
            }
        }));
        Self {
            inner: Arc::new(SkillsManagerInner { accounts }),
        }
    }

    pub async fn list_skills(&self) -> Result<SkillListSnapshot> {
        let inner = Arc::clone(&self.inner);
        task::spawn_blocking(move || inner.list_skills_blocking())
            .await
            .context("join skills list task")?
    }

    pub async fn skill_preview(&self, name: &str) -> Result<Option<SkillPreviewSnapshot>> {
        let inner = Arc::clone(&self.inner);
        let name = name.to_string();
        task::spawn_blocking(move || inner.skill_preview_blocking(&name))
            .await
            .context("join skill preview task")?
    }

    pub async fn install_archive(&self, archive_name: &str, bytes: Vec<u8>) -> Result<String> {
        let inner = Arc::clone(&self.inner);
        let archive_name = archive_name.to_string();
        task::spawn_blocking(move || inner.install_archive_blocking(&archive_name, &bytes))
            .await
            .context("join skill install task")?
    }

    pub async fn delete_skill(&self, name: &str) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        let name = name.to_string();
        task::spawn_blocking(move || inner.delete_skill_blocking(&name))
            .await
            .context("join skill delete task")?
    }
}

impl SkillsManagerInner {
    fn list_skills_blocking(&self) -> Result<SkillListSnapshot> {
        let aggregates = self.scan_installed_skills()?;
        let mut skills = aggregates
            .into_values()
            .map(|aggregate| SkillListItemSnapshot {
                description: aggregate.canonical_location().metadata.description.clone(),
                sync_state: aggregate.sync_state(self.accounts.len()),
                installed_accounts: aggregate.locations.len(),
                total_accounts: self.accounts.len(),
                name: aggregate.name,
            })
            .collect::<Vec<_>>();
        skills.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(SkillListSnapshot { skills })
    }

    fn skill_preview_blocking(&self, name: &str) -> Result<Option<SkillPreviewSnapshot>> {
        validate_skill_name(name)?;
        let Some(aggregate) = self.scan_installed_skills()?.remove(name) else {
            return Ok(None);
        };
        let canonical = aggregate.canonical_location();
        let skill_markdown = fs::read_to_string(canonical.root_path.join(ROOT_SKILL_MD))
            .with_context(|| {
                format!("read {}", canonical.root_path.join(ROOT_SKILL_MD).display())
            })?;
        let file_paths = canonical
            .manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        let canonical_manifest = &canonical.manifest;
        Ok(Some(SkillPreviewSnapshot {
            name: aggregate.name.clone(),
            description: canonical.metadata.description.clone(),
            sync_state: aggregate.sync_state(self.accounts.len()),
            canonical_path: canonical.root_path.display().to_string(),
            skill_markdown,
            file_paths,
            accounts: self
                .accounts
                .iter()
                .map(|account| {
                    let location = aggregate
                        .locations
                        .iter()
                        .find(|location| location.account_name == account.name);
                    SkillAccountSnapshot {
                        account_name: account.name.clone(),
                        installed: location.is_some(),
                        root_path: location.map(|entry| entry.root_path.display().to_string()),
                        matches_canonical: location
                            .map(|entry| entry.manifest == *canonical_manifest)
                            .unwrap_or(false),
                    }
                })
                .collect(),
        }))
    }

    fn install_archive_blocking(&self, archive_name: &str, bytes: &[u8]) -> Result<String> {
        let prepared = self.prepare_archive_install(archive_name, bytes)?;
        let resolved_name = prepared.resolved_name.clone();
        let stage_root = prepared.stage_root.clone();
        let cleanup_result = self.copy_stage_into_accounts(&resolved_name, &stage_root);
        let cleanup_err = fs::remove_dir_all(&stage_root);
        if let Err(err) = cleanup_result {
            if let Err(cleanup) = cleanup_err {
                return Err(err.context(format!("cleanup staged archive: {cleanup}")));
            }
            return Err(err);
        }
        cleanup_err.with_context(|| format!("cleanup staged archive {}", stage_root.display()))?;
        Ok(resolved_name)
    }

    fn delete_skill_blocking(&self, name: &str) -> Result<()> {
        validate_skill_name(name)?;
        if is_reserved_skill_name(name) {
            bail!("invalid skill name: {name}");
        }
        let mut removed_any = false;
        for account in &self.accounts {
            let root = account.codex_home.join(SKILLS_DIR_NAME).join(name);
            if !root.exists() {
                continue;
            }
            removed_any = true;
            fs::remove_dir_all(&root)
                .with_context(|| format!("remove skill {} from {}", name, root.display()))?;
        }
        if !removed_any {
            bail!("skill not found: {name}");
        }
        Ok(())
    }

    fn scan_installed_skills(&self) -> Result<BTreeMap<String, SkillAggregate>> {
        let mut by_name = BTreeMap::<String, SkillAggregate>::new();
        for account in &self.accounts {
            let skills_root = account.codex_home.join(SKILLS_DIR_NAME);
            if !skills_root.exists() {
                continue;
            }
            for entry in fs::read_dir(&skills_root)
                .with_context(|| format!("read {}", skills_root.display()))?
            {
                let entry = entry.with_context(|| format!("read {}", skills_root.display()))?;
                let file_type = entry
                    .file_type()
                    .with_context(|| format!("inspect {}", entry.path().display()))?;
                if !file_type.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if is_reserved_skill_name(&name) {
                    continue;
                }
                let root_path = entry.path();
                let skill_md_path = root_path.join(ROOT_SKILL_MD);
                if !skill_md_path.is_file() {
                    continue;
                }
                let skill_markdown = fs::read_to_string(&skill_md_path)
                    .with_context(|| format!("read {}", skill_md_path.display()))?;
                let metadata = parse_skill_metadata(&skill_markdown);
                let manifest = build_skill_manifest(&root_path)?;
                by_name
                    .entry(name.clone())
                    .or_insert_with(|| SkillAggregate {
                        name: name.clone(),
                        locations: Vec::new(),
                    })
                    .locations
                    .push(SkillInstallLocation {
                        account_name: account.name.clone(),
                        root_path,
                        metadata,
                        manifest,
                    });
            }
        }
        Ok(by_name)
    }

    fn prepare_archive_install(
        &self,
        archive_name: &str,
        bytes: &[u8],
    ) -> Result<PreparedSkillArchive> {
        let extracted = extract_archive(archive_name, bytes)?;
        if extracted.is_empty() {
            bail!("invalid skill archive: archive is empty");
        }
        let stripped = strip_common_wrapper(extracted);
        validate_archive_paths(&stripped)?;
        let skill_md_entry = stripped
            .iter()
            .find(|entry| entry.relative_path == Path::new(ROOT_SKILL_MD))
            .ok_or_else(|| anyhow::anyhow!("invalid skill archive: root SKILL.md is required"))?;
        let skill_markdown = std::str::from_utf8(&skill_md_entry.bytes)
            .context("invalid skill archive: SKILL.md must be valid UTF-8")?;
        let metadata = parse_skill_metadata(skill_markdown);
        let resolved_name = resolve_skill_name(archive_name, &metadata, &stripped)?;
        validate_skill_name(&resolved_name)?;
        if is_reserved_skill_name(&resolved_name) {
            bail!("invalid skill name: {}", resolved_name);
        }
        if self.scan_installed_skills()?.contains_key(&resolved_name) {
            bail!("skill already exists: {}", resolved_name);
        }
        let staged_root = temp_workspace_root("skill-stage");
        fs::create_dir_all(&staged_root)
            .with_context(|| format!("create {}", staged_root.display()))?;
        if let Err(err) = write_archive_entries(&staged_root, &stripped) {
            let _ = fs::remove_dir_all(&staged_root);
            return Err(err);
        }
        Ok(PreparedSkillArchive {
            resolved_name,
            stage_root: staged_root,
        })
    }

    fn copy_stage_into_accounts(&self, name: &str, stage_root: &Path) -> Result<()> {
        let mut installed_paths = Vec::<PathBuf>::new();
        for account in &self.accounts {
            let skills_root = account.codex_home.join(SKILLS_DIR_NAME);
            if let Err(err) = fs::create_dir_all(&skills_root)
                .with_context(|| format!("create {}", skills_root.display()))
            {
                self.rollback_install(&installed_paths);
                return Err(err);
            }
            let final_path = skills_root.join(name);
            if final_path.exists() {
                self.rollback_install(&installed_paths);
                bail!("skill already exists: {}", name);
            }
            let temp_path = skills_root.join(format!(".install-{}-{}", name, Uuid::new_v4()));
            if temp_path.exists() {
                fs::remove_dir_all(&temp_path)
                    .with_context(|| format!("cleanup {}", temp_path.display()))?;
            }
            if let Err(err) = copy_dir(stage_root, &temp_path)
                .with_context(|| format!("stage install into {}", temp_path.display()))
            {
                let _ = fs::remove_dir_all(&temp_path);
                self.rollback_install(&installed_paths);
                return Err(err);
            }
            if let Err(err) = fs::rename(&temp_path, &final_path)
                .with_context(|| format!("install skill into {}", final_path.display()))
            {
                let _ = fs::remove_dir_all(&temp_path);
                self.rollback_install(&installed_paths);
                return Err(err);
            }
            installed_paths.push(final_path);
        }
        Ok(())
    }

    fn rollback_install(&self, installed_paths: &[PathBuf]) {
        for path in installed_paths {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl SkillAggregate {
    fn canonical_location(&self) -> &SkillInstallLocation {
        self.locations
            .iter()
            .find(|location| location.account_name == "primary")
            .unwrap_or_else(|| &self.locations[0])
    }

    fn sync_state(&self, total_accounts: usize) -> SkillSyncState {
        let manifests = self
            .locations
            .iter()
            .map(|location| &location.manifest)
            .collect::<Vec<_>>();
        let manifest_mismatch = manifests
            .split_first()
            .is_some_and(|(first, rest)| rest.iter().any(|manifest| *manifest != *first));
        if manifest_mismatch {
            SkillSyncState::ContentMismatch
        } else if self.locations.len() < total_accounts {
            SkillSyncState::MissingOnSomeAccounts
        } else {
            SkillSyncState::Synced
        }
    }
}

fn build_skill_manifest(root: &Path) -> Result<SkillManifest> {
    let mut files = Vec::new();
    collect_manifest_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(SkillManifest { files })
}

fn collect_manifest_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<SkillManifestFile>,
) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry.with_context(|| format!("read {}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", path.display()))?;
        if file_type.is_dir() {
            collect_manifest_files(root, &path, files)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("strip {} from {}", root.display(), path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        files.push(SkillManifestFile {
            path: relative,
            size_bytes: bytes.len() as u64,
            digest: hasher.finish(),
        });
    }
    Ok(())
}

fn extract_archive(archive_name: &str, bytes: &[u8]) -> Result<Vec<ArchiveFileEntry>> {
    if archive_name.ends_with(".zip") {
        return extract_zip(bytes);
    }
    if archive_name.ends_with(".tar") {
        return extract_tar(Cursor::new(bytes));
    }
    if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        return extract_tar(GzDecoder::new(Cursor::new(bytes)));
    }
    bail!("unsupported archive type: {}", archive_name);
}

fn extract_zip(bytes: &[u8]) -> Result<Vec<ArchiveFileEntry>> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).context("invalid zip archive")?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("read zip entry {index}"))?;
        if is_zip_link(&entry) {
            bail!("invalid skill archive: symlinks are not allowed");
        }
        let relative_path = normalize_archive_path_string(entry.name())?;
        if should_ignore_archive_path(&relative_path) || entry.is_dir() {
            continue;
        }
        let entry_name = entry.name().to_string();
        enforce_archive_size_limits(entry.size(), &mut total_bytes, &entry_name)?;
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .with_context(|| format!("read zip entry {}", entry.name()))?;
        enforce_read_size(contents.len(), &entry_name)?;
        files.push(ArchiveFileEntry {
            relative_path,
            bytes: contents,
            unix_mode: entry.unix_mode(),
        });
    }
    Ok(files)
}

fn is_zip_link<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> bool {
    let Some(mode) = entry.unix_mode() else {
        return false;
    };
    let file_type = mode & 0o170000;
    file_type == 0o120000 || file_type == 0o100000 && entry.name().ends_with('/')
}

fn extract_tar<R: Read>(reader: R) -> Result<Vec<ArchiveFileEntry>> {
    let mut archive = Archive::new(reader);
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for entry in archive.entries().context("read tar archive entries")? {
        let mut entry = entry.context("read tar archive entry")?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            bail!("invalid skill archive: symlinks are not allowed");
        }
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            bail!("invalid skill archive: only regular files are allowed");
        }
        let relative_path = normalize_archive_path(entry.path()?.as_ref())?;
        if should_ignore_archive_path(&relative_path) {
            continue;
        }
        let entry_name = relative_path.to_string_lossy().to_string();
        enforce_archive_size_limits(entry.size(), &mut total_bytes, &entry_name)?;
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .context("read tar archive file")?;
        enforce_read_size(contents.len(), &entry_name)?;
        files.push(ArchiveFileEntry {
            relative_path,
            bytes: contents,
            unix_mode: entry.header().mode().ok(),
        });
    }
    Ok(files)
}

fn validate_archive_paths(files: &[ArchiveFileEntry]) -> Result<()> {
    let mut seen = HashSet::<String>::new();
    let mut skill_md_paths = Vec::new();
    for file in files {
        let key = file.relative_path.to_string_lossy().replace('\\', "/");
        if !seen.insert(key.clone()) {
            bail!("invalid skill archive: duplicate file {}", key);
        }
        if file
            .relative_path
            .file_name()
            .and_then(|name| name.to_str())
            == Some(ROOT_SKILL_MD)
        {
            skill_md_paths.push(key);
        }
    }
    if skill_md_paths.len() != 1 || skill_md_paths[0] != ROOT_SKILL_MD {
        bail!("invalid skill archive: root SKILL.md is required");
    }
    Ok(())
}

fn strip_common_wrapper(mut files: Vec<ArchiveFileEntry>) -> Vec<ArchiveFileEntry> {
    loop {
        if files
            .iter()
            .any(|entry| entry.relative_path == Path::new(ROOT_SKILL_MD))
        {
            return files;
        }
        let Some(common_prefix) = shared_first_component(&files) else {
            return files;
        };
        files = files
            .into_iter()
            .map(|entry| ArchiveFileEntry {
                relative_path: strip_first_component(&entry.relative_path, &common_prefix),
                bytes: entry.bytes,
                unix_mode: entry.unix_mode,
            })
            .collect();
    }
}

fn shared_first_component(files: &[ArchiveFileEntry]) -> Option<String> {
    let mut first_components = BTreeSet::new();
    for file in files {
        let component = file.relative_path.iter().next()?;
        first_components.insert(component.to_string_lossy().to_string());
    }
    if first_components.len() == 1 {
        first_components.into_iter().next()
    } else {
        None
    }
}

fn strip_first_component(path: &Path, component: &str) -> PathBuf {
    let mut pieces = path.iter();
    let first = pieces.next();
    if first.is_some_and(|value| value == component) {
        let mut stripped = PathBuf::new();
        for piece in pieces {
            stripped.push(piece);
        }
        stripped
    } else {
        path.to_path_buf()
    }
}

fn normalize_archive_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(
                value
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid skill archive: non-UTF-8 path"))?,
            ),
            Component::CurDir => {}
            Component::ParentDir => bail!("invalid skill archive: parent traversal is not allowed"),
            Component::RootDir | Component::Prefix(_) => {
                bail!("invalid skill archive: absolute paths are not allowed")
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("invalid skill archive: empty path");
    }
    Ok(normalized)
}

fn normalize_archive_path_string(path: &str) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.split(['/', '\\']) {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            bail!("invalid skill archive: parent traversal is not allowed");
        }
        if component.contains(':') {
            bail!("invalid skill archive: absolute paths are not allowed");
        }
        normalized.push(component);
    }
    if normalized.as_os_str().is_empty() {
        bail!("invalid skill archive: empty path");
    }
    Ok(normalized)
}

fn should_ignore_archive_path(path: &Path) -> bool {
    let mut components = path.iter();
    let Some(first) = components.next() else {
        return false;
    };
    if first == MACOS_METADATA_DIR {
        return true;
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == MACOS_METADATA_FILE)
}

fn write_archive_entries(root: &Path, entries: &[ArchiveFileEntry]) -> Result<()> {
    for entry in entries {
        let full_path = root.join(&entry.relative_path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&full_path, &entry.bytes)
            .with_context(|| format!("write {}", full_path.display()))?;
        apply_unix_mode(&full_path, entry.unix_mode)
            .with_context(|| format!("set permissions on {}", full_path.display()))?;
    }
    Ok(())
}

fn copy_dir(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination).with_context(|| format!("create {}", destination.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("read {}", source.display()))? {
        let entry = entry.with_context(|| format!("read {}", source.display()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", source_path.display()))?;
        if file_type.is_dir() {
            copy_dir(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
            let permissions = fs::metadata(&source_path)
                .with_context(|| format!("stat {}", source_path.display()))?
                .permissions();
            fs::set_permissions(&destination_path, permissions)
                .with_context(|| format!("copy permissions to {}", destination_path.display()))?;
        } else {
            bail!(
                "unsupported filesystem entry while copying staged skill: {}",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn parse_skill_metadata(markdown: &str) -> SkillMetadata {
    let mut lines = markdown.lines();
    if lines.next().map(str::trim) != Some("---") {
        return SkillMetadata::default();
    }
    let mut metadata = SkillMetadata::default();
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" {
            break;
        }
        let Some((key, raw_value)) = trimmed.split_once(':') else {
            continue;
        };
        let value = unquote_yaml_value(raw_value.trim());
        match key.trim() {
            "name" if !value.is_empty() => metadata.name = Some(value.to_string()),
            "description" if !value.is_empty() => metadata.description = Some(value.to_string()),
            _ => {}
        }
    }
    metadata
}

fn unquote_yaml_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn resolve_skill_name(
    archive_name: &str,
    metadata: &SkillMetadata,
    files: &[ArchiveFileEntry],
) -> Result<String> {
    if let Some(name) = metadata
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(name.to_string());
    }
    let mut first_components = files
        .iter()
        .filter_map(|entry| entry.relative_path.iter().next())
        .map(|component| component.to_string_lossy().to_string())
        .collect::<BTreeSet<_>>();
    if first_components.len() == 1 {
        let candidate = first_components
            .pop_first()
            .expect("single component set cannot be empty");
        if candidate != ROOT_SKILL_MD {
            return Ok(candidate);
        }
    }
    archive_stem(archive_name)
}

fn archive_stem(archive_name: &str) -> Result<String> {
    let name = archive_name
        .trim_end_matches(".tar.gz")
        .trim_end_matches(".tgz")
        .trim_end_matches(".tar")
        .trim_end_matches(".zip")
        .trim();
    if name.is_empty() {
        bail!("invalid skill archive: missing archive filename");
    }
    Ok(name.to_string())
}

fn validate_skill_name(name: &str) -> Result<()> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        bail!("invalid skill name: empty");
    }
    if trimmed.starts_with('.') {
        bail!("invalid skill name: {}", name);
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        bail!("invalid skill name: {}", name);
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        bail!("invalid skill name: {}", name);
    }
    Ok(())
}

fn is_reserved_skill_name(name: &str) -> bool {
    name.starts_with('.') || name == DIST_DIR
}

fn temp_workspace_root(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("codex-gitlab-review-{prefix}-{}", Uuid::new_v4()))
}

fn enforce_archive_size_limits(
    entry_size: u64,
    total_bytes: &mut u64,
    entry_name: &str,
) -> Result<()> {
    if entry_size > MAX_ARCHIVE_ENTRY_BYTES {
        bail!(
            "invalid skill archive: {} exceeds the per-file limit",
            entry_name
        );
    }
    *total_bytes = total_bytes.saturating_add(entry_size);
    if *total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
        bail!("invalid skill archive: extracted content exceeds the total size limit");
    }
    Ok(())
}

fn enforce_read_size(read_len: usize, entry_name: &str) -> Result<()> {
    if (read_len as u64) > MAX_ARCHIVE_ENTRY_BYTES {
        bail!(
            "invalid skill archive: {} exceeds the per-file limit",
            entry_name
        );
    }
    Ok(())
}

#[cfg(unix)]
fn apply_unix_mode(path: &Path, unix_mode: Option<u32>) -> Result<()> {
    if let Some(mode) = unix_mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
            .with_context(|| format!("set unix mode {:o}", mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_unix_mode(_path: &Path, _unix_mode: Option<u32>) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;

use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use zip::write::SimpleFileOptions;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let path = temp_workspace_root(prefix);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_manager(accounts: &[(&str, &Path)]) -> SkillsManagerInner {
    SkillsManagerInner {
        accounts: accounts
            .iter()
            .map(|(name, path)| ManagedSkillAccount {
                name: (*name).to_string(),
                codex_home: (*path).to_path_buf(),
            })
            .collect(),
    }
}

fn write_skill(root: &Path, name: &str, markdown: &str, extra_files: &[(&str, &[u8])]) {
    let skill_root = root.join(SKILLS_DIR_NAME).join(name);
    fs::create_dir_all(&skill_root).expect("create skill root");
    fs::write(skill_root.join(ROOT_SKILL_MD), markdown).expect("write SKILL.md");
    for (path, bytes) in extra_files {
        let full_path = skill_root.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent).expect("create extra file parent");
        }
        fs::write(full_path, bytes).expect("write extra file");
    }
}

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, bytes) in entries {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start zip file");
        writer.write_all(bytes).expect("write zip file");
    }
    writer.finish().expect("finish zip").into_inner()
}

#[cfg(unix)]
fn build_zip_with_mode(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, bytes, mode) in entries {
        writer
            .start_file(path, SimpleFileOptions::default().unix_permissions(*mode))
            .expect("start zip file");
        writer.write_all(bytes).expect("write zip file");
    }
    writer.finish().expect("finish zip").into_inner()
}

fn build_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let encoder = GzEncoder::new(&mut output, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).expect("set tar path");
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append(&header, *bytes).expect("append tar file");
        }
        archive.finish().expect("finish tar");
    }
    output
}

#[test]
fn list_skills_reports_synced_missing_and_mismatch_states() {
    let primary = TestDir::new("skills-primary");
    let backup = TestDir::new("skills-backup");
    write_skill(
        primary.path(),
        "synced",
        "---\nname: synced\ndescription: Synced skill\n---\n",
        &[("scripts/run.sh", b"echo synced")],
    );
    write_skill(
        backup.path(),
        "synced",
        "---\nname: synced\ndescription: Synced skill\n---\n",
        &[("scripts/run.sh", b"echo synced")],
    );
    write_skill(
        primary.path(),
        "missing",
        "---\nname: missing\ndescription: Missing on fallback\n---\n",
        &[("agents/help.md", b"docs")],
    );
    write_skill(
        primary.path(),
        "mismatch",
        "---\nname: mismatch\ndescription: Mismatch\n---\n",
        &[("scripts/run.sh", b"echo primary")],
    );
    write_skill(
        backup.path(),
        "mismatch",
        "---\nname: mismatch\ndescription: Mismatch\n---\n",
        &[("scripts/run.sh", b"echo backup")],
    );

    let manager = test_manager(&[("primary", primary.path()), ("backup", backup.path())]);
    let snapshot = manager.list_skills_blocking().expect("list skills");
    let states = snapshot
        .skills
        .into_iter()
        .map(|skill| (skill.name, skill.sync_state))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(states.get("synced"), Some(&SkillSyncState::Synced));
    assert_eq!(
        states.get("missing"),
        Some(&SkillSyncState::MissingOnSomeAccounts)
    );
    assert_eq!(
        states.get("mismatch"),
        Some(&SkillSyncState::ContentMismatch)
    );
}

#[test]
fn install_archive_copies_skill_into_all_accounts() {
    let primary = TestDir::new("skills-install-primary");
    let backup = TestDir::new("skills-install-backup");
    let manager = test_manager(&[("primary", primary.path()), ("backup", backup.path())]);
    let archive = build_zip(&[
        (
            "cool-skill/SKILL.md",
            b"---\nname: cool-skill\ndescription: Installed skill\n---\n",
        ),
        ("cool-skill/scripts/run.sh", b"echo hi\n"),
    ]);

    let installed = manager
        .install_archive_blocking("cool-skill.zip", &archive)
        .expect("install skill archive");

    assert_eq!(installed, "cool-skill");
    assert!(
        primary
            .path()
            .join(SKILLS_DIR_NAME)
            .join("cool-skill")
            .join(ROOT_SKILL_MD)
            .is_file()
    );
    assert!(
        backup
            .path()
            .join(SKILLS_DIR_NAME)
            .join("cool-skill")
            .join("scripts/run.sh")
            .is_file()
    );
}

#[test]
fn install_archive_supports_tgz_uploads() {
    let primary = TestDir::new("skills-tgz-primary");
    let manager = test_manager(&[("primary", primary.path())]);
    let archive = build_tgz(&[
        ("wrapped/skill/SKILL.md", b"---\nname: wrapped-skill\n---\n"),
        ("wrapped/skill/examples/sample.txt", b"example"),
    ]);

    let installed = manager
        .install_archive_blocking("wrapped-skill.tgz", &archive)
        .expect("install tgz");

    assert_eq!(installed, "wrapped-skill");
    assert!(
        primary
            .path()
            .join(SKILLS_DIR_NAME)
            .join("wrapped-skill")
            .join("examples/sample.txt")
            .is_file()
    );
}

#[test]
fn install_archive_rejects_missing_root_skill_markdown() {
    let primary = TestDir::new("skills-invalid-primary");
    let manager = test_manager(&[("primary", primary.path())]);
    let archive = build_zip(&[("missing/README.md", b"no skill entrypoint")]);

    let error = manager
        .install_archive_blocking("missing.zip", &archive)
        .expect_err("missing SKILL.md should fail");

    assert!(error.to_string().contains("root SKILL.md"));
}

#[test]
fn delete_skill_removes_existing_skill_from_all_accounts() {
    let primary = TestDir::new("skills-delete-primary");
    let backup = TestDir::new("skills-delete-backup");
    write_skill(
        primary.path(),
        "delete-me",
        "---\nname: delete-me\n---\n",
        &[("scripts/run.sh", b"echo delete")],
    );
    write_skill(
        backup.path(),
        "delete-me",
        "---\nname: delete-me\n---\n",
        &[("scripts/run.sh", b"echo delete")],
    );
    let manager = test_manager(&[("primary", primary.path()), ("backup", backup.path())]);

    manager
        .delete_skill_blocking("delete-me")
        .expect("delete skill");

    assert!(
        !primary
            .path()
            .join(SKILLS_DIR_NAME)
            .join("delete-me")
            .exists()
    );
    assert!(
        !backup
            .path()
            .join(SKILLS_DIR_NAME)
            .join("delete-me")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn install_archive_preserves_executable_permissions() {
    let primary = TestDir::new("skills-perms-primary");
    let manager = test_manager(&[("primary", primary.path())]);
    let archive = build_zip_with_mode(&[
        (
            "perm-skill/SKILL.md",
            b"---\nname: perm-skill\n---\n",
            0o644,
        ),
        ("perm-skill/scripts/run.sh", b"#!/bin/sh\necho hi\n", 0o755),
    ]);

    manager
        .install_archive_blocking("perm-skill.zip", &archive)
        .expect("install skill archive");

    let metadata = fs::metadata(
        primary
            .path()
            .join(SKILLS_DIR_NAME)
            .join("perm-skill")
            .join("scripts/run.sh"),
    )
    .expect("stat installed script");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o755);
}

#[test]
fn archive_size_limits_reject_entries_above_budget() {
    let mut total = 0;
    let error = enforce_archive_size_limits(MAX_ARCHIVE_ENTRY_BYTES + 1, &mut total, "big.bin")
        .expect_err("large file should fail");
    assert!(error.to_string().contains("per-file limit"));
}

#[test]
fn zip_path_normalizer_rejects_drive_prefixed_paths() {
    let error = normalize_archive_path_string("C:/tmp/evil.sh")
        .expect_err("drive-prefixed paths should fail");
    assert!(error.to_string().contains("absolute paths"));
}

use anyhow::Result;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;

pub(crate) struct TestAuthDir {
    path: PathBuf,
}

impl TestAuthDir {
    pub(crate) fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "codex-gitlab-review-{prefix}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create auth dir");
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestAuthDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn write_skill(
    auth_home: &Path,
    name: &str,
    markdown: &str,
    extra_files: &[(&str, &[u8])],
) -> Result<()> {
    let skill_root = auth_home.join("skills").join(name);
    fs::create_dir_all(&skill_root)?;
    fs::write(skill_root.join("SKILL.md"), markdown)?;
    for (path, contents) in extra_files {
        let full_path = skill_root.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full_path, contents)?;
    }
    Ok(())
}

pub(crate) fn build_skill_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, bytes) in entries {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start skill zip entry");
        writer.write_all(bytes).expect("write skill zip entry");
    }
    writer.finish().expect("finish skill zip").into_inner()
}

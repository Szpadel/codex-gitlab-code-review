use crate::skills::{SkillListSnapshot, SkillPreviewSnapshot, SkillsManager};
use anyhow::Result;

#[derive(Clone)]
pub struct SkillsService {
    skills_manager: SkillsManager,
}

impl SkillsService {
    pub fn new(skills_manager: SkillsManager) -> Self {
        Self { skills_manager }
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn snapshot(&self) -> Result<SkillListSnapshot> {
        self.skills_manager.list_skills().await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn preview_snapshot(&self, name: &str) -> Result<Option<SkillPreviewSnapshot>> {
        self.skills_manager.skill_preview(name).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn install_archive(&self, archive_name: &str, bytes: Vec<u8>) -> Result<String> {
        self.skills_manager
            .install_archive(archive_name, bytes)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn delete_skill(&self, name: &str) -> Result<()> {
        self.skills_manager.delete_skill(name).await
    }
}

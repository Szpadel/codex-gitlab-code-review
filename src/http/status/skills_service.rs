use crate::service_error::ServiceError;
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
    pub async fn snapshot(&self) -> Result<SkillListSnapshot, ServiceError> {
        self.skills_manager
            .list_skills()
            .await
            .map_err(ServiceError::from)
    }

    /// # Errors
    ///
    /// Rejects invalid skill names. Reports filesystem and task failures as internal errors.
    pub async fn preview_snapshot(
        &self,
        name: &str,
    ) -> Result<Option<SkillPreviewSnapshot>, ServiceError> {
        self.skills_manager
            .skill_preview(name)
            .await
            .map_err(ServiceError::from)
    }

    /// # Errors
    ///
    /// Rejects invalid archives or an existing skill. Reports filesystem and task
    /// failures as internal errors.
    pub async fn install_archive(
        &self,
        archive_name: &str,
        bytes: Vec<u8>,
    ) -> Result<String, ServiceError> {
        self.skills_manager
            .install_archive(archive_name, bytes)
            .await
            .map_err(ServiceError::from)
    }

    /// # Errors
    ///
    /// Rejects invalid names or a missing skill. Reports filesystem and task failures
    /// as internal errors.
    pub async fn delete_skill(&self, name: &str) -> Result<(), ServiceError> {
        self.skills_manager
            .delete_skill(name)
            .await
            .map_err(ServiceError::from)
    }
}

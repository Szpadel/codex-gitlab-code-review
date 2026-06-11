use crate::gitlab::{AwardEmoji, GitLabApi};
use anyhow::Result;
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AwardService {
    gitlab: Arc<dyn GitLabApi>,
    bot_user_id: u64,
}

impl AwardService {
    pub(crate) fn new(gitlab: Arc<dyn GitLabApi>, bot_user_id: u64) -> Self {
        Self {
            gitlab,
            bot_user_id,
        }
    }

    pub(crate) async fn has_award(&self, repo: &str, iid: u64, name: &str) -> Result<bool> {
        if self.bot_user_id == 0 {
            return Ok(false);
        }
        let awards = self.gitlab.list_awards(repo, iid).await?;
        Ok(has_bot_award(&awards, self.bot_user_id, name))
    }

    pub(crate) async fn create_award(&self, repo: &str, iid: u64, name: &str) -> Result<()> {
        self.gitlab.add_award(repo, iid, name).await
    }

    pub(crate) async fn ensure_award(&self, repo: &str, iid: u64, name: &str) -> Result<()> {
        if self.bot_user_id == 0 {
            return Ok(());
        }
        if self.has_award(repo, iid, name).await? {
            return Ok(());
        }
        self.gitlab.add_award(repo, iid, name).await
    }

    pub(crate) async fn remove_award(&self, repo: &str, iid: u64, name: &str) -> Result<()> {
        if self.bot_user_id == 0 {
            return Ok(());
        }
        let awards = self.gitlab.list_awards(repo, iid).await?;
        for award in awards {
            if is_bot_award(&award, self.bot_user_id, name) {
                self.gitlab.delete_award(repo, iid, award.id).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn ensure_discussion_note_award(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        if self.bot_user_id == 0 {
            return Ok(());
        }
        let awards = self
            .gitlab
            .list_discussion_note_awards(repo, iid, discussion_id, note_id)
            .await?;
        if awards
            .iter()
            .any(|award| is_bot_award(award, self.bot_user_id, name))
        {
            return Ok(());
        }
        self.gitlab
            .add_discussion_note_award(repo, iid, discussion_id, note_id, name)
            .await
    }

    pub(crate) async fn remove_discussion_note_award(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        if self.bot_user_id == 0 {
            return Ok(());
        }
        let awards = self
            .gitlab
            .list_discussion_note_awards(repo, iid, discussion_id, note_id)
            .await?;
        for award in awards {
            if is_bot_award(&award, self.bot_user_id, name) {
                self.gitlab
                    .delete_discussion_note_award(repo, iid, discussion_id, note_id, award.id)
                    .await?;
            }
        }
        Ok(())
    }
}

fn has_bot_award(awards: &[AwardEmoji], bot_user_id: u64, name: &str) -> bool {
    awards
        .iter()
        .any(|award| is_bot_award(award, bot_user_id, name))
}

fn is_bot_award(award: &AwardEmoji, bot_user_id: u64, name: &str) -> bool {
    award.user.id == bot_user_id && award.name == name
}

#[cfg(test)]
mod tests {
    use super::AwardService;
    use crate::gitlab::{
        AwardEmoji, GitLabApi, GitLabProject, GitLabProjectSummary, GitLabUser, MergeRequest, Note,
    };
    use anyhow::{Result, anyhow, bail};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct AwardRecordingGitLab {
        bot_user: GitLabUser,
        awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
        add_award_calls: Mutex<Vec<String>>,
        delete_award_calls: Mutex<Vec<u64>>,
    }

    impl AwardRecordingGitLab {
        fn new(bot_user_id: u64) -> Self {
            Self {
                bot_user: GitLabUser {
                    id: bot_user_id,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
                awards: Mutex::new(HashMap::new()),
                add_award_calls: Mutex::new(Vec::new()),
                delete_award_calls: Mutex::new(Vec::new()),
            }
        }

        fn add_award_call_count(&self, repo: &str, iid: u64, award_name: &str) -> usize {
            let expected = format!("add_award:{repo}:{iid}:{award_name}");
            self.add_award_calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| *call == &expected)
                .count()
        }

        fn delete_award_call_count(&self) -> usize {
            self.delete_award_calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl GitLabApi for AwardRecordingGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            Ok(self.bot_user.clone())
        }

        async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_group_projects(&self, _group: &str) -> Result<Vec<GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
            Ok(Vec::new())
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<MergeRequest>> {
            Ok(None)
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
            Err(anyhow!("get_mr is not used by this test"))
        }

        async fn get_project(&self, project: &str) -> Result<GitLabProject> {
            Ok(GitLabProject {
                path_with_namespace: Some(project.to_string()),
                web_url: None,
                default_branch: None,
                last_activity_at: None,
            })
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            Ok(self
                .awards
                .lock()
                .unwrap()
                .get(&(project.to_string(), iid))
                .cloned()
                .unwrap_or_default())
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.add_award_calls
                .lock()
                .unwrap()
                .push(format!("add_award:{project}:{iid}:{name}"));
            let mut awards = self.awards.lock().unwrap();
            let entry = awards.entry((project.to_string(), iid)).or_default();
            entry.push(AwardEmoji {
                id: entry.len() as u64 + 1,
                name: name.to_string(),
                user: self.bot_user.clone(),
            });
            Ok(())
        }

        async fn delete_award(&self, _project: &str, _iid: u64, award_id: u64) -> Result<()> {
            self.delete_award_calls.lock().unwrap().push(award_id);
            Ok(())
        }

        async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<Note>> {
            Ok(Vec::new())
        }

        async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
            bail!("create_note is not used by this test")
        }
    }

    #[tokio::test]
    async fn ensure_award_does_not_duplicate_existing_bot_award() -> Result<()> {
        let gitlab = Arc::new(AwardRecordingGitLab::new(1));
        let service = AwardService::new(gitlab.clone(), 1);

        service.ensure_award("group/repo", 42, "eyes").await?;
        service.ensure_award("group/repo", 42, "eyes").await?;

        assert_eq!(gitlab.add_award_call_count("group/repo", 42, "eyes"), 1);
        Ok(())
    }

    #[tokio::test]
    async fn remove_award_ignores_missing_bot_award() -> Result<()> {
        let gitlab = Arc::new(AwardRecordingGitLab::new(1));
        let service = AwardService::new(gitlab.clone(), 1);

        service.remove_award("group/repo", 42, "eyes").await?;

        assert_eq!(gitlab.delete_award_call_count(), 0);
        Ok(())
    }
}

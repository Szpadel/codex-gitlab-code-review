use super::*;
use crate::codex_runner::{
    CodexResult, CodexRunner, MentionCommandContext, MentionCommandResult, MentionCommandStatus,
    ReviewContext,
};
use crate::config::{
    CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets,
    McpServerOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ReviewSecurityConfig,
    ScheduleConfig, ServerConfig, TargetSelector,
};
use crate::gitlab::{
    AwardEmoji, GitLabUser, GitLabUserDetail, MergeRequestDiff, MergeRequestDiffDiscussion,
    MergeRequestDiffVersion, MergeRequestDiscussion, Note,
};
use crate::lifecycle::ServiceLifecycle;
use crate::state::{
    ReviewRateLimitBucketMode, ReviewRateLimitRuleUpsert, ReviewRateLimitScope,
    ReviewRateLimitTarget, ReviewRateLimitTargetKind,
};
use anyhow::anyhow;
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

pub(super) struct FakeGitLab {
    pub(super) bot_user: GitLabUser,
    pub(super) mrs: Mutex<Vec<MergeRequest>>,
    pub(super) awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
    pub(super) notes: Mutex<HashMap<(String, u64), Vec<Note>>>,
    pub(super) discussions: Mutex<HashMap<(String, u64), Vec<MergeRequestDiscussion>>>,
    pub(super) users: Mutex<HashMap<u64, GitLabUserDetail>>,
    pub(super) projects: Mutex<HashMap<String, String>>,
    pub(super) all_projects: Mutex<Vec<String>>,
    pub(super) group_projects: Mutex<HashMap<String, Vec<String>>>,
    pub(super) calls: Mutex<Vec<String>>,
    pub(super) list_open_calls: Mutex<u32>,
    pub(super) list_projects_calls: Mutex<u32>,
    pub(super) list_group_projects_calls: Mutex<u32>,
    pub(super) delete_award_fails: bool,
}

#[async_trait]
impl GitLabApi for FakeGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        Ok(self.bot_user.clone())
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        *self.list_projects_calls.lock().unwrap() += 1;
        let projects = self.all_projects.lock().unwrap().clone();
        Ok(projects
            .into_iter()
            .map(|path| crate::gitlab::GitLabProjectSummary {
                path_with_namespace: path,
                archived: false,
                marked_for_deletion_on: None,
                marked_for_deletion_at: None,
            })
            .collect())
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        *self.list_group_projects_calls.lock().unwrap() += 1;
        let map = self.group_projects.lock().unwrap();
        let projects = map.get(group).cloned().unwrap_or_default();
        Ok(projects
            .into_iter()
            .map(|path| crate::gitlab::GitLabProjectSummary {
                path_with_namespace: path,
                archived: false,
                marked_for_deletion_on: None,
                marked_for_deletion_at: None,
            })
            .collect())
    }

    async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
        *self.list_open_calls.lock().unwrap() += 1;
        Ok(self.mrs.lock().unwrap().clone())
    }

    async fn get_latest_open_mr_activity(&self, _project: &str) -> Result<Option<MergeRequest>> {
        let mrs = self.mrs.lock().unwrap();
        let mut latest: Option<MergeRequest> = None;
        for mr in mrs.iter() {
            let candidate_time = mr.updated_at.or(mr.created_at);
            let Some(candidate_time) = candidate_time else {
                continue;
            };
            match latest.as_ref() {
                Some(existing) => {
                    let existing_time = existing.updated_at.or(existing.created_at);
                    let replace = match existing_time {
                        Some(existing_time) => {
                            candidate_time > existing_time
                                || (candidate_time == existing_time && mr.iid > existing.iid)
                        }
                        None => true,
                    };
                    if replace {
                        latest = Some(mr.clone());
                    }
                }
                None => latest = Some(mr.clone()),
            }
        }
        Ok(latest)
    }

    async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
        let mrs = self.mrs.lock().unwrap();
        let found = mrs
            .iter()
            .find(|mr| mr.iid == _iid)
            .cloned()
            .ok_or_else(|| anyhow!("mr not found"))?;
        Ok(found)
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        let map = self.projects.lock().unwrap();
        let mapped = map.get(project).cloned();
        Ok(crate::gitlab::GitLabProject {
            path_with_namespace: mapped
                .as_deref()
                .filter(|value| value.contains('/'))
                .map(ToOwned::to_owned)
                .or_else(|| Some(project.to_string())),
            web_url: None,
            default_branch: None,
            last_activity_at: mapped.filter(|value| !value.contains('/')),
        })
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        let map = self.awards.lock().unwrap();
        Ok(map
            .get(&(project.to_string(), iid))
            .cloned()
            .unwrap_or_default())
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("add_award:{project}:{iid}:{name}"));
        Ok(())
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        if self.delete_award_fails {
            return Err(anyhow!("delete failed"));
        }
        self.calls
            .lock()
            .unwrap()
            .push(format!("delete_award:{project}:{iid}:{award_id}"));
        Ok(())
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        let map = self.notes.lock().unwrap();
        Ok(map
            .get(&(project.to_string(), iid))
            .cloned()
            .unwrap_or_default())
    }

    async fn create_note(&self, project: &str, iid: u64, _body: &str) -> Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("create_note:{project}:{iid}"));
        Ok(())
    }

    async fn list_discussions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        let map = self.discussions.lock().unwrap();
        Ok(map
            .get(&(project.to_string(), iid))
            .cloned()
            .unwrap_or_default())
    }

    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        _body: &str,
    ) -> Result<()> {
        self.calls.lock().unwrap().push(format!(
            "create_discussion_note:{project}:{iid}:{discussion_id}"
        ));
        Ok(())
    }

    async fn list_discussion_note_awards(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        let calls = self.calls.lock().unwrap();
        let add_prefix =
            format!("add_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:");
        let delete_prefix =
            format!("delete_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:");
        let added_emoji = calls
            .iter()
            .rev()
            .find_map(|call| call.strip_prefix(&add_prefix).map(ToOwned::to_owned));
        let has_delete = calls.iter().any(|call| call.starts_with(&delete_prefix));
        if let Some(name) = added_emoji.filter(|_| !has_delete) {
            return Ok(vec![AwardEmoji {
                id: note_id + 10_000,
                name,
                user: self.bot_user.clone(),
            }]);
        }
        Ok(Vec::new())
    }

    async fn add_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        self.calls.lock().unwrap().push(format!(
            "add_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:{name}"
        ));
        Ok(())
    }

    async fn delete_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        self.calls.lock().unwrap().push(format!(
            "delete_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:{award_id}"
        ));
        Ok(())
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        self.users
            .lock()
            .unwrap()
            .get(&user_id)
            .cloned()
            .ok_or_else(|| anyhow!("user not found"))
    }
}

pub(super) struct InlineReviewGitLab {
    pub(super) inner: Arc<FakeGitLab>,
    pub(super) diff_versions: Vec<MergeRequestDiffVersion>,
    pub(super) diffs: Vec<MergeRequestDiff>,
    pub(super) list_discussions_error: Option<String>,
    pub(super) create_diff_discussion_error: Option<String>,
    pub(super) created_note_bodies: Mutex<Vec<String>>,
    pub(super) created_diff_discussions: Mutex<Vec<MergeRequestDiffDiscussion>>,
}

impl InlineReviewGitLab {
    pub(super) fn new(
        inner: Arc<FakeGitLab>,
        diff_versions: Vec<MergeRequestDiffVersion>,
        diffs: Vec<MergeRequestDiff>,
    ) -> Self {
        Self {
            inner,
            diff_versions,
            diffs,
            list_discussions_error: None,
            create_diff_discussion_error: None,
            created_note_bodies: Mutex::new(Vec::new()),
            created_diff_discussions: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn with_list_discussions_error(mut self, message: &str) -> Self {
        self.list_discussions_error = Some(message.to_string());
        self
    }

    pub(super) fn with_create_diff_discussion_error(mut self, message: &str) -> Self {
        self.create_diff_discussion_error = Some(message.to_string());
        self
    }

    pub(super) fn created_note_bodies(&self) -> Vec<String> {
        self.created_note_bodies.lock().unwrap().clone()
    }

    pub(super) fn created_diff_discussions(&self) -> Vec<MergeRequestDiffDiscussion> {
        self.created_diff_discussions.lock().unwrap().clone()
    }
}

#[async_trait]
impl GitLabApi for InlineReviewGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.inner.current_user().await
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_projects().await
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_group_projects(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.inner.list_open_mrs(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.inner.get_latest_open_mr_activity(project).await
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        self.inner.get_mr(project, iid).await
    }

    async fn list_mr_diff_versions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        Ok(self.diff_versions.clone())
    }

    async fn list_mr_diffs(&self, _project: &str, _iid: u64) -> Result<Vec<MergeRequestDiff>> {
        Ok(self.diffs.clone())
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        self.inner.get_project(project).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.inner.list_awards(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.inner.add_award(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.inner.delete_award(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.inner.list_notes(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.created_note_bodies
            .lock()
            .unwrap()
            .push(body.to_string());
        self.inner.create_note(project, iid, body).await
    }

    async fn create_diff_discussion(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        if let Some(message) = &self.create_diff_discussion_error {
            return Err(anyhow!(message.clone()));
        }
        self.created_diff_discussions
            .lock()
            .unwrap()
            .push(request.clone());
        self.inner
            .calls
            .lock()
            .unwrap()
            .push(format!("create_diff_discussion:{project}:{iid}"));
        Ok(())
    }

    async fn list_discussions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        if let Some(message) = &self.list_discussions_error {
            return Err(anyhow!(message.clone()));
        }
        self.inner.list_discussions(project, iid).await
    }

    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        self.inner
            .create_discussion_note(project, iid, discussion_id, body)
            .await
    }

    async fn list_discussion_note_awards(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        self.inner
            .list_discussion_note_awards(project, iid, discussion_id, note_id)
            .await
    }

    async fn add_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        self.inner
            .add_discussion_note_award(project, iid, discussion_id, note_id, name)
            .await
    }

    async fn delete_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        self.inner
            .delete_discussion_note_award(project, iid, discussion_id, note_id, award_id)
            .await
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        self.inner.get_user(user_id).await
    }
}

pub(super) struct FakeRunner {
    pub(super) result: Mutex<Option<CodexResult>>,
    pub(super) calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for FakeRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.calls.lock().unwrap() += 1;
        Ok(self
            .result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(CodexResult::Pass {
                summary: "ok".to_string(),
            }))
    }
}

pub(super) struct CapturingReviewRunner {
    pub(super) result: Mutex<Option<CodexResult>>,
    pub(super) review_contexts: Mutex<Vec<ReviewContext>>,
}

#[async_trait]
impl CodexRunner for CapturingReviewRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        self.review_contexts.lock().unwrap().push(ctx);
        Ok(self
            .result
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(CodexResult::Pass {
                summary: "ok".to_string(),
            }))
    }
}

pub(super) struct FailingRunner {
    pub(super) calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for FailingRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.calls.lock().unwrap() += 1;
        Err(anyhow!("runner failed"))
    }
}

pub(super) struct BlockingReviewRunner {
    pub(super) first_started: Arc<tokio::sync::Notify>,
    pub(super) release_first: Arc<tokio::sync::Notify>,
    pub(super) review_calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for BlockingReviewRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        let call_index = {
            let mut review_calls = self.review_calls.lock().unwrap();
            *review_calls += 1;
            *review_calls
        };
        if call_index == 1 {
            self.first_started.notify_waiters();
            self.release_first.notified().await;
        }
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }
}

pub(super) struct MentionRunner {
    pub(super) mention_calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for MentionRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }

    async fn run_mention_command(
        &self,
        _ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        *self.mention_calls.lock().unwrap() += 1;
        Ok(MentionCommandResult {
            status: MentionCommandStatus::Committed,
            commit_sha: Some("deadbeef".to_string()),
            reply_message: "Implemented and committed deadbeef".to_string(),
        })
    }
}

pub(super) struct BlockingMentionRunner {
    pub(super) first_started: Arc<tokio::sync::Notify>,
    pub(super) release_first: Arc<tokio::sync::Notify>,
    pub(super) mention_calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for BlockingMentionRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }

    async fn run_mention_command(
        &self,
        _ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        let call_index = {
            let mut mention_calls = self.mention_calls.lock().unwrap();
            *mention_calls += 1;
            *mention_calls
        };
        if call_index == 1 {
            self.first_started.notify_waiters();
            self.release_first.notified().await;
        }
        Ok(MentionCommandResult {
            status: MentionCommandStatus::NoChanges,
            commit_sha: None,
            reply_message: "No code changes required.".to_string(),
        })
    }
}

pub(super) struct MentionAndReviewCounterRunner {
    pub(super) mention_calls: Mutex<u32>,
    pub(super) review_calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for MentionAndReviewCounterRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.review_calls.lock().unwrap() += 1;
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }

    async fn run_mention_command(
        &self,
        _ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        *self.mention_calls.lock().unwrap() += 1;
        Ok(MentionCommandResult {
            status: MentionCommandStatus::NoChanges,
            commit_sha: None,
            reply_message: "No code changes required.".to_string(),
        })
    }
}

pub(super) struct RecoveryRunner {
    pub(super) stop_calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for RecoveryRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        Err(anyhow!("run_review should not be called in recovery test"))
    }

    async fn stop_active_reviews(&self) -> Result<()> {
        *self.stop_calls.lock().unwrap() += 1;
        Ok(())
    }
}

pub(super) struct ShutdownTriggerRunner {
    pub(super) lifecycle: Arc<ServiceLifecycle>,
    pub(super) calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for ShutdownTriggerRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.calls.lock().unwrap() += 1;
        self.lifecycle.request_fast_stop();
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }
}

pub(super) struct GracefulDrainTriggerRunner {
    pub(super) lifecycle: Arc<ServiceLifecycle>,
    pub(super) calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for GracefulDrainTriggerRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.calls.lock().unwrap() += 1;
        self.lifecycle.request_graceful_drain();
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }
}

pub(super) struct ShutdownOnEyesAwardGitLab {
    pub(super) inner: Arc<FakeGitLab>,
    pub(super) lifecycle: Arc<ServiceLifecycle>,
    pub(super) eyes_emoji: String,
}

#[async_trait]
impl GitLabApi for ShutdownOnEyesAwardGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.inner.current_user().await
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_projects().await
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_group_projects(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.inner.list_open_mrs(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.inner.get_latest_open_mr_activity(project).await
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        self.inner.get_mr(project, iid).await
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        self.inner.get_project(project).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.inner.list_awards(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        if name == self.eyes_emoji {
            self.lifecycle.request_fast_stop();
        }
        self.inner.add_award(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.inner.delete_award(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.inner.list_notes(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.inner.create_note(project, iid, body).await
    }
}

pub(super) struct ShutdownOnListOpenGitLab {
    pub(super) inner: Arc<FakeGitLab>,
    pub(super) signal_open: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl GitLabApi for ShutdownOnListOpenGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.inner.current_user().await
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_projects().await
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_group_projects(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.signal_open.notify_waiters();
        self.inner.list_open_mrs(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.inner.get_latest_open_mr_activity(project).await
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        self.inner.get_mr(project, iid).await
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        self.inner.get_project(project).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.inner.list_awards(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.inner.add_award(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.inner.delete_award(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.inner.list_notes(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.inner.create_note(project, iid, body).await
    }
}

pub(super) struct ShutdownOnListAwardsGitLab {
    pub(super) inner: Arc<FakeGitLab>,
    pub(super) lifecycle: Arc<ServiceLifecycle>,
}

#[async_trait]
impl GitLabApi for ShutdownOnListAwardsGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.inner.current_user().await
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_projects().await
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_group_projects(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.inner.list_open_mrs(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.inner.get_latest_open_mr_activity(project).await
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        self.inner.get_mr(project, iid).await
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        self.inner.get_project(project).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.lifecycle.request_fast_stop();
        self.inner.list_awards(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.inner.add_award(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.inner.delete_award(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.inner.list_notes(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.inner.create_note(project, iid, body).await
    }
}

pub(super) struct RefreshedMentionGitLab {
    pub(super) inner: Arc<FakeGitLab>,
    pub(super) refreshed_mr: MergeRequest,
}

#[async_trait]
impl GitLabApi for RefreshedMentionGitLab {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.inner.current_user().await
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_projects().await
    }

    async fn list_group_projects(
        &self,
        group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        self.inner.list_group_projects(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.inner.list_open_mrs(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.inner.get_latest_open_mr_activity(project).await
    }

    async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
        Ok(self.refreshed_mr.clone())
    }

    async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
        self.inner.get_project(project).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.inner.list_awards(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.inner.add_award(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.inner.delete_award(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.inner.list_notes(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.inner.create_note(project, iid, body).await
    }

    async fn list_discussions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        self.inner.list_discussions(project, iid).await
    }

    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        self.inner
            .create_discussion_note(project, iid, discussion_id, body)
            .await
    }

    async fn list_discussion_note_awards(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        self.inner
            .list_discussion_note_awards(project, iid, discussion_id, note_id)
            .await
    }

    async fn add_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        self.inner
            .add_discussion_note_award(project, iid, discussion_id, note_id, name)
            .await
    }

    async fn delete_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        self.inner
            .delete_discussion_note_award(project, iid, discussion_id, note_id, award_id)
            .await
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        self.inner.get_user(user_id).await
    }
}

pub(super) fn test_config() -> Config {
    Config {
        feature_flags: crate::feature_flags::FeatureFlagDefaults::default(),
        gitlab: GitLabConfig {
            base_url: "https://gitlab.example.com".to_string(),
            token: "token".to_string(),
            bot_user_id: Some(1),
            created_after: None,
            targets: GitLabTargets {
                repos: TargetSelector::List(vec!["group/repo".to_string()]),
                ..Default::default()
            },
        },
        schedule: ScheduleConfig {
            cron: "* * * * *".to_string(),
            timezone: None,
        },
        review: ReviewConfig {
            max_concurrent: 1,
            eyes_emoji: "eyes".to_string(),
            thumbs_emoji: "thumbsup".to_string(),
            rate_limit_emoji: "hourglass_flowing_sand".to_string(),
            comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
            stale_in_progress_minutes: 60,
            dry_run: false,
            additional_developer_instructions: None,
            security: ReviewSecurityConfig::default(),
            mention_commands: ReviewMentionCommandsConfig::default(),
        },
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 300,
            auth_host_path: "/root/.codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: Vec::new(),
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: crate::config::DepsConfig { enabled: false },
            browser_mcp: crate::config::BrowserMcpConfig::default(),
            work_tmpfs: crate::config::WorkTmpfsConfig::default(),
            gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            session_overrides: crate::config::SessionOverridesConfig::default(),
            reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
        },
        docker: DockerConfig {
            host: "tcp://localhost:2375".to_string(),
        },
        database: DatabaseConfig {
            path: ":memory:".to_string(),
        },
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            status_ui_enabled: false,
        },
    }
}

pub(super) fn fake_gitlab(mrs: Vec<MergeRequest>) -> Arc<FakeGitLab> {
    Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(mrs),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    })
}

pub(super) fn default_created_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime")
}

pub(super) fn default_created_after() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0)
        .single()
        .expect("valid datetime")
}

pub(super) fn mr(iid: u64, sha: &str) -> MergeRequest {
    mr_with_created_at(iid, sha, default_created_at())
}

pub(super) fn mr_with_created_at(iid: u64, sha: &str, created_at: DateTime<Utc>) -> MergeRequest {
    MergeRequest {
        iid,
        title: None,
        web_url: None,
        draft: false,
        created_at: Some(created_at),
        updated_at: Some(created_at),
        sha: Some(sha.to_string()),
        source_branch: None,
        target_branch: None,
        author: Some(GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        }),
        source_project_id: Some(1),
        target_project_id: Some(1),
        diff_refs: None,
    }
}

pub(super) fn review_rate_limit_rule(
    id: &str,
    label: &str,
    spec: ReviewRateLimitRuleSpec<'_>,
) -> ReviewRateLimitRuleUpsert {
    ReviewRateLimitRuleUpsert {
        id: Some(id.to_string()),
        label: label.to_string(),
        scope: spec.scope,
        targets: vec![ReviewRateLimitTarget {
            kind: ReviewRateLimitTargetKind::Repo,
            path: spec.scope_repo.to_string(),
        }],
        bucket_mode: ReviewRateLimitBucketMode::Shared,
        scope_iid: spec.scope_iid,
        applies_to_review: spec.applies_to_review,
        applies_to_security: spec.applies_to_security,
        capacity: spec.capacity,
        window_seconds: spec.window_seconds,
    }
}

pub(super) struct ReviewRateLimitRuleSpec<'a> {
    pub(super) scope: ReviewRateLimitScope,
    pub(super) scope_repo: &'a str,
    pub(super) scope_iid: Option<u64>,
    pub(super) applies_to_review: bool,
    pub(super) applies_to_security: bool,
    pub(super) capacity: u32,
    pub(super) window_seconds: u64,
}

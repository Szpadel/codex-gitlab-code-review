use super::*;
use crate::codex_runner::{
    CodexResult, CodexRunner, DockerCodexRunner, MentionCommandContext, MentionCommandResult,
    MentionCommandStatus, ReviewContext, RunnerRuntimeOptions,
    test_support::{FakeRunnerHarness, ScriptedAppChunk, ScriptedAppRequest, ScriptedAppServer},
};
use crate::config::{
    CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets,
    McpServerOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ReviewSecurityConfig,
    ScheduleConfig, ServerConfig, TargetSelector,
};
use crate::dev_mode::{DevToolsService, MockCodexRunner};
use crate::flow::mention::{contains_mention, extract_parent_chain};
use crate::flow::review::{RetryKey, ReviewRunContext};
use crate::gitlab::{
    AwardEmoji, DiscussionNote, GitLabUser, GitLabUserDetail, MergeRequestDiff,
    MergeRequestDiffDiscussion, MergeRequestDiffVersion, MergeRequestDiscussion, Note,
};
use crate::lifecycle::ServiceLifecycle;
use crate::state::{
    ReviewRateLimitBucketMode, ReviewRateLimitRuleUpsert, ReviewRateLimitScope,
    ReviewRateLimitTarget, ReviewRateLimitTargetKind,
};
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use pretty_assertions::assert_eq;
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Mutex;

struct FakeGitLab {
    bot_user: GitLabUser,
    mrs: Mutex<Vec<MergeRequest>>,
    awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
    notes: Mutex<HashMap<(String, u64), Vec<Note>>>,
    discussions: Mutex<HashMap<(String, u64), Vec<MergeRequestDiscussion>>>,
    users: Mutex<HashMap<u64, GitLabUserDetail>>,
    projects: Mutex<HashMap<String, String>>,
    all_projects: Mutex<Vec<String>>,
    group_projects: Mutex<HashMap<String, Vec<String>>>,
    calls: Mutex<Vec<String>>,
    list_open_calls: Mutex<u32>,
    list_projects_calls: Mutex<u32>,
    list_group_projects_calls: Mutex<u32>,
    delete_award_fails: bool,
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

struct InlineReviewGitLab {
    inner: Arc<FakeGitLab>,
    diff_versions: Vec<MergeRequestDiffVersion>,
    diffs: Vec<MergeRequestDiff>,
    list_discussions_error: Option<String>,
    create_diff_discussion_error: Option<String>,
    created_note_bodies: Mutex<Vec<String>>,
    created_diff_discussions: Mutex<Vec<MergeRequestDiffDiscussion>>,
}

impl InlineReviewGitLab {
    fn new(
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

    fn with_list_discussions_error(mut self, message: &str) -> Self {
        self.list_discussions_error = Some(message.to_string());
        self
    }

    fn with_create_diff_discussion_error(mut self, message: &str) -> Self {
        self.create_diff_discussion_error = Some(message.to_string());
        self
    }

    fn created_note_bodies(&self) -> Vec<String> {
        self.created_note_bodies.lock().unwrap().clone()
    }

    fn created_diff_discussions(&self) -> Vec<MergeRequestDiffDiscussion> {
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

struct FakeRunner {
    result: Mutex<Option<CodexResult>>,
    calls: Mutex<u32>,
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

struct CapturingReviewRunner {
    result: Mutex<Option<CodexResult>>,
    review_contexts: Mutex<Vec<ReviewContext>>,
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

struct FailingRunner {
    calls: Mutex<u32>,
}

#[async_trait]
impl CodexRunner for FailingRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        *self.calls.lock().unwrap() += 1;
        Err(anyhow!("runner failed"))
    }
}

struct BlockingReviewRunner {
    first_started: Arc<tokio::sync::Notify>,
    release_first: Arc<tokio::sync::Notify>,
    review_calls: Mutex<u32>,
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

struct MentionRunner {
    mention_calls: Mutex<u32>,
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

struct BlockingMentionRunner {
    first_started: Arc<tokio::sync::Notify>,
    release_first: Arc<tokio::sync::Notify>,
    mention_calls: Mutex<u32>,
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

struct MentionAndReviewCounterRunner {
    mention_calls: Mutex<u32>,
    review_calls: Mutex<u32>,
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

struct RecoveryRunner {
    stop_calls: Mutex<u32>,
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

struct ShutdownTriggerRunner {
    lifecycle: Arc<ServiceLifecycle>,
    calls: Mutex<u32>,
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

struct GracefulDrainTriggerRunner {
    lifecycle: Arc<ServiceLifecycle>,
    calls: Mutex<u32>,
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

struct ShutdownOnEyesAwardGitLab {
    inner: Arc<FakeGitLab>,
    lifecycle: Arc<ServiceLifecycle>,
    eyes_emoji: String,
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

struct ShutdownOnListOpenGitLab {
    inner: Arc<FakeGitLab>,
    signal_open: Arc<tokio::sync::Notify>,
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

struct ShutdownOnListAwardsGitLab {
    inner: Arc<FakeGitLab>,
    lifecycle: Arc<ServiceLifecycle>,
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

struct RefreshedMentionGitLab {
    inner: Arc<FakeGitLab>,
    refreshed_mr: MergeRequest,
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

fn test_config() -> Config {
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

fn fake_gitlab(mrs: Vec<MergeRequest>) -> Arc<FakeGitLab> {
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

fn default_created_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime")
}

fn default_created_after() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0)
        .single()
        .expect("valid datetime")
}

fn mr(iid: u64, sha: &str) -> MergeRequest {
    mr_with_created_at(iid, sha, default_created_at())
}

fn mr_with_created_at(iid: u64, sha: &str, created_at: DateTime<Utc>) -> MergeRequest {
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

fn review_rate_limit_rule(
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

struct ReviewRateLimitRuleSpec<'a> {
    scope: ReviewRateLimitScope,
    scope_repo: &'a str,
    scope_iid: Option<u64>,
    applies_to_review: bool,
    applies_to_security: bool,
    capacity: u32,
    window_seconds: u64,
}

#[tokio::test]
async fn scan_once_with_fake_runtime_runner_posts_review_comment() -> Result<()> {
    let config = test_config();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(vec![mr(41, "sha41")]),
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
    });
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", serde_json::json!({})),
        ScriptedAppRequest::result(
            "thread/start",
            serde_json::json!({ "thread": { "id": "thread-41" } }),
        ),
        ScriptedAppRequest::result(
            "review/start",
            serde_json::json!({
                "turn": { "id": "turn-41" },
                "reviewThreadId": "thread-41",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "turn/started",
                "params": { "threadId": "thread-41", "turnId": "turn-41" }
            })),
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-41",
                    "turnId": "turn-41",
                    "item": {
                        "id": "review-item-41",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"comment\",\"summary\":\"needs changes\",\"comment_markdown\":\"- scan-level check\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-41",
                    "turnId": "turn-41",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let runner = Arc::new(DockerCodexRunner::new_with_test_runtime(
        config.codex.clone(),
        url::Url::parse("https://gitlab.example.com").expect("url"),
        Arc::clone(&state),
        None,
        RunnerRuntimeOptions {
            gitlab_token: config.gitlab.token.clone(),
            log_all_json: false,
            owner_id: state.get_or_create_review_owner_id().await?,
            mention_commands_active: false,
            review_additional_developer_instructions: None,
        },
        harness.clone(),
    ));
    let service = ReviewService::new(
        config.clone(),
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:41:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:41"))
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:41:thumbsup")
    );
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_post_inline_discussions_and_fallback_note() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(42, "sha42");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/42".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha42".to_string(),
            base_commit_sha: "base42".to_string(),
            start_commit_sha: "start42".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,2 @@\n-old\n+new\n+extra\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some(
                    "Overall see /work/repo/group/repo/src/other.rs:8 for fallback context."
                        .to_string(),
                ),
                overall_confidence_score: None,
                findings: vec![
                    crate::codex_runner::ReviewFinding {
                        title: "Inline finding".to_string(),
                        body: "Please fix /work/repo/group/repo/src/lib.rs:10 before merging."
                            .to_string(),
                        confidence_score: None,
                        priority: None,
                        code_location: crate::codex_runner::ReviewCodeLocation {
                            absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                            line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                        },
                    },
                    crate::codex_runner::ReviewFinding {
                        title: "Fallback finding".to_string(),
                        body: "This remains unresolved near /work/repo/group/repo/src/other.rs:8."
                            .to_string(),
                        confidence_score: None,
                        priority: None,
                        code_location: crate::codex_runner::ReviewCodeLocation {
                            absolute_file_path: "/work/repo/group/repo/src/other.rs".to_string(),
                            line_range: crate::codex_runner::ReviewLineRange { start: 8, end: 8 },
                        },
                    },
                ],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let inline_discussions = gitlab.created_diff_discussions();
    assert_eq!(inline_discussions.len(), 1);
    assert!(inline_discussions[0].body.contains("Inline finding"));
    assert!(
        inline_discussions[0]
            .body
            .contains("https://gitlab.example.com/group/repo/-/blob/sha42/src/lib.rs#L10")
    );

    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("Overall see"));
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha42/src/other.rs#L8")
    );
    assert!(fallback_notes[0].contains("<!-- codex-review:sha=sha42 -->"));

    let calls = inner.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_diff_discussion:group/repo:42")
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:42"))
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_plain_note_when_no_diff_anchor_exists() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(43, "sha43");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/43".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha43".to_string(),
            base_commit_sha: "base43".to_string(),
            start_commit_sha: "start43".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/unrelated.rs".to_string(),
            new_path: "src/unrelated.rs".to_string(),
            diff: "@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback only".to_string(),
                    body: "See /work/repo/group/repo/src/lib.rs:30 for the broken call."
                        .to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 30, end: 30 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha43/src/lib.rs#L30")
    );
    assert!(fallback_notes[0].contains("[src/lib.rs:30]"));
    Ok(())
}

#[tokio::test]
async fn completed_review_state_skips_same_sha_without_note_marker() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(44, "sha44")]);
    gitlab.discussions.lock().unwrap().insert(
        ("group/repo".to_string(), 44),
        vec![MergeRequestDiscussion {
            id: "discussion-44".to_string(),
            notes: vec![DiscussionNote {
                id: 1,
                body: "<!-- codex-review-finding:sha=sha44 key=deadbeef -->".to_string(),
                author: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            }],
        }],
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 44,
            head_sha: "sha44".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    let outcome = service.scan_once().await?;

    assert_eq!(outcome, ScanRunStatus::Completed);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("add_award:group/repo:44"))
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:44"))
    );
    Ok(())
}

#[tokio::test]
async fn legacy_dry_run_comment_history_without_gitlab_markers_does_not_skip_same_sha() -> Result<()>
{
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(441, "sha441")]);
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 441,
            head_sha: "sha441".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    Ok(())
}

#[tokio::test]
async fn completed_inline_review_state_skips_when_discussion_lookup_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let inner = fake_gitlab(vec![mr(442, "sha442")]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(Arc::clone(&inner), Vec::new(), Vec::new())
            .with_list_discussions_error("discussions unavailable"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 442,
            head_sha: "sha442".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn errored_review_state_does_not_skip_same_sha() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(45, "sha45")]);
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 45,
            head_sha: "sha45".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "error".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:45:thumbsup")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_when_head_sha_no_longer_matches_latest_diff() -> Result<()>
{
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(46, "sha46");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/46".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "newer-sha".to_string(),
            base_commit_sha: "base46".to_string(),
            start_commit_sha: "start46".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Head moved".to_string(),
                    body: "See /work/repo/group/repo/src/lib.rs:10 before merging.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha46/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_use_matching_diff_version_even_when_not_first() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(47, "sha47");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/47".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![
            MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "stale-sha".to_string(),
                base_commit_sha: "base-stale".to_string(),
                start_commit_sha: "start-stale".to_string(),
            },
            MergeRequestDiffVersion {
                id: 2,
                head_commit_sha: "sha47".to_string(),
                base_commit_sha: "base47".to_string(),
                start_commit_sha: "start47".to_string(),
            },
        ],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Inline finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(gitlab.created_diff_discussions().len(), 1);
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_note_when_marker_prefetch_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(48, "sha48");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/48".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(
            Arc::clone(&inner),
            vec![MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "sha48".to_string(),
                base_commit_sha: "base48".to_string(),
                start_commit_sha: "start48".to_string(),
            }],
            vec![MergeRequestDiff {
                old_path: "src/lib.rs".to_string(),
                new_path: "src/lib.rs".to_string(),
                diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
                new_file: false,
                deleted_file: false,
                renamed_file: false,
                collapsed: false,
                too_large: false,
            }],
        )
        .with_list_discussions_error("discussions unavailable"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("[src/lib.rs:10-10]"));
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha48/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_note_when_inline_post_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(49, "sha49");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/49".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(
            Arc::clone(&inner),
            vec![MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "sha49".to_string(),
                base_commit_sha: "base49".to_string(),
                start_commit_sha: "start49".to_string(),
            }],
            vec![MergeRequestDiff {
                old_path: "src/lib.rs".to_string(),
                new_path: "src/lib.rs".to_string(),
                diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
                new_file: false,
                deleted_file: false,
                renamed_file: false,
                collapsed: false,
                too_large: false,
            }],
        )
        .with_create_diff_discussion_error("invalid position"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some("Overall context.".to_string()),
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("Overall context."));
    assert!(fallback_notes[0].contains("[src/lib.rs:10-10]"));
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_use_source_project_links_for_fork_mrs() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(50, "sha50");
    merge_request.web_url =
        Some("https://gitlab.example.com/target/repo/-/merge_requests/50".to_string());
    merge_request.source_project_id = Some(123);
    merge_request.target_project_id = Some(456);
    let inner = fake_gitlab(vec![merge_request]);
    inner
        .projects
        .lock()
        .unwrap()
        .insert("123".to_string(), "fork/source".to_string());
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha50".to_string(),
            base_commit_sha: "base50".to_string(),
            start_commit_sha: "start50".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/unrelated.rs".to_string(),
            new_path: "src/unrelated.rs".to_string(),
            diff: "@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some("See /work/repo/fork/source/src/lib.rs:10.".to_string()),
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fork fallback".to_string(),
                    body: "Fix /work/repo/fork/source/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/fork/source/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/fork/source/-/blob/sha50/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn skips_when_thumbsup_exists() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(1, "sha1")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 1),
            vec![AwardEmoji {
                id: 10,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn skips_when_comment_marker_exists() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let marker = format!("{}sha1 -->", config.review.comment_marker_prefix);
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(2, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 2),
            vec![Note {
                id: 99,
                body: format!("Review\n\n{}", marker),
                author: bot_user,
            }],
        )])),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn skips_when_created_before_cutoff() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let created_at = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let cutoff = Utc
        .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr_with_created_at(5, "sha1", created_at)]),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab.clone(), state, runner.clone(), 1, cutoff);

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn dry_run_skips_writes() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(3, "sha1")]),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn dry_run_completion_does_not_block_followup_real_review_for_same_sha() -> Result<()> {
    let mut dry_run_config = test_config();
    dry_run_config.review.dry_run = true;
    dry_run_config.feature_flags.gitlab_inline_review_comments = true;
    let mut live_config = test_config();
    live_config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(47, "sha47")]);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);

    let dry_run_runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let dry_run_service = ReviewService::new(
        dry_run_config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        Arc::clone(&state),
        dry_run_runner,
        1,
        default_created_after(),
    );
    dry_run_service.scan_once().await?;
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);

    let live_runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let live_service = ReviewService::new(
        live_config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        live_runner.clone(),
        1,
        default_created_after(),
    );

    live_service.scan_once().await?;

    assert_eq!(*live_runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:47:thumbsup")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_dedupe_duplicate_findings_in_single_response() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(48, "sha48");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/48".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha48".to_string(),
            base_commit_sha: "base48".to_string(),
            start_commit_sha: "start48".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let finding = crate::codex_runner::ReviewFinding {
        title: "Duplicate".to_string(),
        body: "See /work/repo/group/repo/src/lib.rs:10.".to_string(),
        confidence_score: None,
        priority: None,
        code_location: crate::codex_runner::ReviewCodeLocation {
            absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
            line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
        },
    };
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![finding.clone(), finding],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(gitlab.created_diff_discussions().len(), 1);
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

#[tokio::test]
async fn review_history_insert_failure_releases_review_lock() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(40, "sha40")]),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(service.scan_once().await.is_err());
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert!(state.list_in_progress_reviews().await?.is_empty());
    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(40i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result.as_deref(), Some("error"));
    Ok(())
}

#[tokio::test]
async fn error_backoff_skips_repeat_and_no_error_comment() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(6, "sha1")]),
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
    });
    let runner = Arc::new(FailingRunner {
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;
    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap();
    assert!(calls.iter().all(|call| !call.starts_with("create_note:")));
    Ok(())
}

#[tokio::test]
async fn fork_reviews_use_source_project_path_for_runner_context() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::List(vec!["target/repo".to_string()]);
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut fork_mr = mr(12, "sha1");
    fork_mr.source_project_id = Some(42);
    fork_mr.target_project_id = Some(7);
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![fork_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "42".to_string(),
            "forks/source-repo".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    let _ = service.scan_once().await?;

    let contexts = runner.review_contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].repo, "target/repo");
    assert_eq!(contexts[0].project_path, "forks/source-repo");
    Ok(())
}

#[tokio::test]
async fn security_reviews_use_canonical_project_path_for_runner_context() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::List(vec!["target/repo".to_string()]);
    config.feature_flags.security_review = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut fork_mr = mr(12, "sha1");
    fork_mr.source_project_id = Some(42);
    fork_mr.target_project_id = Some(7);
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![fork_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "42".to_string(),
            "forks/source-repo".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    let _ = service.scan_once().await?;

    {
        let contexts = runner.review_contexts.lock().unwrap();
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts
                .iter()
                .find(|ctx| ctx.lane == crate::review_lane::ReviewLane::General)
                .map(|ctx| ctx.project_path.as_str()),
            Some("forks/source-repo")
        );
        assert_eq!(
            contexts
                .iter()
                .find(|ctx| ctx.lane == crate::review_lane::ReviewLane::Security)
                .map(|ctx| ctx.project_path.as_str()),
            Some("target/repo")
        );
    }
    let run_kinds = service
        .state
        .list_run_history_for_mr("target/repo", 12)
        .await?
        .into_iter()
        .map(|record| record.kind)
        .collect::<Vec<_>>();
    assert!(run_kinds.contains(&crate::state::RunHistoryKind::Review));
    assert!(run_kinds.contains(&crate::state::RunHistoryKind::Security));
    Ok(())
}

#[test]
fn retry_backoff_doubles_delay() {
    let backoff = RetryBackoff::new(Duration::hours(1));
    let key = RetryKey::new(
        crate::review_lane::ReviewLane::General,
        "group/repo",
        1,
        "sha1",
    );
    let start = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");

    let next_first = backoff.record_failure(key.clone(), start);
    assert_eq!(next_first, start + Duration::hours(1));

    let next_second = backoff.record_failure(key.clone(), next_first);
    assert_eq!(next_second, next_first + Duration::hours(2));

    let state = backoff.state_for(&key).expect("backoff state");
    assert_eq!(state.failures, 2);
}

#[tokio::test]
async fn incremental_skips_when_activity_unchanged() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(10, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "group/repo".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let activity_marker = format!("{}|{}", default_created_at().to_rfc3339(), 10);
    state
        .set_project_last_mr_activity("group/repo", &activity_marker)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn incremental_scans_when_activity_changes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(11, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "group/repo".to_string(),
            "2025-01-02T00:00:00Z".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        11
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 1);
    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let stored = state.get_project_last_mr_activity("group/repo").await?;
    let current_marker = format!("{}|{}", default_created_at().to_rfc3339(), 11);
    assert_eq!(stored, Some(current_marker));
    Ok(())
}

#[tokio::test]
async fn incremental_does_not_advance_marker_when_repo_scan_is_interrupted() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(12, "sha12")]),
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
    });
    let signal_open = Arc::new(tokio::sync::Notify::new());
    let gitlab = Arc::new(ShutdownOnListOpenGitLab {
        inner: Arc::clone(&base_gitlab),
        signal_open: Arc::clone(&signal_open),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        12
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    ));
    let drain_service = Arc::clone(&service);
    tokio::spawn(async move {
        signal_open.notified().await;
        drain_service.request_graceful_drain();
    });

    service.scan_once_incremental().await?;

    assert_eq!(*base_gitlab.list_open_calls.lock().unwrap(), 1);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let stored = state.get_project_last_mr_activity("group/repo").await?;
    assert_eq!(stored, Some(previous_marker));
    Ok(())
}

#[tokio::test]
async fn incremental_uses_cached_project_catalog() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::All;
    config.gitlab.targets.refresh_seconds = 3600;

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(vec!["group/ignored".to_string()]),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let cache_key = config.gitlab.targets.cache_key_for_all();
    state
        .save_project_catalog(&cache_key, &["group/repo".to_string()])
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 0);
    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn incremental_refreshes_project_catalog_when_expired() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::All;
    config.gitlab.targets.refresh_seconds = 0;

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(vec!["group/fresh".to_string()]),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let cache_key = config.gitlab.targets.cache_key_for_all();
    state
        .save_project_catalog(&cache_key, &["group/stale".to_string()])
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 1);
    let loaded = state
        .load_project_catalog(&cache_key)
        .await?
        .expect("catalog");
    assert_eq!(loaded.projects, vec!["group/fresh".to_string()]);
    Ok(())
}

#[tokio::test]
async fn incremental_scan_returns_before_blocking_review_finishes() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let review_mr = mr(40, "sha40");
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![review_mr]),
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
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        40
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    let scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), scan_task).await???;
    assert_eq!(scan_status, ScanRunStatus::Completed);

    let in_progress = state.list_in_progress_reviews().await?;
    assert_eq!(in_progress.len(), 1);
    assert_eq!(in_progress[0].iid, 40);
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);

    release_first.notify_waiters();
    for _ in 0..50 {
        if state.list_in_progress_reviews().await?.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(state.list_in_progress_reviews().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn second_incremental_scan_returns_while_first_review_holds_only_permit() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(70, "sha70");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![first_mr.clone()]),
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
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        70
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab.clone(),
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let first_scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    let first_scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task).await???;
    assert_eq!(first_scan_status, ScanRunStatus::Completed);

    let mut second_mr = mr(71, "sha71");
    second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr];

    let second_scan_status = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        service.scan_once_incremental(),
    )
    .await??;
    assert_eq!(second_scan_status, ScanRunStatus::Completed);

    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    let review_iids: Vec<i64> =
        sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(review_iids, vec![70, 71]);
    let in_progress = state.list_in_progress_reviews().await?;
    assert_eq!(in_progress.len(), 2);

    release_first.notify_waiters();
    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 2
            && state.list_in_progress_reviews().await?.is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 2);
    assert!(state.list_in_progress_reviews().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn queued_reviews_are_heartbeated_across_incremental_scans() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.review.stale_in_progress_minutes = 0;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(80, "sha80");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let mut second_mr = mr(81, "sha81");
    second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![first_mr.clone(), second_mr.clone()]),
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
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        80
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab.clone(),
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let first_scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    let first_scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task).await???;
    assert_eq!(first_scan_status, ScanRunStatus::Completed);

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let mut third_mr = mr(82, "sha82");
    third_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
    *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr, third_mr];

    let second_scan_status = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        service.scan_once_incremental(),
    )
    .await??;
    assert_eq!(second_scan_status, ScanRunStatus::Completed);

    let run_counts: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT iid, COUNT(*) FROM run_history WHERE kind = 'review' GROUP BY iid ORDER BY iid",
    )
    .fetch_all(state.pool())
    .await?;
    assert_eq!(run_counts, vec![(80, 1), (81, 1), (82, 1)]);

    release_first.notify_waiters();
    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 3
            && state.list_in_progress_reviews().await?.is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 3);
    assert!(state.list_in_progress_reviews().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn incremental_defers_same_mr_mentions_while_active_mention_blocks_review() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let mut busy_mr = mr(41, "sha41");
    busy_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    let mut other_mr = mr(42, "sha42");
    other_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![busy_mr, other_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![MergeRequestDiscussion {
                id: "discussion-41".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 1040,
                        body: "bot context".to_string(),
                        author: bot_user.clone(),
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1041,
                        body: "@botuser first request".to_string(),
                        author: requester.clone(),
                        system: false,
                        in_reply_to_id: Some(1040),
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1042,
                        body: "@botuser second request".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(1040),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        41
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    state
        .begin_mention_command("group/repo", 41, "discussion-41", 1041, "sha41")
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let review_iids: Vec<i64> =
        sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(review_iids, vec![42]);
    let mention_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
            .fetch_one(state.pool())
            .await?;
    assert_eq!(mention_rows, 0);
    let stored = state.get_project_last_mr_activity("group/repo").await?;
    assert_eq!(stored, Some(previous_marker.clone()));

    state
        .finish_mention_command(
            "group/repo",
            41,
            "discussion-41",
            1041,
            "sha41",
            "no_changes",
        )
        .await?;

    service.scan_once_incremental().await?;

    for _ in 0..50 {
        if *runner.mention_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let blocked_review_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'review' AND iid = ?")
            .bind(41i64)
            .fetch_one(state.pool())
            .await?;
    assert_eq!(blocked_review_rows, 0);
    let second_trigger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(41i64)
    .bind("discussion-41")
    .bind(1042i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(second_trigger_rows, 1);
    Ok(())
}

#[tokio::test]
async fn incremental_defers_new_mentions_while_same_mr_review_is_in_progress() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let mut active_review_mr = mr(51, "sha51");
    active_review_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![active_review_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 51),
            vec![MergeRequestDiscussion {
                id: "discussion-51".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 1050,
                        body: "bot context".to_string(),
                        author: bot_user.clone(),
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1051,
                        body: "@botuser please follow up".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(1050),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        51
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    state.begin_review("group/repo", 51, "sha51").await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let mention_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
            .fetch_one(state.pool())
            .await?;
    assert_eq!(mention_rows, 0);
    let stored = state.get_project_last_mr_activity("group/repo").await?;
    assert_eq!(stored, Some(previous_marker.clone()));

    state
        .finish_review("group/repo", 51, "sha51", "pass")
        .await?;

    service.scan_once_incremental().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    for _ in 0..50 {
        if *runner.mention_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let scheduled_trigger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(51i64)
    .bind("discussion-51")
    .bind(1051i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(scheduled_trigger_rows, 1);
    Ok(())
}

#[tokio::test]
async fn review_finishes_when_eye_removal_fails() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(4, "sha1")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 4),
            vec![AwardEmoji {
                id: 55,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
        delete_award_fails: true,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    service.review_mr("group/repo", 4).await?;

    let row = sqlx::query("SELECT status FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(4i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    assert_eq!(status, "done");
    Ok(())
}

#[tokio::test]
async fn scan_skips_review_for_draft_merge_request() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut draft_mr = mr(52, "sha52");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![draft_mr]),
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
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_draft_merge_request_without_reviewing_it() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.review.mention_commands.eyes_emoji = Some("inspect".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let mut draft_mr = mr(53, "sha53");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![draft_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 53),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "review note".to_string(),
                        author: bot_user,
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser question".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn explicit_review_still_runs_for_draft_merge_request() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut draft_mr = mr(54, "sha54");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![draft_mr]),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.review_mr("group/repo", 54).await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_cancels_and_removes_eyes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 20),
            vec![AwardEmoji {
                id: 200,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 20, "sha20").await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:20:200")
    );
    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(20i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_marks_mentions_error_without_review_rows() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
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
    });
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    assert!(
        state
            .begin_mention_command("group/repo", 21, "discussion-1", 901, "sha21")
            .await?
    );
    gitlab
        .calls
        .lock()
        .unwrap()
        .push("add_discussion_note_award:group/repo:21:discussion-1:901:eyes".to_string());
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:21:discussion-1:901:10901"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(21i64)
    .bind("discussion-1")
    .bind(901i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_dry_run_skips_mention_reaction_cleanup() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
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
    });
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    assert!(
        state
            .begin_mention_command("group/repo", 22, "discussion-2", 902, "sha22")
            .await?
    );
    gitlab
        .calls
        .lock()
        .unwrap()
        .push("add_discussion_note_award:group/repo:22:discussion-2:902:eyes".to_string());
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(!calls.iter().any(|call| {
        call.starts_with("delete_discussion_note_award:group/repo:22:discussion-2:902:")
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(22i64)
    .bind("discussion-2")
    .bind(902i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn shutdown_request_skips_new_review_runs() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(21, "sha21")]),
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
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );
    service.request_shutdown();

    service.review_mr("group/repo", 21).await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn scan_once_reports_interrupted_when_shutdown_requested_before_start() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let service = ReviewService::new(
        config,
        Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(Vec::new()),
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
        }),
        Arc::new(ReviewStateStore::new(":memory:").await?),
        Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        }),
        1,
        default_created_after(),
    );
    service.request_shutdown();

    let status = service.scan_once().await?;

    assert_eq!(status, ScanRunStatus::Interrupted);
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_when_shutdown_requested_after_runner_completes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 22),
            vec![AwardEmoji {
                id: 220,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 22, "sha22").await?;
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let runner = Arc::new(ShutdownTriggerRunner {
        lifecycle: Arc::clone(&lifecycle),
        calls: Mutex::new(0),
    });
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(22, "sha22"),
            "sha22",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:22:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:22:220")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:22:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:22"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(22i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_without_starting_runner_when_shutdown_requested_during_eyes_award()
-> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 23),
            vec![AwardEmoji {
                id: 230,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let gitlab = Arc::new(ShutdownOnEyesAwardGitLab {
        inner: Arc::clone(&base_gitlab),
        lifecycle: Arc::clone(&lifecycle),
        eyes_emoji: config.review.eyes_emoji.clone(),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 23, "sha23").await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab,
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(23, "sha23"),
            "sha23",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let calls = base_gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:23:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:23:230")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:23:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:23"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(23i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_when_shutdown_requested_during_eyes_removal() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 24),
            vec![AwardEmoji {
                id: 240,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let gitlab = Arc::new(ShutdownOnListAwardsGitLab {
        inner: Arc::clone(&base_gitlab),
        lifecycle: Arc::clone(&lifecycle),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 24, "sha24").await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab,
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(24, "sha24"),
            "sha24",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = base_gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:24:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:24:240")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:24:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:24"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(24i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_finishes_successfully_when_graceful_drain_starts_after_runner_begins() -> Result<()>
{
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 26),
            vec![AwardEmoji {
                id: 260,
                name: "eyes".to_string(),
                user: bot_user,
            }],
        )])),
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
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 26, "sha26").await?;
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let runner = Arc::new(GracefulDrainTriggerRunner {
        lifecycle: Arc::clone(&lifecycle),
        calls: Mutex::new(0),
    });
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(26, "sha26"),
            "sha26",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:26:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:26:260")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:26:thumbsup")
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(26i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn graceful_drain_cancels_queued_review_without_starting_second_codex_run() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(90, "sha90");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let mut second_mr = mr(91, "sha91");
    second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![first_mr.clone(), second_mr.clone()]),
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
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        90
    );
    state
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let first_scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    let first_scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task).await???;
    assert_eq!(first_scan_status, ScanRunStatus::Completed);
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert_eq!(state.list_in_progress_reviews().await?.len(), 2);

    service.request_graceful_drain();
    release_first.notify_waiters();

    for _ in 0..50 {
        if state.list_in_progress_reviews().await?.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert!(state.list_in_progress_reviews().await?.is_empty());
    let results: Vec<(i64, String)> =
        sqlx::query_as("SELECT iid, result FROM review_state ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(
        results,
        vec![(90, "pass".to_string()), (91, "cancelled".to_string())]
    );
    Ok(())
}

#[tokio::test]
async fn security_inline_review_comments_link_sectioned_references() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let render_sectioned_body = |sections: &[(&str, String)]| -> String {
        sections
            .iter()
            .map(|(label, body)| format!("{label}:\n{body}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    let auth_ref = "`/work/repo/group/repo/src/auth.rs:10`";
    let http_ref = "`/work/repo/group/repo/src/http.rs:22`";
    let finding_body = render_sectioned_body(&[
        ("Summary", format!("Untrusted callers can reach {auth_ref}.")),
        (
            "Severity",
            format!("P1 because {auth_ref} removes the only authorization gate."),
        ),
        (
            "Reproduction",
            format!("Replay the existing request flow and hit {auth_ref}."),
        ),
        (
            "Evidence",
            format!(
                "{auth_ref} returns before the guard and {http_ref} still executes the privileged handler."
            ),
        ),
        (
            "Attack-path analysis",
            "An attacker-controlled request crosses the HTTP boundary, bypasses the role check, and reaches the privileged sink.".to_string(),
        ),
        (
            "Likelihood",
            "High because the endpoint is externally reachable.".to_string(),
        ),
        ("Impact", "Cross-tenant data exposure.".to_string()),
        (
            "Assumptions",
            "The route is reachable to ordinary API clients.".to_string(),
        ),
        (
            "Blindspots",
            format!("Did not validate proxy-specific auth at {http_ref}."),
        ),
    ]);

    let mut merge_request = mr(25, "sha25");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/25".to_string());
    let inner = fake_gitlab(vec![merge_request.clone()]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha25".to_string(),
            base_commit_sha: "base25".to_string(),
            start_commit_sha: "start25".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/auth.rs".to_string(),
            new_path: "src/auth.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "confirmed auth bypass".to_string(),
                overall_explanation: None,
                overall_confidence_score: Some(0.93),
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "[P1] Missing auth guard".to_string(),
                    body: finding_body,
                    confidence_score: Some(0.93),
                    priority: Some(1),
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/auth.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .begin_review_for_lane(
            "group/repo",
            25,
            "sha25",
            crate::review_lane::ReviewLane::Security,
        )
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::Security,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle: Arc::new(ServiceLifecycle::default()),
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            merge_request,
            "sha25",
            crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                security_review: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
            0,
        )
        .await?;

    let inline_discussions = gitlab.created_diff_discussions();
    assert_eq!(inline_discussions.len(), 1);
    let (rendered_body, marker_suffix) = inline_discussions[0]
        .body
        .rsplit_once("\n\n<!-- ")
        .expect("inline finding marker");
    let auth_link =
        "[`src/auth.rs:10`](https://gitlab.example.com/group/repo/-/blob/sha25/src/auth.rs#L10)";
    let http_link =
        "[`src/http.rs:22`](https://gitlab.example.com/group/repo/-/blob/sha25/src/http.rs#L22)";
    let expected_rendered_body = format!(
        "Security finding: [P1] Missing auth guard\n\n{}",
        render_sectioned_body(&[
            ("Summary", format!("Untrusted callers can reach {auth_link}.")),
            (
                "Severity",
                format!("P1 because {auth_link} removes the only authorization gate."),
            ),
            (
                "Reproduction",
                format!("Replay the existing request flow and hit {auth_link}."),
            ),
            (
                "Evidence",
                format!(
                    "{auth_link} returns before the guard and {http_link} still executes the privileged handler."
                ),
            ),
            (
                "Attack-path analysis",
                "An attacker-controlled request crosses the HTTP boundary, bypasses the role check, and reaches the privileged sink.".to_string(),
            ),
            (
                "Likelihood",
                "High because the endpoint is externally reachable.".to_string(),
            ),
            ("Impact", "Cross-tenant data exposure.".to_string()),
            (
                "Assumptions",
                "The route is reachable to ordinary API clients.".to_string(),
            ),
            (
                "Blindspots",
                format!("Did not validate proxy-specific auth at {http_link}."),
            ),
        ])
    );
    assert_eq!(rendered_body, expected_rendered_body);
    assert!(!rendered_body.contains(auth_ref));
    assert!(!rendered_body.contains(http_ref));
    assert!(marker_suffix.starts_with("codex-security-review-finding:sha=sha25 key="));
    assert!(marker_suffix.ends_with(" -->"));
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

#[tokio::test]
async fn security_review_pass_stays_silent() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "no confirmed security issues found".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .begin_review_for_lane(
            "group/repo",
            25,
            "sha25",
            crate::review_lane::ReviewLane::Security,
        )
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::Security,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle: Arc::new(ServiceLifecycle::default()),
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(25, "sha25"),
            "sha25",
            crate::feature_flags::FeatureFlagSnapshot {
                security_review: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(!calls.iter().any(|call| call.contains(":eyes")));
    assert!(!calls.iter().any(|call| call.contains(":thumbsup")));
    assert!(!calls.iter().any(|call| call.starts_with("create_note:")));

    let row = sqlx::query(
        "SELECT status, result FROM review_state WHERE repo = ? AND iid = ? AND lane = ?",
    )
    .bind("group/repo")
    .bind(25i64)
    .bind("security")
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_blocks_same_mr_and_clears_pending_after_success() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    let first = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-old"), "sha26-old")
        .await?;
    let second = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-new"), "sha26-new")
        .await?;
    let third = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-newer"), "sha26-newer")
        .await?;

    assert_eq!(first, crate::flow::review::ReviewScheduleOutcome::Scheduled);
    assert_eq!(
        second,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert_eq!(
        third,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );

    let pending = state.list_review_rate_limit_pending().await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].lane, crate::review_lane::ReviewLane::General);
    assert_eq!(pending[0].repo, "group/repo".to_string());
    assert_eq!(pending[0].iid, 26);
    assert_eq!(pending[0].last_seen_head_sha, "sha26-newer".to_string());
    assert!(pending[0].first_blocked_at <= pending[0].last_blocked_at);
    assert!(pending[0].next_retry_at > pending[0].last_blocked_at);

    state
        .refund_review_rate_limit_buckets(
            &[format!("{rule_id}:repo:group/repo")],
            Utc::now().timestamp(),
        )
        .await?;

    let fourth = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-final"), "sha26-final")
        .await?;
    assert_eq!(
        fourth,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    assert!(state.list_review_rate_limit_pending().await?.is_empty());
    assert_eq!(runner.review_contexts.lock().unwrap().len(), 2);
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_block_adds_configured_mr_award() -> Result<()> {
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let now = Utc::now().timestamp();
    state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 27, now)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(27, "sha27"), "sha27")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "add_award:group/repo:27:hourglass_flowing_sand")
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_block_skips_duplicate_mr_award_when_bot_already_has_it() -> Result<()> {
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 28),
            vec![AwardEmoji {
                id: 280,
                name: "hourglass_flowing_sand".to_string(),
                user: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
            }],
        )])),
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
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let now = Utc::now().timestamp();
    state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 28, now)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(28, "sha28"), "sha28")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call != "add_award:group/repo:28:hourglass_flowing_sand")
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_clear_removes_configured_mr_award_before_review_resumes() -> Result<()>
{
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 29),
            vec![AwardEmoji {
                id: 290,
                name: "hourglass_flowing_sand".to_string(),
                user: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
            }],
        )])),
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
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .upsert_review_rate_limit_pending(
            ReviewLane::General,
            "group/repo",
            29,
            "sha29-old",
            100,
            0,
        )
        .await?;
    state
        .refund_review_rate_limit_buckets(
            &[format!("{rule_id}:repo:group/repo")],
            Utc::now().timestamp(),
        )
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(29, "sha29"), "sha29")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "delete_award:group/repo:29:290")
    );
    assert!(state.list_review_rate_limit_pending().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_applies_general_security_and_shared_rules() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.security_review = true;
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let general_only = state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let security_only = state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "security-only",
            "Security only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: false,
                applies_to_security: true,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let shared = state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "shared",
            "Shared",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: true,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert_eq!(
        service
            .general_review_flow
            .run_for_mr("group/repo", mr(30, "sha30"), "sha30")
            .await?,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    let mut active_rule_ids = state
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?
        .into_iter()
        .map(|bucket| bucket.rule_id)
        .collect::<Vec<_>>();
    active_rule_ids.sort();
    assert_eq!(active_rule_ids, vec![general_only.clone(), shared.clone()]);

    assert_eq!(
        service
            .security_review_flow
            .run_for_mr("group/repo", mr(31, "sha31"), "sha31")
            .await?,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    let mut active_rule_ids = state
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?
        .into_iter()
        .map(|bucket| bucket.rule_id)
        .collect::<Vec<_>>();
    active_rule_ids.sort();
    assert_eq!(active_rule_ids, vec![general_only, security_only, shared]);
    assert_eq!(
        runner
            .review_contexts
            .lock()
            .unwrap()
            .iter()
            .filter(|ctx| ctx.lane == crate::review_lane::ReviewLane::General)
            .count(),
        1
    );
    assert_eq!(
        runner
            .review_contexts
            .lock()
            .unwrap()
            .iter()
            .filter(|ctx| ctx.lane == crate::review_lane::ReviewLane::Security)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_refunds_on_startup_failure() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "startup-failure",
            "Startup failure",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(
        service
            .general_review_flow
            .run_for_mr("group/repo", mr(32, "sha32"), "sha32")
            .await
            .is_err()
    );
    assert!(state.list_review_rate_limit_pending().await?.is_empty());
    assert!(
        state
            .list_active_review_rate_limit_buckets(Utc::now().timestamp())
            .await?
            .is_empty()
    );
    assert!(state.list_in_progress_reviews().await?.is_empty());
    assert!(runner.review_contexts.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn queued_reviews_snapshot_feature_flags_before_runner_start() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/repo".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/shared".to_string()],
        target_groups: Vec::new(),
    }];
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(60, "sha60"), mr(61, "sha61")]),
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
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    for _ in 0..50 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'review'")
                .fetch_one(state.pool())
                .await?;
        if count == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    state
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(false),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;

    let mut snapshots = Vec::new();
    for _ in 0..50 {
        let rows = sqlx::query(
            "SELECT feature_flags_json FROM run_history WHERE kind = 'review' ORDER BY iid",
        )
        .fetch_all(state.pool())
        .await?;
        if rows.len() == 2 {
            snapshots = rows
                .into_iter()
                .map(|row| {
                    let json: String = row.try_get("feature_flags_json")?;
                    let snapshot =
                        serde_json::from_str::<crate::feature_flags::FeatureFlagSnapshot>(&json)?;
                    Ok(snapshot)
                })
                .collect::<Result<Vec<_>>>()?;
            if snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
            {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.gitlab_discovery_mcp)
    );

    release_first.notify_waiters();
    scan_task.await??;
    Ok(())
}

#[test]
fn mention_detection_honors_boundaries() {
    assert!(contains_mention("@botuser please fix", "botuser"));
    assert!(contains_mention("@botuser.", "botuser"));
    assert!(contains_mention("ping (@botuser).", "botuser"));
    assert!(!contains_mention("@botuser2 please fix", "botuser"));
    assert!(!contains_mention("@botuser.example please fix", "botuser"));
    assert!(!contains_mention("emailbotuser@example.com", "botuser"));
}

#[test]
fn extract_parent_chain_uses_reply_chain_when_available() {
    let discussion = MergeRequestDiscussion {
        id: "discussion".to_string(),
        notes: vec![
            DiscussionNote {
                id: 1,
                body: "root".to_string(),
                author: GitLabUser {
                    id: 1,
                    username: Some("a".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            },
            DiscussionNote {
                id: 2,
                body: "reply".to_string(),
                author: GitLabUser {
                    id: 2,
                    username: Some("b".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: Some(1),
                created_at: None,
            },
            DiscussionNote {
                id: 3,
                body: "second reply".to_string(),
                author: GitLabUser {
                    id: 3,
                    username: Some("c".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: Some(2),
                created_at: None,
            },
        ],
    };
    let chain = extract_parent_chain(&discussion, 3).expect("chain");
    assert_eq!(
        chain.iter().map(|note| note.id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn scan_runs_mention_command_for_triggered_discussion_note() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.review.mention_commands.eyes_emoji = Some("inspect".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(30, "sha30")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 30),
            vec![AwardEmoji {
                id: 301,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 30),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 900,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 901,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(900),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:30:discussion-1")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| { call.as_str() == "create_discussion_note:group/repo:30:discussion-1" })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:30:discussion-1:901:inspect"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:30:discussion-1:901:10901"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(30i64)
    .bind("discussion-1")
    .bind(901i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn mention_history_insert_failure_releases_mention_lock() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(41, "sha41")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![AwardEmoji {
                id: 411,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 910,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 911,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(910),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(service.scan_once().await.is_err());
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    assert!(state.list_in_progress_mention_commands().await?.is_empty());
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(41i64)
    .bind("discussion-1")
    .bind(911i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result.as_deref(), Some("error"));
    Ok(())
}

#[tokio::test]
async fn mention_run_history_uses_refreshed_mr_sha() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let inner_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(42, "sha-old")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 42),
            vec![AwardEmoji {
                id: 421,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 42),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let gitlab = Arc::new(RefreshedMentionGitLab {
        inner: Arc::clone(&inner_gitlab),
        refreshed_mr: mr(42, "sha-new"),
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let row = sqlx::query(
        "SELECT head_sha FROM run_history WHERE repo = ? AND iid = ? ORDER BY started_at DESC, id DESC LIMIT 1",
    )
    .bind("group/repo")
    .bind(42i64)
    .fetch_one(state.pool())
    .await?;
    let head_sha: String = row.try_get("head_sha")?;
    assert_eq!(head_sha, "sha-new");
    Ok(())
}

#[tokio::test]
async fn queued_mentions_snapshot_feature_flags_before_runner_start() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/repo".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/shared".to_string()],
        target_groups: Vec::new(),
    }];
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(52, "sha52"), mr(53, "sha53")]),
        awards: Mutex::new(HashMap::from([
            (
                ("group/repo".to_string(), 52),
                vec![AwardEmoji {
                    id: 521,
                    name: "thumbsup".to_string(),
                    user: bot_user.clone(),
                }],
            ),
            (
                ("group/repo".to_string(), 53),
                vec![AwardEmoji {
                    id: 531,
                    name: "thumbsup".to_string(),
                    user: bot_user.clone(),
                }],
            ),
        ])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([
            (
                ("group/repo".to_string(), 52),
                vec![MergeRequestDiscussion {
                    id: "discussion-52".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 952,
                            body: "initial review comment".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 953,
                            body: "@botuser please implement change".to_string(),
                            author: requester.clone(),
                            system: false,
                            in_reply_to_id: Some(952),
                            created_at: None,
                        },
                    ],
                }],
            ),
            (
                ("group/repo".to_string(), 53),
                vec![MergeRequestDiscussion {
                    id: "discussion-53".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 962,
                            body: "initial review comment".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 963,
                            body: "@botuser please implement another change".to_string(),
                            author: requester.clone(),
                            system: false,
                            in_reply_to_id: Some(962),
                            created_at: None,
                        },
                    ],
                }],
            ),
        ])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingMentionRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    for _ in 0..50 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
                .fetch_one(state.pool())
                .await?;
        if count == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    state
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(false),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;

    let mut snapshots = Vec::new();
    for _ in 0..50 {
        let rows = sqlx::query(
            "SELECT feature_flags_json FROM run_history WHERE kind = 'mention' ORDER BY trigger_note_id",
        )
        .fetch_all(state.pool())
        .await?;
        if rows.len() == 2 {
            snapshots = rows
                .into_iter()
                .map(|row| {
                    let json: String = row.try_get("feature_flags_json")?;
                    let snapshot =
                        serde_json::from_str::<crate::feature_flags::FeatureFlagSnapshot>(&json)?;
                    Ok(snapshot)
                })
                .collect::<Result<Vec<_>>>()?;
            if snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
            {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.gitlab_discovery_mcp)
    );

    release_first.notify_waiters();
    scan_task.await??;
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_standalone_discussion_comment() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let standalone_author = GitLabUser {
        id: 42,
        username: Some("reviewer".to_string()),
        name: Some("Reviewer".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(33, "sha33")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 33),
            vec![AwardEmoji {
                id: 331,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 33),
            vec![MergeRequestDiscussion {
                id: "discussion-standalone".to_string(),
                notes: vec![DiscussionNote {
                    id: 930,
                    body: "@botuser please handle this standalone comment".to_string(),
                    author: standalone_author,
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                }],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            42,
            GitLabUserDetail {
                id: 42,
                username: Some("reviewer".to_string()),
                name: Some("Reviewer".to_string()),
                public_email: Some("reviewer@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:33:discussion-standalone")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| {
                call.as_str() == "create_discussion_note:group/repo:33:discussion-standalone"
            })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:33:discussion-standalone:930:eyes"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str()
            == "delete_discussion_note_award:group/repo:33:discussion-standalone:930:10930"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(33i64)
    .bind("discussion-standalone")
    .bind(930i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_reply_from_non_mr_author() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let reviewer = GitLabUser {
        id: 44,
        username: Some("reviewer2".to_string()),
        name: Some("Reviewer Two".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(34, "sha34")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 34),
            vec![AwardEmoji {
                id: 341,
                name: "thumbsup".to_string(),
                user: bot_user.clone(),
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 34),
            vec![MergeRequestDiscussion {
                id: "discussion-reply".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 940,
                        body: "Initial review thread note".to_string(),
                        author: bot_user,
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 941,
                        body: "@botuser please implement this follow-up".to_string(),
                        author: reviewer,
                        system: false,
                        in_reply_to_id: Some(940),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            44,
            GitLabUserDetail {
                id: 44,
                username: Some("reviewer2".to_string()),
                name: Some("Reviewer Two".to_string()),
                public_email: Some("reviewer2@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:34:discussion-reply")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| {
                call.as_str() == "create_discussion_note:group/repo:34:discussion-reply"
            })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:34:discussion-reply:941:eyes"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:34:discussion-reply:941:10941"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(34i64)
    .bind("discussion-reply")
    .bind(941i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn dry_run_skips_mention_commands_and_thread_status_writes() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(31, "sha31")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 31),
            vec![AwardEmoji {
                id: 311,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 31),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 910,
                        body: "review note".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 911,
                        body: "@botuser please implement".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(910),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:31:discussion-1")
    );
    let processed_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(31i64)
    .bind("discussion-1")
    .bind(911i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(processed_count, 0);
    Ok(())
}

#[tokio::test]
async fn mention_runs_even_when_mr_created_before_cutoff() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let created_at = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let cutoff = Utc
        .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr_with_created_at(32, "sha32", created_at)]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 32),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "review note".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser question".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab, state, runner.clone(), 1, cutoff);

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn resolves_targets_with_exclusions() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos =
        TargetSelector::List(vec!["group/keep".to_string(), "group/drop".to_string()]);
    config.gitlab.targets.groups = TargetSelector::List(vec!["group".to_string()]);
    config.gitlab.targets.exclude_repos = vec!["group/drop".to_string()];
    config.gitlab.targets.exclude_groups = vec!["group/exclude".to_string()];

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::from([(
            "group".to_string(),
            vec![
                "group/include".to_string(),
                "group/exclude/project".to_string(),
            ],
        )])),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab, state, runner, 1, default_created_after());

    let repos = service.resolve_repos(ScanMode::Full).await?;

    assert_eq!(
        repos,
        vec!["group/include".to_string(), "group/keep".to_string()]
    );
    Ok(())
}

#[tokio::test]
async fn dev_mode_scan_persists_mocked_run_history_for_synthetic_merge_request() -> Result<()> {
    let config = test_config();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let dev_tools = Arc::new(DevToolsService::new("/tmp/dev-mode.sqlite"));
    dev_tools.simulate_new_mr("demo/group/service-a").await?;
    let first_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing synthetic head sha")?;
    let dynamic_repo_source: Arc<dyn DynamicRepoSource> = dev_tools.clone();
    let service = ReviewService::new(
        config,
        dev_tools.gitlab_api(),
        Arc::clone(&state),
        Arc::new(MockCodexRunner::new(Arc::clone(&state))),
        1,
        default_created_after(),
    )
    .with_dynamic_repo_source(dynamic_repo_source);

    service.scan_once().await?;

    let runs = state
        .list_run_history_for_mr("demo/group/service-a", 1)
        .await?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].head_sha, first_head_sha);
    assert_eq!(runs[0].auth_account_name.as_deref(), Some("dev-mode"));

    let events = state.list_run_history_events(runs[0].id).await?;
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "turn_completed")
    );
    Ok(())
}

#[tokio::test]
async fn dev_mode_incremental_scan_detects_new_commit_on_existing_synthetic_merge_request()
-> Result<()> {
    let config = test_config();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let dev_tools = Arc::new(DevToolsService::new("/tmp/dev-mode.sqlite"));
    dev_tools.simulate_new_mr("demo/group/service-a").await?;
    let first_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing initial synthetic head sha")?;
    let dynamic_repo_source: Arc<dyn DynamicRepoSource> = dev_tools.clone();
    let service = ReviewService::new(
        config,
        dev_tools.gitlab_api(),
        Arc::clone(&state),
        Arc::new(MockCodexRunner::new(Arc::clone(&state))),
        1,
        default_created_after(),
    )
    .with_dynamic_repo_source(dynamic_repo_source);

    service.scan_once().await?;
    dev_tools
        .simulate_new_commit("demo/group/service-a")
        .await?;
    let second_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing updated synthetic head sha")?;

    service.scan_once_incremental().await?;

    let runs = state
        .list_run_history_for_mr("demo/group/service-a", 1)
        .await?;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].head_sha, second_head_sha);
    assert_eq!(runs[1].head_sha, first_head_sha);
    Ok(())
}

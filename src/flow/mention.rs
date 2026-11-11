//! Mention admission, execution, and interrupted-claim recovery.

use crate::codex_runner::{
    CodexQuotaExhausted, MentionCommandContext, MentionCommandResult, MentionCommandStatus,
};
use crate::config::FeatureFlagSnapshot;
use crate::flow::admission::AdmissionHistory;
use crate::flow::award_service::AwardService;
use crate::flow::comment_text::sanitize_comment_text;
use crate::flow::mention_assets::collect_note_image_uploads;
use crate::flow::orchestration::{
    ScheduledTaskContext, finish_task_run_history, task_cancelled_finish, task_error_finish,
};
use crate::flow::run_queue::{JobKey, QueueJob};
use crate::flow::{ActiveMentionKey, FlowShared, MergeRequestFlow};
use crate::gitlab::links::{extract_root_relative_markdown_urls, gitlab_web_base};
use crate::gitlab::{DiscussionNote, GitLabUser, MergeRequest, MergeRequestDiscussion};
use crate::run_history_kind::RunHistoryKind;
use crate::state::{
    InProgressMentionCommand, MentionCommandScanState, MentionQuotaPendingUpsert, NewRunHistory,
    ReviewStateStore, RunHistoryFinish,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use tracing::{debug, info, warn};
use url::Url;

const MENTION_STATE_PERSISTENCE_ATTEMPTS: i32 = 3;

#[derive(Clone, Debug)]
pub(crate) struct MentionTrigger {
    discussion_id: String,
    trigger_note: DiscussionNote,
    parent_chain: Vec<DiscussionNote>,
}

#[derive(Clone, Debug)]
pub(crate) struct RequesterIdentity {
    name: String,
    email: String,
}

/// Mention command that waits in the run queue.
#[derive(Clone, Debug)]
pub(crate) struct QueuedMention {
    repo: String,
    /// MR as the scan saw it. The command reads the MR again when it starts.
    mr: MergeRequest,
    head_sha: String,
    trigger: MentionTrigger,
    command_repo: String,
    /// Command repository and source branch. Commands with one key push to one branch.
    branch_key: String,
}

impl QueuedMention {
    pub(crate) fn discussion_id(&self) -> &str {
        &self.trigger.discussion_id
    }

    pub(crate) fn trigger_note_id(&self) -> u64 {
        self.trigger.trigger_note.id
    }
}

impl QueueJob for QueuedMention {
    fn key(&self) -> JobKey {
        JobKey::Mention {
            repo: self.repo.clone(),
            iid: self.mr.iid,
            discussion_id: self.trigger.discussion_id.clone(),
            trigger_note_id: self.trigger.trigger_note.id,
        }
    }

    fn head_sha(&self) -> &str {
        &self.head_sha
    }

    fn mention_branch(&self) -> Option<&str> {
        Some(&self.branch_key)
    }
}

/// Mention triggers of one MR found by a scan.
#[derive(Debug, Default)]
pub(crate) struct MentionAdmission {
    pub(crate) jobs: Vec<QueuedMention>,
    /// Triggers that already run or have finished.
    pub(crate) skipped_processed: usize,
    /// Triggers that the codex quota blocks. Each one has a pending row.
    pub(crate) quota_blocked: usize,
}

/// Keeps the scheduled claim head even when runner inputs and history use a refreshed head.
#[derive(Clone, Copy, Debug)]
struct MentionRunIdentity<'a> {
    task: &'a ScheduledTaskContext,
    discussion_id: &'a str,
    trigger_note_id: u64,
}

struct PreparedMentionRun {
    task: ScheduledTaskContext,
    requester: RequesterIdentity,
    feature_flags: FeatureFlagSnapshot,
}

/// Claimed mention command with everything needed to run it.
struct MentionExecution {
    command_repo: String,
    mr: MergeRequest,
    trigger: MentionTrigger,
    prepared: PreparedMentionRun,
}

/// Runner completion keeps quota deferral separate from status publication.
struct MentionCompletion {
    state_result: &'static str,
    status_message: Option<String>,
    history_finish: RunHistoryFinish,
}

pub(crate) struct MentionFlow {
    shared: FlowShared,
}

impl MentionFlow {
    pub(crate) fn new(shared: FlowShared) -> Self {
        Self { shared }
    }

    pub(crate) async fn clear_stale_in_progress(&self) -> Result<()> {
        self.shared
            .state
            .mention_commands
            .clear_stale_in_progress_mentions(self.shared.config.review.stale_in_progress_minutes)
            .await
    }

    /// Attempts reaction cleanup and marks interrupted claims as errors. Logs per-claim failures.
    /// Returns an error if the claim list cannot be read.
    pub(crate) async fn recover_in_progress(&self) -> Result<()> {
        let mention_in_progress = self
            .shared
            .state
            .mention_commands
            .list_in_progress_mention_commands()
            .await?;
        if !mention_in_progress.is_empty() {
            info!(
                count = mention_in_progress.len(),
                "recovering interrupted in-progress mention commands"
            );
        }
        let mention_eyes_emoji = self.mention_eyes_emoji();
        for mention in mention_in_progress {
            if self.shared.config.review.dry_run {
                info!(
                    repo = mention.key.repo.as_str(),
                    iid = mention.key.iid,
                    discussion_id = mention.key.discussion_id.as_str(),
                    trigger_note_id = mention.key.trigger_note_id,
                    "dry run: skipping stale mention-command eyes-reaction cleanup during recovery"
                );
            } else {
                self.remove_recovery_mention_eyes_best_effort(&mention, &mention_eyes_emoji)
                    .await;
            }
            self.finish_interrupted_mention_best_effort(&mention).await;
        }
        Ok(())
    }

    /// Logs failed reaction cleanup so recovery still releases the interrupted claim.
    async fn remove_recovery_mention_eyes_best_effort(
        &self,
        mention: &InProgressMentionCommand,
        mention_eyes_emoji: &str,
    ) {
        if let Err(err) = self
            .shared
            .award_service
            .remove_discussion_note_award(
                mention.key.repo.as_str(),
                mention.key.iid,
                mention.key.discussion_id.as_str(),
                mention.key.trigger_note_id,
                mention_eyes_emoji,
            )
            .await
        {
            let error_chain = format!("{err:#}");
            warn!(
                repo = mention.key.repo.as_str(),
                iid = mention.key.iid,
                discussion_id = mention.key.discussion_id.as_str(),
                trigger_note_id = mention.key.trigger_note_id,
                error = %err,
                error_chain = error_chain.as_str(),
                "failed to remove stale mention-command eyes reaction during recovery"
            );
        }
    }

    /// Logs a failed error-state write so recovery can continue with the next claim.
    async fn finish_interrupted_mention_best_effort(&self, mention: &InProgressMentionCommand) {
        if let Err(err) = self
            .shared
            .state
            .mention_commands
            .finish_mention_command(
                mention.key.repo.as_str(),
                mention.key.iid,
                mention.key.discussion_id.as_str(),
                mention.key.trigger_note_id,
                mention.head_sha.as_str(),
                "error",
            )
            .await
        {
            warn!(
                repo = mention.key.repo.as_str(),
                iid = mention.key.iid,
                discussion_id = mention.key.discussion_id.as_str(),
                trigger_note_id = mention.key.trigger_note_id,
                error = %err,
                "failed to mark interrupted mention command as error"
            );
        }
    }

    fn mention_commands_enabled(&self) -> bool {
        self.shared.config.review.mention_commands.enabled
    }

    fn mention_bot_username(&self) -> Option<&str> {
        self.shared
            .config
            .review
            .mention_commands
            .bot_username
            .as_deref()
            .and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
    }

    fn mention_eyes_emoji(&self) -> String {
        self.shared
            .config
            .review
            .mention_commands
            .eyes_emoji
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(self.shared.config.review.eyes_emoji.as_str())
            .to_string()
    }

    async fn ensure_quota_award_best_effort(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) {
        if self.shared.config.review.dry_run {
            return;
        }
        self.add_mention_quota_award_best_effort(repo, iid, discussion_id, trigger_note_id)
            .await;
    }

    async fn remove_quota_award_best_effort(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) {
        if self.shared.config.review.dry_run {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .remove_discussion_note_award(
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                &self.shared.config.review.quota_emoji,
            )
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                discussion_id = discussion_id,
                trigger_note_id,
                error = %err,
                "failed to remove mention quota award"
            );
        }
    }

    fn gitlab_host(&self) -> String {
        Url::parse(&self.shared.config.gitlab.base_url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "gitlab.local".to_string())
    }

    async fn resolve_requester_identity(&self, author: &GitLabUser) -> RequesterIdentity {
        let name = author
            .name
            .clone()
            .or_else(|| author.username.clone())
            .unwrap_or_else(|| format!("GitLab User {}", author.id));
        let fallback_local = sanitize_email_local_part(
            author
                .username
                .as_deref()
                .unwrap_or(&format!("user{}", author.id)),
        );
        let fallback_email = format!("{}@users.noreply.{}", fallback_local, self.gitlab_host());
        let email = match self.shared.gitlab.get_user(author.id).await {
            Ok(detail) => detail
                .public_email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map_or(fallback_email, ToOwned::to_owned),
            Err(err) => {
                warn!(
                    user_id = author.id,
                    error = %err,
                    "failed to load requester public email; using noreply fallback"
                );
                fallback_email
            }
        };
        RequesterIdentity { name, email }
    }

    async fn resolve_mention_command_repo(&self, repo: &str, mr: &MergeRequest) -> Result<String> {
        let Some(source_project_id) = mr.source_project_id else {
            return Err(anyhow!(
                "source project id is missing for MR {} in repo {}",
                mr.iid,
                repo
            ));
        };
        if mr.target_project_id == Some(source_project_id) {
            return Ok(repo.to_string());
        }
        let project = self
            .shared
            .gitlab
            .get_project(&source_project_id.to_string())
            .await
            .with_context(|| {
                format!(
                    "load source project {} for MR {} in repo {}",
                    source_project_id, mr.iid, repo
                )
            })?;
        let Some(path_with_namespace) = project
            .path_with_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Err(anyhow!(
                "source project {} for MR {} has no path_with_namespace",
                source_project_id,
                mr.iid
            ));
        };
        Ok(path_with_namespace.to_string())
    }

    async fn collect_mention_triggers(
        &self,
        repo: &str,
        iid: u64,
        discussions: &[MergeRequestDiscussion],
        bot_username: &str,
        skipped_processed: &mut usize,
    ) -> Result<Vec<MentionTrigger>> {
        let mut triggers = Vec::new();
        for discussion in discussions {
            let mut parent_index = None;
            for (note_index, note) in discussion.notes.iter().enumerate() {
                if note.system
                    || note.author.id == self.shared.bot_user_id
                    || !contains_mention(note.body.as_str(), bot_username)
                {
                    continue;
                }
                match self
                    .shared
                    .state
                    .mention_commands
                    .mention_command_scan_state(repo, iid, &discussion.id, note.id)
                    .await?
                {
                    MentionCommandScanState::InProgress | MentionCommandScanState::Completed => {
                        *skipped_processed += 1;
                        continue;
                    }
                    MentionCommandScanState::Ready => {}
                }
                let index =
                    parent_index.get_or_insert_with(|| DiscussionParentIndex::new(discussion));
                triggers.push(MentionTrigger {
                    discussion_id: discussion.id.clone(),
                    trigger_note: note.clone(),
                    parent_chain: index
                        .chain_through(note_index)
                        .into_iter()
                        .filter(|entry| !entry.system)
                        .collect(),
                });
            }
        }
        Ok(triggers)
    }

    fn build_mention_prompt(
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        trigger: &MentionTrigger,
        gitlab_base_url: &str,
    ) -> String {
        let title = mr
            .title
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("(no title)");
        let url = mr
            .web_url
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("(no url)");
        let target_branch = mr
            .target_branch
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("(unknown)");
        let gitlab_web_base = gitlab_web_base(gitlab_base_url);
        let chain = trigger
            .parent_chain
            .iter()
            .map(|note| {
                let author = note
                    .author
                    .username
                    .as_deref()
                    .or(note.author.name.as_deref())
                    .unwrap_or("unknown");
                let mut entry = format!("note:{} author:{}\n{}", note.id, author, note.body);
                let asset_urls = extract_root_relative_markdown_urls(
                    note.body.as_str(),
                    gitlab_web_base.as_str(),
                );
                if !asset_urls.is_empty() {
                    entry.push_str("\n\nResolved asset URLs:\n");
                    for url in asset_urls {
                        entry.push_str("- ");
                        entry.push_str(url.as_str());
                        entry.push('\n');
                    }
                    entry = entry.trim_end().to_string();
                }
                entry
            })
            .collect::<Vec<_>>()
            .join("\n\n---\n\n");
        format!(
            "You are implementing a GitLab discussion request.\n\n\
             Repository: {repo}\n\
             Merge Request: !{iid}\n\
             MR Title: {title}\n\
             MR URL: {url}\n\
             Head SHA: {head_sha}\n\
             Target Branch: {target_branch}\n\
             Discussion ID: {discussion_id}\n\
             Trigger Note ID: {trigger_note_id}\n\n\
             Scope rules:\n\
             - Use only the parent chain context below.\n\
             - Ignore all other comments and discussions.\n\
             - Apply code changes directly in this repository working tree when needed.\n\
             - If no code changes are needed, answer the request without committing.\n\
             - Do not push to remote.\n\n\
             Parent chain context:\n\n{chain}",
            repo = repo,
            iid = mr.iid,
            title = title,
            url = url,
            head_sha = head_sha,
            target_branch = target_branch,
            discussion_id = trigger.discussion_id,
            trigger_note_id = trigger.trigger_note.id,
            chain = chain
        )
    }

    async fn prepare_mention_run(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        command_repo: &str,
        trigger: &MentionTrigger,
    ) -> Result<PreparedMentionRun> {
        let trigger_note_id = trigger.trigger_note.id;
        let trigger_author_name = trigger
            .trigger_note
            .author
            .name
            .clone()
            .or_else(|| trigger.trigger_note.author.username.clone());
        let run_history_id = match self
            .shared
            .state
            .run_history
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Mention,
                repo: repo.to_string(),
                iid: mr.iid,
                head_sha: head_sha.to_string(),
                discussion_id: Some(trigger.discussion_id.clone()),
                trigger_note_id: Some(trigger_note_id),
                trigger_note_author_name: trigger_author_name,
                trigger_note_body: Some(trigger.trigger_note.body.clone()),
                command_repo: Some(command_repo.to_string()),
            })
            .await
        {
            Ok(run_history_id) => run_history_id,
            Err(err) => {
                self.release_mention_lock_after_history_failure(
                    repo,
                    mr.iid,
                    &trigger.discussion_id,
                    trigger_note_id,
                    head_sha,
                )
                .await;
                return Err(err);
            }
        };
        let task = ScheduledTaskContext::new(repo, mr.iid, head_sha, run_history_id);
        let feature_flags = match self.resolve_feature_flags().await {
            Ok(feature_flags) => feature_flags,
            Err(err) => {
                self.abort_mention_after_setup_failure(
                    MentionRunIdentity {
                        task: &task,
                        discussion_id: &trigger.discussion_id,
                        trigger_note_id,
                    },
                    &err,
                )
                .await;
                return Err(err);
            }
        };
        if let Err(err) = self
            .shared
            .state
            .run_history
            .set_run_history_feature_flags(task.run_history_id, &feature_flags)
            .await
        {
            self.abort_mention_after_setup_failure(
                MentionRunIdentity {
                    task: &task,
                    discussion_id: &trigger.discussion_id,
                    trigger_note_id,
                },
                &err,
            )
            .await;
            return Err(err);
        }
        let requester = self
            .resolve_requester_identity(&trigger.trigger_note.author)
            .await;
        Ok(PreparedMentionRun {
            task,
            requester,
            feature_flags,
        })
    }

    /// Finds unprocessed mention triggers of one MR and returns them as jobs to queue.
    ///
    /// Takes no claim. A codex quota block writes a pending row instead of a job.
    pub(crate) async fn admit_for_scan(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<MentionAdmission> {
        let mut admission = MentionAdmission::default();
        if !self.mention_commands_enabled() {
            return Ok(admission);
        }
        if self.shared.config.review.dry_run {
            info!(
                repo = repo,
                iid = mr.iid,
                "dry run: skipping mention-command trigger processing"
            );
            return Ok(admission);
        }
        let Some(bot_username) = self.mention_bot_username() else {
            warn!("mention commands enabled but bot username unavailable; skipping triggers");
            return Ok(admission);
        };
        if self.shared.shutdown_requested() {
            return Ok(admission);
        }
        // GitLab merge request discussions cover both standalone comments
        // (individual_note discussions) and threaded replies.
        let discussions = history.discussions().await.with_context(|| {
            format!(
                "load discussions for mention commands in {repo} !{}",
                mr.iid
            )
        })?;
        let triggers = self
            .collect_mention_triggers(
                repo,
                mr.iid,
                discussions,
                bot_username,
                &mut admission.skipped_processed,
            )
            .await?;
        let command_repo = self.resolve_mention_command_repo(repo, mr).await?;
        let source_branch = mr
            .source_branch
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("(unknown-source-branch)");
        let branch_key = format!("{command_repo}::{source_branch}");
        for trigger in triggers {
            if self.shared.shutdown_requested() {
                break;
            }
            if self
                .record_quota_block(repo, mr.iid, head_sha, &trigger)
                .await?
            {
                admission.quota_blocked += 1;
                continue;
            }
            admission.jobs.push(QueuedMention {
                repo: repo.to_string(),
                mr: mr.clone(),
                head_sha: head_sha.to_string(),
                trigger,
                command_repo: command_repo.clone(),
                branch_key: branch_key.clone(),
            });
        }
        Ok(admission)
    }

    /// Runs a queued mention command. Holds a run slot for the whole call.
    ///
    /// A failure is logged and makes the next incremental scan read the repository again.
    pub(crate) async fn run_queued(&self, job: QueuedMention) {
        let repo = job.repo.clone();
        let iid = job.mr.iid;
        let trigger_note_id = job.trigger.trigger_note.id;
        if let Err(err) = self.start_queued(job).await {
            warn!(
                repo = repo.as_str(),
                iid,
                trigger_note_id,
                error = %format!("{err:#}"),
                "queued mention command failed"
            );
            self.shared.rescan_requests.request(&repo);
        }
    }

    async fn start_queued(&self, job: QueuedMention) -> Result<()> {
        let QueuedMention {
            repo,
            mr,
            head_sha,
            trigger,
            command_repo,
            ..
        } = job;
        let trigger_note_id = trigger.trigger_note.id;
        if self
            .record_quota_block(&repo, mr.iid, &head_sha, &trigger)
            .await?
        {
            return Ok(());
        }
        if !self
            .shared
            .state
            .mention_commands
            .begin_mention_command(
                &repo,
                mr.iid,
                &trigger.discussion_id,
                trigger_note_id,
                &head_sha,
            )
            .await?
        {
            // A finished command or a run that ended without cleanup holds the claim.
            // The next scan skips a finished trigger and retries after a stale sweep.
            debug!(
                repo = repo.as_str(),
                iid = mr.iid,
                trigger_note_id,
                "skip queued mention command: trigger is already claimed"
            );
            self.shared.rescan_requests.request(&repo);
            return Ok(());
        }
        // Heartbeats keep the claim alive while the command runs.
        let _active_mention = self.shared.active_tasks.track_mention(ActiveMentionKey {
            repo: repo.clone(),
            iid: mr.iid,
            discussion_id: trigger.discussion_id.clone(),
            trigger_note_id,
            head_sha: head_sha.clone(),
        });
        self.clear_quota_pending_at_start(&repo, mr.iid, &trigger)
            .await;
        let prepared = self
            .prepare_mention_run(&repo, &mr, &head_sha, &command_repo, &trigger)
            .await?;
        self.execute_mention(MentionExecution {
            command_repo,
            mr,
            trigger,
            prepared,
        })
        .await;
        Ok(())
    }

    /// Writes a pending row and the quota award when the codex quota blocks the trigger.
    async fn record_quota_block(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        trigger: &MentionTrigger,
    ) -> Result<bool> {
        let now = Utc::now();
        let Some(block) = self.shared.codex.quota_block(now).await? else {
            return Ok(false);
        };
        let trigger_note_id = trigger.trigger_note.id;
        self.shared
            .state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo,
                iid,
                discussion_id: &trigger.discussion_id,
                trigger_note_id,
                head_sha,
                blocked_at: now.timestamp(),
                next_retry_at: block.retry_at.timestamp(),
            })
            .await?;
        self.ensure_quota_award_best_effort(repo, iid, &trigger.discussion_id, trigger_note_id)
            .await;
        Ok(true)
    }

    async fn clear_quota_pending_at_start(&self, repo: &str, iid: u64, trigger: &MentionTrigger) {
        let trigger_note_id = trigger.trigger_note.id;
        match self
            .shared
            .state
            .mention_quota_pending
            .clear_mention_quota_pending(repo, iid, &trigger.discussion_id, trigger_note_id)
            .await
        {
            Ok(true) => {
                self.remove_quota_award_best_effort(
                    repo,
                    iid,
                    &trigger.discussion_id,
                    trigger_note_id,
                )
                .await;
            }
            Ok(false) => {}
            Err(err) => {
                warn!(
                    repo = repo,
                    iid = iid,
                    discussion_id = trigger.discussion_id.as_str(),
                    trigger_note_id,
                    error = %err,
                    "failed to clear mention quota pending row at run start"
                );
            }
        }
    }

    /// Runs a claimed mention command and publishes its result. Logs every failure.
    async fn execute_mention(&self, run: MentionExecution) {
        let MentionExecution {
            command_repo: command_repo_name,
            mr: mr_copy,
            trigger,
            prepared,
        } = run;
        let PreparedMentionRun {
            task: task_for_run_history,
            requester,
            feature_flags,
        } = prepared;
        let run_history_id = task_for_run_history.run_history_id;
        let config = &self.shared.config;
        let eyes_emoji = self.mention_eyes_emoji();
        let gitlab_base_url = gitlab_web_base(&config.gitlab.base_url);
        let discussion_id = trigger.discussion_id.clone();
        let trigger_note_id = trigger.trigger_note.id;
        let context = MentionRunIdentity {
            task: &task_for_run_history,
            discussion_id: &discussion_id,
            trigger_note_id,
        };

        // Refresh runner inputs without changing the head used to release the scheduled claim.
        let effective_mr = self.refresh_mention_mr(context, &mr_copy).await;
        let effective_head_sha = effective_mr
            .head_sha()
            .unwrap_or_else(|| task_for_run_history.head_sha.clone());
        self.refresh_mention_history_head_best_effort(context, &effective_head_sha)
            .await;
        let prompt = MentionFlow::build_mention_prompt(
            &task_for_run_history.repo,
            &effective_mr,
            &effective_head_sha,
            &trigger,
            &gitlab_base_url,
        );
        let image_uploads = collect_note_image_uploads(&trigger.parent_chain, &gitlab_base_url);
        self.add_mention_eyes_best_effort(context, &eyes_emoji)
            .await;

        let command_context = MentionCommandContext {
            repo: command_repo_name.clone(),
            project_path: command_repo_name.clone(),
            discussion_project_path: task_for_run_history.repo.clone(),
            mr: effective_mr,
            head_sha: effective_head_sha.clone(),
            discussion_id: discussion_id.clone(),
            trigger_note_id,
            requester_name: requester.name.clone(),
            requester_email: requester.email.clone(),
            additional_developer_instructions: config
                .review
                .mention_commands
                .additional_developer_instructions
                .clone(),
            prompt,
            image_uploads,
            feature_flags,
            run_history_id: Some(run_history_id),
        };
        // Refresh and reaction setup can observe shutdown before the runner starts.
        if !self.shared.lifecycle.accepts_new_work() {
            MentionFlow::finalize_rejected_start(
                &self.shared.state,
                &self.shared.award_service,
                &eyes_emoji,
                context,
            )
            .await;
            return;
        }
        let _started_run = self.shared.lifecycle.track_started_run();
        let outcome = self.shared.codex.run_mention_command(command_context).await;
        let completion = self.mention_completion(context, outcome).await;

        // Keep history, publication, claim persistence, and reaction cleanup in this order.
        self.finish_mention_history_best_effort(context, completion.history_finish)
            .await;
        if let Some(message) = completion.status_message {
            self.publish_mention_status_best_effort(context, &message)
                .await;
        }
        self.persist_mention_result_best_effort(context, completion.state_result)
            .await;
        self.remove_mention_eyes_best_effort(context, &eyes_emoji)
            .await;
    }

    /// Uses the scheduled snapshot only when GitLab cannot refresh the MR.
    async fn refresh_mention_mr(
        &self,
        context: MentionRunIdentity<'_>,
        snapshot: &MergeRequest,
    ) -> MergeRequest {
        match self
            .shared
            .gitlab
            .get_mr(&context.task.repo, snapshot.iid)
            .await
        {
            Ok(latest) => latest,
            Err(err) => {
                warn!(
                    repo = context.task.repo.as_str(),
                    iid = snapshot.iid,
                    discussion_id = context.discussion_id,
                    trigger_note_id = context.trigger_note_id,
                    error = %err,
                    "failed to refresh MR before mention command; using scheduled snapshot"
                );
                snapshot.clone()
            }
        }
    }

    /// Records a changed runner head without changing the scheduled claim. Logs write failures.
    async fn refresh_mention_history_head_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        head_sha: &str,
    ) {
        if head_sha != context.task.head_sha
            && let Err(err) = self
                .shared
                .state
                .run_history
                .update_run_history_head_sha(context.task.run_history_id, head_sha)
                .await
        {
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                head_sha,
                error = %err,
                "failed to refresh mention run history head sha"
            );
        }
    }

    /// Logs award failures without preventing the runner from starting.
    async fn add_mention_eyes_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        eyes_emoji: &str,
    ) {
        if let Err(err) = self
            .shared
            .award_service
            .ensure_discussion_note_award(
                &context.task.repo,
                context.task.iid,
                context.discussion_id,
                context.trigger_note_id,
                eyes_emoji,
            )
            .await
        {
            let error_chain = format!("{err:#}");
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                error_chain = error_chain.as_str(),
                "failed to add in-progress eyes reaction to mention trigger note"
            );
        }
    }

    /// Converts runner outcomes into history, claim state, and optional status text.
    /// Quota exhaustion records a retry and does not publish a failure note.
    async fn mention_completion(
        &self,
        context: MentionRunIdentity<'_>,
        outcome: Result<MentionCommandResult>,
    ) -> MentionCompletion {
        match outcome {
            Ok(result) => Self::successful_mention_completion(context, result),
            Err(err) => {
                if let Some(quota) = err.downcast_ref::<CodexQuotaExhausted>() {
                    let quota = quota.clone();
                    self.defer_mention_for_runtime_quota(context, &quota).await
                } else {
                    Self::failed_mention_completion(context, &err)
                }
            }
        }
    }

    /// Supplies default reply text and records a commit only for a committed outcome.
    fn successful_mention_completion(
        context: MentionRunIdentity<'_>,
        result: MentionCommandResult,
    ) -> MentionCompletion {
        let (state_result, message, commit_sha) = match result.status {
            MentionCommandStatus::Committed => (
                "committed",
                Self::committed_mention_message(result.reply_message, result.commit_sha.as_deref()),
                result.commit_sha,
            ),
            MentionCommandStatus::NoChanges => (
                "no_changes",
                if result.reply_message.trim().is_empty() {
                    "Mention command completed with no code changes.".to_string()
                } else {
                    result.reply_message
                },
                None,
            ),
        };
        MentionCompletion {
            state_result,
            status_message: Some(message.clone()),
            history_finish: RunHistoryFinish {
                result: state_result.to_string(),
                preview: Some(format!(
                    "Mention {} !{} note {}",
                    context.task.repo, context.task.iid, context.trigger_note_id
                )),
                summary: Some(message),
                commit_sha,
                ..RunHistoryFinish::default()
            },
        }
    }

    /// Appends the commit only when neither its full nor its nonempty short SHA is in the reply.
    fn committed_mention_message(reply_message: String, commit_sha: Option<&str>) -> String {
        let mut message = if reply_message.trim().is_empty() {
            "Mention command completed.".to_string()
        } else {
            reply_message
        };
        if let Some(commit_sha) = commit_sha {
            let short_sha: String = commit_sha.chars().take(7).collect();
            let has_sha = message.contains(commit_sha)
                || (!short_sha.is_empty() && message.contains(short_sha.as_str()));
            if !has_sha {
                let _ = write!(message, "\n\nCommit SHA: `{commit_sha}`");
            }
        }
        message
    }

    /// Logs the execution error and supplies status text without exposing error details to GitLab.
    fn failed_mention_completion(
        context: MentionRunIdentity<'_>,
        err: &anyhow::Error,
    ) -> MentionCompletion {
        let error_chain = format!("{err:#}");
        warn!(
            repo = context.task.repo.as_str(),
            iid = context.task.iid,
            discussion_id = context.discussion_id,
            trigger_note_id = context.trigger_note_id,
            error = %err,
            error_chain = error_chain.as_str(),
            "mention command execution failed"
        );
        MentionCompletion {
            state_result: "error",
            status_message: Some(
                "Mention command failed. Check service logs for details.".to_string(),
            ),
            history_finish: task_error_finish(
                "error",
                format!(
                    "Mention {} !{} note {}",
                    context.task.repo, context.task.iid, context.trigger_note_id
                ),
                err,
            ),
        }
    }

    /// Attempts both pending-state and quota-award writes before returning a retryable completion.
    async fn defer_mention_for_runtime_quota(
        &self,
        context: MentionRunIdentity<'_>,
        quota: &CodexQuotaExhausted,
    ) -> MentionCompletion {
        warn!(
            repo = context.task.repo.as_str(),
            iid = context.task.iid,
            discussion_id = context.discussion_id,
            trigger_note_id = context.trigger_note_id,
            reset_at = %quota.reset_at,
            retry_at = %quota.retry_at,
            "mention command deferred because codex quota is exhausted"
        );
        self.persist_runtime_mention_quota_best_effort(context, quota)
            .await;
        self.add_mention_quota_award_best_effort(
            &context.task.repo,
            context.task.iid,
            context.discussion_id,
            context.trigger_note_id,
        )
        .await;
        let mut finish = task_cancelled_finish(
            "cancelled",
            format!(
                "Mention {} !{} note {}",
                context.task.repo, context.task.iid, context.trigger_note_id
            ),
        );
        finish.summary = Some(format!(
            "deferred: codex quota exhausted until {}",
            quota.reset_at
        ));
        MentionCompletion {
            state_result: "cancelled",
            status_message: None,
            history_finish: finish,
        }
    }

    /// Keeps the scheduled head on the pending row. Logs persistence failures.
    async fn persist_runtime_mention_quota_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        quota: &CodexQuotaExhausted,
    ) {
        let now = Utc::now();
        if let Err(err) = self
            .shared
            .state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: &context.task.repo,
                iid: context.task.iid,
                discussion_id: context.discussion_id,
                trigger_note_id: context.trigger_note_id,
                head_sha: &context.task.head_sha,
                blocked_at: now.timestamp(),
                next_retry_at: quota.retry_at.timestamp(),
            })
            .await
        {
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                "failed to persist mention quota pending row"
            );
        }
    }

    /// Logs quota-award failures. The caller decides whether dry-run mode permits this write.
    async fn add_mention_quota_award_best_effort(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) {
        if let Err(err) = self
            .shared
            .award_service
            .ensure_discussion_note_award(
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                &self.shared.config.review.quota_emoji,
            )
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                discussion_id = discussion_id,
                trigger_note_id,
                error = %err,
                "failed to add mention quota award"
            );
        }
    }

    /// Logs history failures so publication and claim cleanup still run.
    async fn finish_mention_history_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        finish: RunHistoryFinish,
    ) {
        if let Err(err) = finish_task_run_history(&self.shared.state, context.task, finish).await {
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                "failed to persist mention run history"
            );
        }
    }

    /// Uses an MR note if the discussion rejects the completion message. Logs each failure.
    async fn publish_mention_status_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        message: &str,
    ) {
        if !self.post_mention_thread_status(context, message).await {
            self.post_mention_fallback_status_best_effort(context, message)
                .await;
        }
    }

    /// Sanitizes the reply and logs a failed discussion write.
    async fn post_mention_thread_status(
        &self,
        context: MentionRunIdentity<'_>,
        message: &str,
    ) -> bool {
        let message = sanitize_comment_text(&self.shared.config, message);
        match self
            .shared
            .gitlab
            .create_discussion_note(
                &context.task.repo,
                context.task.iid,
                context.discussion_id,
                &message,
            )
            .await
        {
            Ok(()) => true,
            Err(err) => {
                warn!(
                    repo = context.task.repo.as_str(),
                    iid = context.task.iid,
                    discussion_id = context.discussion_id,
                    trigger_note_id = context.trigger_note_id,
                    error = %err,
                    "failed to post mention-command completion status"
                );
                false
            }
        }
    }

    /// Sanitizes a fallback that identifies the failed discussion. Logs a failed MR note write.
    async fn post_mention_fallback_status_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        message: &str,
    ) {
        let fallback_message = format!(
            "Mention command result for discussion `{}`:\n\n{message}",
            context.discussion_id
        );
        let fallback_message = sanitize_comment_text(&self.shared.config, &fallback_message);
        if let Err(err) = self
            .shared
            .gitlab
            .create_note(&context.task.repo, context.task.iid, &fallback_message)
            .await
        {
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                "failed to post fallback MR note for mention-command completion"
            );
        }
    }

    /// Retries after 100 ms and 200 ms. After three failed attempts, tries an error result.
    async fn persist_mention_result_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        result: &str,
    ) {
        for attempt in 1..=MENTION_STATE_PERSISTENCE_ATTEMPTS {
            match self
                .shared
                .state
                .mention_commands
                .finish_mention_command(
                    &context.task.repo,
                    context.task.iid,
                    context.discussion_id,
                    context.trigger_note_id,
                    &context.task.head_sha,
                    result,
                )
                .await
            {
                Ok(()) => return,
                Err(err) if attempt == MENTION_STATE_PERSISTENCE_ATTEMPTS => {
                    self.finalize_mention_persistence_failure(context, &err)
                        .await;
                }
                Err(err) => {
                    Self::warn_mention_persistence_retry(context, attempt, &err);
                    tokio::time::sleep(std::time::Duration::from_millis(
                        100 * u64::try_from(attempt).ok().unwrap_or(u64::MAX),
                    ))
                    .await;
                }
            }
        }
    }

    fn warn_mention_persistence_retry(
        context: MentionRunIdentity<'_>,
        attempt: i32,
        err: &anyhow::Error,
    ) {
        warn!(
            repo = context.task.repo.as_str(),
            iid = context.task.iid,
            discussion_id = context.discussion_id,
            trigger_note_id = context.trigger_note_id,
            attempt,
            error = %err,
            "failed to persist mention-command state; retrying"
        );
    }

    /// Reports exhausted retries before attempting to release the claim with an error result.
    async fn finalize_mention_persistence_failure(
        &self,
        context: MentionRunIdentity<'_>,
        err: &anyhow::Error,
    ) {
        warn!(
            repo = context.task.repo.as_str(),
            iid = context.task.iid,
            discussion_id = context.discussion_id,
            trigger_note_id = context.trigger_note_id,
            error = %err,
            "failed to persist mention-command state"
        );
        self.mark_mention_persistence_error_best_effort(context)
            .await;
    }

    /// Logs a failed final error write without preventing reaction cleanup.
    async fn mark_mention_persistence_error_best_effort(&self, context: MentionRunIdentity<'_>) {
        if let Err(err) = self
            .shared
            .state
            .mention_commands
            .finish_mention_command(
                &context.task.repo,
                context.task.iid,
                context.discussion_id,
                context.trigger_note_id,
                &context.task.head_sha,
                "error",
            )
            .await
        {
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                "failed to mark mention-command state as error after persistence failures"
            );
        }
    }

    /// Attempts cleanup after all completion writes. Logs reaction-removal failures.
    async fn remove_mention_eyes_best_effort(
        &self,
        context: MentionRunIdentity<'_>,
        eyes_emoji: &str,
    ) {
        if let Err(err) = self
            .shared
            .award_service
            .remove_discussion_note_award(
                &context.task.repo,
                context.task.iid,
                context.discussion_id,
                context.trigger_note_id,
                eyes_emoji,
            )
            .await
        {
            let error_chain = format!("{err:#}");
            warn!(
                repo = context.task.repo.as_str(),
                iid = context.task.iid,
                discussion_id = context.discussion_id,
                trigger_note_id = context.trigger_note_id,
                error = %err,
                error_chain = error_chain.as_str(),
                "failed to remove in-progress eyes reaction from mention trigger note"
            );
        }
    }

    async fn release_mention_lock_after_history_failure(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
        head_sha: &str,
    ) {
        if let Err(recovery_err) = self
            .shared
            .state
            .mention_commands
            .finish_mention_command(repo, iid, discussion_id, trigger_note_id, head_sha, "error")
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                discussion_id = discussion_id,
                trigger_note_id = trigger_note_id,
                head_sha = head_sha,
                error = %recovery_err,
                "failed to release mention lock after run history creation error"
            );
        }
    }

    /// Attempts to finish the rejected claim, history, and eyes award. Logs each failure.
    async fn finalize_rejected_start(
        state: &ReviewStateStore,
        award_service: &AwardService,
        eyes_emoji: &str,
        ctx: MentionRunIdentity<'_>,
    ) {
        Self::cancel_rejected_mention_claim_best_effort(state, ctx).await;
        Self::cancel_rejected_mention_history_best_effort(state, ctx).await;
        Self::remove_rejected_mention_eyes_best_effort(award_service, eyes_emoji, ctx).await;
    }

    /// Logs a failed cancellation write without preventing history or reaction cleanup.
    async fn cancel_rejected_mention_claim_best_effort(
        state: &ReviewStateStore,
        ctx: MentionRunIdentity<'_>,
    ) {
        if let Err(err) = state
            .mention_commands
            .finish_mention_command(
                &ctx.task.repo,
                ctx.task.iid,
                ctx.discussion_id,
                ctx.trigger_note_id,
                &ctx.task.head_sha,
                "cancelled",
            )
            .await
        {
            warn!(repo = ctx.task.repo, iid = ctx.task.iid, error = %err,
                "failed to cancel mention claim after shutdown");
        }
    }

    /// Logs a failed history write without preventing reaction cleanup.
    async fn cancel_rejected_mention_history_best_effort(
        state: &ReviewStateStore,
        ctx: MentionRunIdentity<'_>,
    ) {
        if let Err(err) = finish_task_run_history(
            state,
            ctx.task,
            task_cancelled_finish(
                "cancelled",
                format!(
                    "Mention {} !{} note {}",
                    ctx.task.repo, ctx.task.iid, ctx.trigger_note_id
                ),
            ),
        )
        .await
        {
            warn!(repo = ctx.task.repo, iid = ctx.task.iid, error = %err,
                "failed to cancel mention history after shutdown");
        }
    }

    /// Logs a failed reaction removal after shutdown rejects the runner start.
    async fn remove_rejected_mention_eyes_best_effort(
        award_service: &AwardService,
        eyes_emoji: &str,
        ctx: MentionRunIdentity<'_>,
    ) {
        if let Err(err) = award_service
            .remove_discussion_note_award(
                &ctx.task.repo,
                ctx.task.iid,
                ctx.discussion_id,
                ctx.trigger_note_id,
                eyes_emoji,
            )
            .await
        {
            warn!(repo = ctx.task.repo, iid = ctx.task.iid, error = %err,
                "failed to remove mention eyes award after shutdown");
        }
    }

    async fn resolve_feature_flags(&self) -> Result<FeatureFlagSnapshot> {
        let overrides = self
            .shared
            .state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?;
        Ok(self.shared.config.resolve_feature_flags(&overrides))
    }

    async fn abort_mention_after_setup_failure(
        &self,
        ctx: MentionRunIdentity<'_>,
        err: &anyhow::Error,
    ) {
        self.release_mention_lock_after_history_failure(
            &ctx.task.repo,
            ctx.task.iid,
            ctx.discussion_id,
            ctx.trigger_note_id,
            &ctx.task.head_sha,
        )
        .await;
        if let Err(finish_err) = finish_task_run_history(
            &self.shared.state,
            ctx.task,
            task_error_finish(
                "error",
                format!(
                    "Mention {} !{} note {}",
                    ctx.task.repo, ctx.task.iid, ctx.trigger_note_id
                ),
                err,
            ),
        )
        .await
        {
            warn!(
                repo = ctx.task.repo.as_str(),
                iid = ctx.task.iid,
                discussion_id = ctx.discussion_id,
                trigger_note_id = ctx.trigger_note_id,
                error = %finish_err,
                "failed to finalize mention run history after setup failure"
            );
        }
    }
}

#[async_trait]
impl MergeRequestFlow for MentionFlow {
    fn flow_name(&self) -> &'static str {
        "mention"
    }

    async fn clear_stale_in_progress(&self) -> Result<()> {
        MentionFlow::clear_stale_in_progress(self).await
    }

    async fn recover_in_progress(&self) -> Result<()> {
        MentionFlow::recover_in_progress(self).await
    }
}

pub(crate) fn contains_mention(body: &str, username: &str) -> bool {
    let mention = format!("@{}", username.to_ascii_lowercase());
    let body_lower = body.to_ascii_lowercase();
    let bytes = body_lower.as_bytes();
    let mention_bytes = mention.as_bytes();
    let mut start = 0usize;
    while let Some(offset) = body_lower[start..].find(&mention) {
        let idx = start + offset;
        let before_ok = if idx == 0 {
            true
        } else {
            !is_mention_char(bytes[idx - 1] as char)
        };
        let after_idx = idx + mention_bytes.len();
        let after_ok = if after_idx >= bytes.len() {
            true
        } else {
            mention_after_boundary(bytes, after_idx)
        };
        if before_ok && after_ok {
            return true;
        }
        start = idx + mention_bytes.len();
    }
    false
}

fn mention_after_boundary(bytes: &[u8], after_idx: usize) -> bool {
    let ch = bytes[after_idx] as char;
    if !is_mention_char(ch) {
        return true;
    }
    if ch != '.' {
        return false;
    }
    let next_idx = after_idx + 1;
    if next_idx >= bytes.len() {
        return true;
    }
    !is_mention_char(bytes[next_idx] as char)
}

fn is_mention_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'
}

/// Borrows discussion notes so each ready trigger can reuse the parent lookup.
pub(crate) struct DiscussionParentIndex<'a> {
    notes: &'a [DiscussionNote],
    by_id: HashMap<u64, &'a DiscussionNote>,
}

impl<'a> DiscussionParentIndex<'a> {
    pub(crate) fn new(discussion: &'a MergeRequestDiscussion) -> Self {
        Self {
            notes: &discussion.notes,
            by_id: discussion
                .notes
                .iter()
                .map(|note| (note.id, note))
                .collect(),
        }
    }

    /// Uses explicit reply links when present. Otherwise returns the preceding
    /// notes and the trigger. The zero-based index must belong to this discussion.
    /// Stops at a missing parent or a repeated note.
    pub(crate) fn chain_through(&self, trigger_index: usize) -> Vec<DiscussionNote> {
        let trigger_note = &self.notes[trigger_index];
        if trigger_note.in_reply_to_id.is_none() {
            return self.notes[..=trigger_index].to_vec();
        }
        let mut chain = Vec::new();
        let mut current = Some(trigger_note);
        let mut seen = HashSet::new();
        while let Some(note) = current {
            if !seen.insert(note.id) {
                break;
            }
            current = note
                .in_reply_to_id
                .and_then(|parent_id| self.by_id.get(&parent_id).copied());
            chain.push(note.clone());
        }
        chain.reverse();
        chain
    }
}

pub(crate) fn sanitize_email_local_part(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "user".to_string()
    } else {
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::DiffRefs;
    use std::sync::Arc;

    #[tokio::test]
    async fn mention_status_falls_back_and_releases_claim_when_thread_post_fails() -> Result<()> {
        use reqwest::StatusCode;
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_string_contains, method, path},
        };

        // Reject the thread status but accept the MR fallback and eyes cleanup.
        let server = MockServer::start().await;
        let note_path = "/api/v4/projects/group%2Frepo/merge_requests/1/discussions/discussion/notes/2/award_emoji";
        let mocks = [
            Mock::given(method("GET"))
                .and(path(note_path))
                .respond_with(
                    ResponseTemplate::new(StatusCode::OK.as_u16()).set_body_json(json!([
                        {"id": 9, "name": "eyes", "user": {"id": 1}}
                    ])),
                )
                .expect(2),
            Mock::given(method("DELETE"))
                .and(path(format!("{note_path}/9")))
                .respond_with(ResponseTemplate::new(StatusCode::NO_CONTENT.as_u16()))
                .expect(1),
            Mock::given(method("POST"))
                .and(path(
                    "/api/v4/projects/group%2Frepo/merge_requests/1/discussions/discussion/notes",
                ))
                .respond_with(ResponseTemplate::new(StatusCode::BAD_REQUEST.as_u16()))
                .expect(1),
            Mock::given(method("POST"))
                .and(path("/api/v4/projects/group%2Frepo/merge_requests/1/notes"))
                .and(body_string_contains(
                    "Mention command result for discussion `discussion`:",
                ))
                .and(body_string_contains("Mention command failed."))
                .respond_with(
                    ResponseTemplate::new(StatusCode::CREATED.as_u16())
                        .set_body_json(json!({"id": 3})),
                )
                .expect(1),
        ];
        for endpoint in mocks {
            endpoint.mount(&server).await;
        }

        // Run the queued command through the default runner's failure path.
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let gitlab = Arc::new(crate::gitlab::GitLabClient::new(&server.uri(), "token")?);
        let mut config = crate::config::test_builder::ConfigBuilder::for_review_tests().build();
        config.review.eyes_emoji = "eyes".to_string();
        config.review.mention_commands.eyes_emoji = None;
        let flow = MentionFlow::new(FlowShared {
            config,
            gitlab: gitlab.clone(),
            award_service: AwardService::new(gitlab, 1),
            // This runner's default mention method reports an execution error.
            codex: Arc::new(crate::dev_mode::MockCodexRunner::new(state.clone())),
            state: state.clone(),
            bot_user_id: 1,
            created_after: chrono::DateTime::UNIX_EPOCH,
            lifecycle: Arc::default(),
            active_tasks: Arc::default(),
            rescan_requests: Arc::default(),
        });
        let trigger_note: DiscussionNote = serde_json::from_value(json!({
            "id": 2, "body": "@bot check this", "author": {"id": 7}
        }))?;
        flow.run_queued(QueuedMention {
            repo: "group/repo".to_string(),
            mr: serde_json::from_value(json!({"iid": 1, "sha": "sha1"}))?,
            head_sha: "sha1".to_string(),
            trigger: MentionTrigger {
                discussion_id: "discussion".to_string(),
                parent_chain: vec![trigger_note.clone()],
                trigger_note,
            },
            command_repo: "group/repo".to_string(),
            branch_key: "group/repo::feature".to_string(),
        })
        .await;

        // Publication failure must not leave a claim active or prevent reaction cleanup.
        assert!(
            state
                .mention_commands
                .list_in_progress_mention_commands()
                .await?
                .is_empty()
        );
        let history = state
            .run_history
            .list_run_history_for_mr("group/repo", 1)
            .await?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].result.as_deref(), Some("error"));
        assert!(history[0].error.is_some());
        server.verify().await;
        Ok(())
    }

    #[tokio::test]
    async fn processed_mentions_have_no_collected_parent_chains() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .mention_commands
            .begin_mention_command("group/repo", 1, "discussion", 2, "sha1")
            .await?;
        state
            .mention_commands
            .finish_mention_command("group/repo", 1, "discussion", 2, "sha1", "committed")
            .await?;
        let gitlab = Arc::new(crate::gitlab::GitLabClient::new("http://127.0.0.1:9", "")?);
        let flow = MentionFlow::new(FlowShared {
            config: crate::config::test_builder::ConfigBuilder::for_review_tests().build(),
            gitlab: gitlab.clone(),
            award_service: AwardService::new(gitlab, 1),
            codex: Arc::new(crate::dev_mode::MockCodexRunner::new(state.clone())),
            state,
            bot_user_id: 1,
            created_after: chrono::DateTime::UNIX_EPOCH,
            lifecycle: Arc::new(crate::lifecycle::ServiceLifecycle::default()),
            active_tasks: Arc::new(crate::flow::ActiveTaskRegistry::default()),
            rescan_requests: Arc::default(),
        });
        let discussions = vec![MergeRequestDiscussion {
            id: "discussion".to_string(),
            individual_note: true,
            notes: vec![DiscussionNote {
                id: 2,
                body: "@bot check this".to_string(),
                author: GitLabUser {
                    id: 7,
                    username: None,
                    name: None,
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            }],
        }];

        let mut skipped_processed = 0;
        let triggers = flow
            .collect_mention_triggers("group/repo", 1, &discussions, "bot", &mut skipped_processed)
            .await?;

        assert!(triggers.is_empty());
        assert_eq!(skipped_processed, 1);
        Ok(())
    }

    #[test]
    fn build_mention_prompt_absolutizes_gitlab_upload_image_urls() {
        let trigger = MentionTrigger {
            discussion_id: "discussion-1".to_string(),
            trigger_note: DiscussionNote {
                id: 2,
                body: "@botuser please inspect this".to_string(),
                author: GitLabUser {
                    id: 5,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                },
                system: false,
                in_reply_to_id: Some(1),
                created_at: None,
            },
            parent_chain: vec![
                DiscussionNote {
                    id: 1,
                    body: "![shot](/uploads/hash/screenshot.png)".to_string(),
                    author: GitLabUser {
                        id: 4,
                        username: Some("bob".to_string()),
                        name: Some("Bob".to_string()),
                    },
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                },
                DiscussionNote {
                    id: 2,
                    body: "@botuser please inspect this".to_string(),
                    author: GitLabUser {
                        id: 5,
                        username: Some("alice".to_string()),
                        name: Some("Alice".to_string()),
                    },
                    system: false,
                    in_reply_to_id: Some(1),
                    created_at: None,
                },
            ],
        };
        let mr = MergeRequest {
            iid: 7,
            state: Some("opened".to_string()),
            title: Some("Demo".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/7".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("deadbeef".to_string()),
            source_branch: Some("feature".to_string()),
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: Some(DiffRefs {
                base_sha: Some("base".to_string()),
                head_sha: Some("deadbeef".to_string()),
                start_sha: Some("start".to_string()),
            }),
        };

        let prompt = MentionFlow::build_mention_prompt(
            "group/repo",
            &mr,
            "deadbeef",
            &trigger,
            "https://gitlab.example.com/api/v4",
        );

        assert!(prompt.contains("![shot](/uploads/hash/screenshot.png)"));
        assert!(prompt.contains("Resolved asset URLs:"));
        assert!(prompt.contains("https://gitlab.example.com/uploads/hash/screenshot.png"));
    }
}

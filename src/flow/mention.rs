use crate::codex_runner::{MentionCommandContext, MentionCommandResult, MentionCommandStatus};
use crate::flow::{FlowShared, MergeRequestFlow};
use crate::gitlab::{DiscussionNote, GitLabApi, GitLabUser, MergeRequest, MergeRequestDiscussion};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use url::Url;

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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MentionScheduleOutcome {
    pub(crate) scheduled: usize,
    pub(crate) skipped_processed: usize,
    pub(crate) blocks_review: bool,
}

pub(crate) struct MentionFlow {
    shared: FlowShared,
    mention_branch_locks: Arc<Mutex<HashMap<String, Arc<TokioMutex<()>>>>>,
}

impl MentionFlow {
    pub(crate) fn new(
        shared: FlowShared,
        mention_branch_locks: Arc<Mutex<HashMap<String, Arc<TokioMutex<()>>>>>,
    ) -> Self {
        Self {
            shared,
            mention_branch_locks,
        }
    }

    pub(crate) async fn clear_stale_in_progress(&self) -> Result<()> {
        self.shared
            .state
            .clear_stale_in_progress_mentions(self.shared.config.review.stale_in_progress_minutes)
            .await
    }

    pub(crate) async fn recover_in_progress(&self) -> Result<()> {
        let mention_in_progress = self
            .shared
            .state
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
            } else if let Err(err) = remove_eyes_from_discussion_note(
                self.shared.gitlab.as_ref(),
                mention.key.repo.as_str(),
                mention.key.iid,
                mention.key.discussion_id.as_str(),
                mention.key.trigger_note_id,
                self.shared.bot_user_id,
                &mention_eyes_emoji,
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
            if let Err(err) = self
                .shared
                .state
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
        Ok(())
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
                .map(ToOwned::to_owned)
                .unwrap_or(fallback_email),
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

    fn mention_branch_lock(&self, command_repo: &str, source_branch: &str) -> Arc<TokioMutex<()>> {
        let key = format!("{command_repo}::{source_branch}");
        let mut locks = self.mention_branch_locks.lock().unwrap();
        locks
            .entry(key)
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone()
    }

    fn collect_mention_triggers(
        &self,
        discussions: &[MergeRequestDiscussion],
        bot_username: &str,
    ) -> Vec<MentionTrigger> {
        let mut triggers = Vec::new();
        for discussion in discussions {
            for note in &discussion.notes {
                if note.system {
                    continue;
                }
                if note.author.id == self.shared.bot_user_id {
                    continue;
                }
                if !contains_mention(note.body.as_str(), bot_username) {
                    continue;
                }
                if let Some(parent_chain) = extract_parent_chain(discussion, note.id) {
                    let filtered_chain = parent_chain
                        .into_iter()
                        .filter(|entry| !entry.system)
                        .collect::<Vec<_>>();
                    if filtered_chain.is_empty() {
                        continue;
                    }
                    triggers.push(MentionTrigger {
                        discussion_id: discussion.id.clone(),
                        trigger_note: note.clone(),
                        parent_chain: filtered_chain,
                    });
                }
            }
        }
        triggers
    }

    fn build_mention_prompt(
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        trigger: &MentionTrigger,
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
                format!("note:{} author:{}\n{}", note.id, author, note.body)
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

    pub(crate) async fn schedule_for_scan(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        tasks: &mut Vec<JoinHandle<()>>,
    ) -> Result<MentionScheduleOutcome> {
        let mut outcome = MentionScheduleOutcome::default();
        if !self.mention_commands_enabled() {
            return Ok(outcome);
        }
        if self.shared.config.review.dry_run {
            info!(
                repo = repo,
                iid = mr.iid,
                "dry run: skipping mention-command trigger processing"
            );
            return Ok(outcome);
        }
        let Some(bot_username) = self.mention_bot_username() else {
            warn!("mention commands enabled but bot username unavailable; skipping triggers");
            return Ok(outcome);
        };
        if self.shared.shutdown_requested() {
            return Ok(outcome);
        }
        // GitLab merge request discussions cover both standalone comments
        // (individual_note discussions) and threaded replies.
        let discussions = match self.shared.gitlab.list_discussions(repo, mr.iid).await {
            Ok(discussions) => discussions,
            Err(err) => {
                warn!(
                    repo = repo,
                    iid = mr.iid,
                    error = %err,
                    "failed to list MR discussions; skipping mention commands for this MR"
                );
                return Ok(outcome);
            }
        };
        let triggers = self.collect_mention_triggers(&discussions, bot_username);
        let command_repo = match self.resolve_mention_command_repo(repo, mr).await {
            Ok(path) => path,
            Err(err) => {
                warn!(
                    repo = repo,
                    iid = mr.iid,
                    error = %err,
                    "failed to resolve source repository for mention command; skipping triggers"
                );
                return Ok(outcome);
            }
        };
        let mention_eyes_emoji = self.mention_eyes_emoji();
        let additional_developer_instructions = self
            .shared
            .config
            .review
            .mention_commands
            .additional_developer_instructions
            .clone();
        for trigger in triggers {
            if self.shared.shutdown_requested() {
                break;
            }
            let trigger_note_id = trigger.trigger_note.id;
            if !self
                .shared
                .state
                .begin_mention_command(
                    repo,
                    mr.iid,
                    &trigger.discussion_id,
                    trigger_note_id,
                    head_sha,
                )
                .await?
            {
                outcome.skipped_processed += 1;
                continue;
            }
            let source_branch_key = mr
                .source_branch
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("(unknown-source-branch)")
                .to_string();
            let branch_lock = self.mention_branch_lock(&command_repo, &source_branch_key);
            let semaphore = Arc::clone(&self.shared.semaphore);
            let gitlab = Arc::clone(&self.shared.gitlab);
            let codex = Arc::clone(&self.shared.codex);
            let state = Arc::clone(&self.shared.state);
            let shutdown = Arc::clone(&self.shared.shutdown);
            let repo_name = repo.to_string();
            let command_repo_name = command_repo.clone();
            let mr_copy = mr.clone();
            let head_sha_copy = head_sha.to_string();
            let eyes_emoji = mention_eyes_emoji.clone();
            let bot_user_id = self.shared.bot_user_id;
            let additional_developer_instructions = additional_developer_instructions.clone();
            let requester = self
                .resolve_requester_identity(&trigger.trigger_note.author)
                .await;
            outcome.scheduled += 1;
            outcome.blocks_review = true;
            tasks.push(tokio::spawn(async move {
                let _branch_guard = branch_lock.lock().await;
                let Ok(_permit) = semaphore.acquire_owned().await else {
                    warn!(
                        repo = repo_name.as_str(),
                        iid = mr_copy.iid,
                        "mention command cancelled: semaphore closed"
                    );
                    return;
                };
                let discussion_id = trigger.discussion_id.clone();
                let trigger_note_id = trigger.trigger_note.id;
                if shutdown.load(Ordering::SeqCst) {
                    let _ = state
                        .finish_mention_command(
                            &repo_name,
                            mr_copy.iid,
                            &discussion_id,
                            trigger_note_id,
                            &head_sha_copy,
                            "cancelled",
                        )
                        .await;
                    return;
                }
                let effective_mr = match gitlab.get_mr(&repo_name, mr_copy.iid).await {
                    Ok(latest) => latest,
                    Err(err) => {
                        warn!(
                            repo = repo_name.as_str(),
                            iid = mr_copy.iid,
                            discussion_id = discussion_id.as_str(),
                            trigger_note_id,
                            error = %err,
                            "failed to refresh MR before mention command; using scheduled snapshot"
                        );
                        mr_copy.clone()
                    }
                };
                let effective_head_sha = effective_mr
                    .head_sha()
                    .unwrap_or_else(|| head_sha_copy.clone());
                let prompt = MentionFlow::build_mention_prompt(
                    &repo_name,
                    &effective_mr,
                    &effective_head_sha,
                    &trigger,
                );
                if let Err(err) = add_eyes_to_discussion_note(
                    gitlab.as_ref(),
                    &repo_name,
                    mr_copy.iid,
                    &discussion_id,
                    trigger_note_id,
                    bot_user_id,
                    &eyes_emoji,
                )
                .await
                {
                    let error_chain = format!("{err:#}");
                    warn!(
                        repo = repo_name.as_str(),
                        iid = mr_copy.iid,
                        discussion_id = discussion_id.as_str(),
                        trigger_note_id,
                        error = %err,
                        error_chain = error_chain.as_str(),
                        "failed to add in-progress eyes reaction to mention trigger note"
                    );
                }

                let command_context = MentionCommandContext {
                    repo: command_repo_name.clone(),
                    project_path: command_repo_name.clone(),
                    mr: effective_mr,
                    head_sha: effective_head_sha.clone(),
                    discussion_id: discussion_id.clone(),
                    trigger_note_id,
                    requester_name: requester.name.clone(),
                    requester_email: requester.email.clone(),
                    additional_developer_instructions,
                    prompt,
                };
                let outcome = codex.run_mention_command(command_context).await;
                let (state_result, status_message) = match outcome {
                    Ok(MentionCommandResult {
                        status: MentionCommandStatus::Committed,
                        commit_sha,
                        reply_message,
                    }) => {
                        let mut message = if reply_message.trim().is_empty() {
                            "Mention command completed.".to_string()
                        } else {
                            reply_message
                        };
                        if let Some(commit_sha) = commit_sha {
                            let short_sha: String = commit_sha.chars().take(7).collect();
                            let has_sha = message.contains(commit_sha.as_str())
                                || (!short_sha.is_empty() && message.contains(short_sha.as_str()));
                            if !has_sha {
                                message.push_str(&format!("\n\nCommit SHA: `{}`", commit_sha));
                            }
                        }
                        ("committed", message)
                    }
                    Ok(MentionCommandResult {
                        status: MentionCommandStatus::NoChanges,
                        reply_message,
                        ..
                    }) => (
                        "no_changes",
                        if reply_message.trim().is_empty() {
                            "Mention command completed with no code changes.".to_string()
                        } else {
                            reply_message
                        },
                    ),
                    Err(err) => {
                        let error_chain = format!("{err:#}");
                        warn!(
                            repo = repo_name.as_str(),
                            iid = mr_copy.iid,
                            discussion_id = discussion_id.as_str(),
                            trigger_note_id,
                            error = %err,
                            error_chain = error_chain.as_str(),
                            "mention command execution failed"
                        );
                        (
                            "error",
                            "Mention command failed. Check service logs for details.".to_string(),
                        )
                    }
                };
                let mut completion_note_posted = false;
                for attempt in 1..=3 {
                    match gitlab
                        .create_discussion_note(
                            &repo_name,
                            mr_copy.iid,
                            &discussion_id,
                            &status_message,
                        )
                        .await
                    {
                        Ok(()) => {
                            completion_note_posted = true;
                            break;
                        }
                        Err(err) => {
                            if attempt == 3 {
                                warn!(
                                    repo = repo_name.as_str(),
                                    iid = mr_copy.iid,
                                    discussion_id = discussion_id.as_str(),
                                    trigger_note_id,
                                    error = %err,
                                    "failed to post mention-command completion status"
                                );
                            } else {
                                warn!(
                                    repo = repo_name.as_str(),
                                    iid = mr_copy.iid,
                                    discussion_id = discussion_id.as_str(),
                                    trigger_note_id,
                                    attempt,
                                    error = %err,
                                    "failed to post mention-command completion status; retrying"
                                );
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    100 * attempt as u64,
                                ))
                                .await;
                            }
                        }
                    }
                }
                if !completion_note_posted {
                    let fallback_message = format!(
                        "Mention command result for discussion `{}`:\n\n{}",
                        discussion_id, status_message
                    );
                    if let Err(err) = gitlab
                        .create_note(&repo_name, mr_copy.iid, &fallback_message)
                        .await
                    {
                        warn!(
                            repo = repo_name.as_str(),
                            iid = mr_copy.iid,
                            discussion_id = discussion_id.as_str(),
                            trigger_note_id,
                            error = %err,
                            "failed to post fallback MR note for mention-command completion"
                        );
                    }
                }
                let persisted_result = state_result;
                let mut mention_state_persisted = false;
                for attempt in 1..=3 {
                    match state
                        .finish_mention_command(
                            &repo_name,
                            mr_copy.iid,
                            &discussion_id,
                            trigger_note_id,
                            &head_sha_copy,
                            persisted_result,
                        )
                        .await
                    {
                        Ok(()) => {
                            mention_state_persisted = true;
                            break;
                        }
                        Err(err) => {
                            if attempt == 3 {
                                warn!(
                                    repo = repo_name.as_str(),
                                    iid = mr_copy.iid,
                                    discussion_id = discussion_id.as_str(),
                                    trigger_note_id,
                                    error = %err,
                                    "failed to persist mention-command state"
                                );
                            } else {
                                warn!(
                                    repo = repo_name.as_str(),
                                    iid = mr_copy.iid,
                                    discussion_id = discussion_id.as_str(),
                                    trigger_note_id,
                                    attempt,
                                    error = %err,
                                    "failed to persist mention-command state; retrying"
                                );
                                tokio::time::sleep(std::time::Duration::from_millis(
                                    100 * attempt as u64,
                                ))
                                .await;
                            }
                        }
                    }
                }
                if !mention_state_persisted {
                    let _ = state
                        .finish_mention_command(
                            &repo_name,
                            mr_copy.iid,
                            &discussion_id,
                            trigger_note_id,
                            &head_sha_copy,
                            "error",
                        )
                        .await;
                }
                if let Err(err) = remove_eyes_from_discussion_note(
                    gitlab.as_ref(),
                    &repo_name,
                    mr_copy.iid,
                    &discussion_id,
                    trigger_note_id,
                    bot_user_id,
                    &eyes_emoji,
                )
                .await
                {
                    let error_chain = format!("{err:#}");
                    warn!(
                        repo = repo_name.as_str(),
                        iid = mr_copy.iid,
                        discussion_id = discussion_id.as_str(),
                        trigger_note_id,
                        error = %err,
                        error_chain = error_chain.as_str(),
                        "failed to remove in-progress eyes reaction from mention trigger note"
                    );
                }
            }));
        }
        Ok(outcome)
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

pub(crate) fn extract_parent_chain(
    discussion: &MergeRequestDiscussion,
    trigger_note_id: u64,
) -> Option<Vec<DiscussionNote>> {
    let notes = &discussion.notes;
    let trigger_index = notes.iter().position(|note| note.id == trigger_note_id)?;
    let trigger_note = notes[trigger_index].clone();
    let has_explicit_parent = trigger_note.in_reply_to_id.is_some();
    if !has_explicit_parent {
        return Some(notes.iter().take(trigger_index + 1).cloned().collect());
    }

    let mut by_id: HashMap<u64, DiscussionNote> = HashMap::new();
    for note in notes {
        by_id.insert(note.id, note.clone());
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
            .and_then(|parent_id| by_id.get(&parent_id).cloned());
        chain.push(note);
    }
    chain.reverse();
    Some(chain)
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

pub(crate) async fn add_eyes_to_discussion_note(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    discussion_id: &str,
    note_id: u64,
    bot_user_id: u64,
    eyes: &str,
) -> Result<()> {
    if bot_user_id == 0 {
        return Ok(());
    }
    let awards = gitlab
        .list_discussion_note_awards(repo, iid, discussion_id, note_id)
        .await?;
    if awards
        .iter()
        .any(|award| award.user.id == bot_user_id && award.name == eyes)
    {
        return Ok(());
    }
    gitlab
        .add_discussion_note_award(repo, iid, discussion_id, note_id, eyes)
        .await?;
    Ok(())
}

pub(crate) async fn remove_eyes_from_discussion_note(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    discussion_id: &str,
    note_id: u64,
    bot_user_id: u64,
    eyes: &str,
) -> Result<()> {
    if bot_user_id == 0 {
        return Ok(());
    }
    let awards = gitlab
        .list_discussion_note_awards(repo, iid, discussion_id, note_id)
        .await?;
    for award in awards {
        if award.user.id == bot_user_id && award.name == eyes {
            gitlab
                .delete_discussion_note_award(repo, iid, discussion_id, note_id, award.id)
                .await?;
        }
    }
    Ok(())
}

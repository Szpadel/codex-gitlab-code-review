use super::super::markdown::render_safe_markdown;
use super::super::status::{
    RunDetailSnapshot, SecurityContextPreview, ThreadSnapshot, TranscriptBackfillSnapshot,
};
use super::super::transcript::render_thread_stream;
use super::html::{
    NavItem, bool_label, escape_html, pretty_print_json, render_definition_list,
    render_optional_unix_timestamp, render_shell, render_unix_timestamp, run_kind_label,
};
use crate::state::{RunHistoryKind, RunHistoryRecord};

pub(in crate::http) fn render_run_detail_page(
    snapshot: &RunDetailSnapshot,
    gitlab_base_url: &str,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let run = &snapshot.run;
    let body = format!(
        "<section class=\"hero\"><h1>Run {}</h1><p class=\"muted\">{} run for {} !{}.</p></section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>Run metadata</h2>{}</article>\
         <article class=\"card\"><h2>Related sessions</h2>{}</article>\
         </section>\
         {}{}{}{}",
        run.id,
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        run.iid,
        render_run_metadata(run),
        render_related_runs(&snapshot.related_runs, run.id),
        render_trigger_card(run, gitlab_base_url),
        render_security_context_card(run, snapshot.security_context_preview.as_ref()),
        render_failure_details_card(run),
        render_thread_card(
            run,
            snapshot.thread.as_ref(),
            snapshot.transcript_backfill.as_ref(),
            gitlab_base_url,
        ),
    );
    render_shell(
        "Run Detail",
        NavItem::History,
        body,
        csrf_token,
        development_enabled,
    )
}

fn render_run_metadata(run: &RunHistoryRecord) -> String {
    let items = vec![
        ("Kind".to_string(), escape_html(run_kind_label(run.kind))),
        ("Repo".to_string(), escape_html(&run.repo)),
        ("MR".to_string(), escape_html(&format!("!{}", run.iid))),
        ("Head SHA".to_string(), escape_html(&run.head_sha)),
        ("Status".to_string(), escape_html(&run.status)),
        (
            "Result".to_string(),
            escape_html(run.result.as_deref().unwrap_or("-")),
        ),
        ("Started".to_string(), render_unix_timestamp(run.started_at)),
        (
            "Finished".to_string(),
            render_optional_unix_timestamp(run.finished_at),
        ),
        (
            "Account".to_string(),
            escape_html(run.auth_account_name.as_deref().unwrap_or("-")),
        ),
        (
            "Thread".to_string(),
            escape_html(
                run.review_thread_id
                    .as_deref()
                    .or(run.thread_id.as_deref())
                    .unwrap_or("-"),
            ),
        ),
        (
            "Turn".to_string(),
            escape_html(run.turn_id.as_deref().unwrap_or("-")),
        ),
        (
            "Command repo".to_string(),
            escape_html(run.command_repo.as_deref().unwrap_or("-")),
        ),
        (
            "Commit SHA".to_string(),
            escape_html(run.commit_sha.as_deref().unwrap_or("-")),
        ),
        (
            "Feature flags".to_string(),
            escape_html(&render_run_feature_flags(run)),
        ),
    ];
    format!("<dl>{}</dl>", render_definition_list(&items))
}

fn render_run_feature_flags(run: &RunHistoryRecord) -> String {
    let flags = [
        format!(
            "gitlab_discovery_mcp={}",
            bool_label(run.feature_flags.gitlab_discovery_mcp)
        ),
        format!(
            "gitlab_inline_review_comments={}",
            bool_label(run.feature_flags.gitlab_inline_review_comments)
        ),
        format!(
            "composer_install={}",
            bool_label(run.feature_flags.composer_install)
        ),
        format!(
            "security_context_ignore_base_head={}",
            bool_label(run.feature_flags.security_context_ignore_base_head)
        ),
        format!(
            "composer_auto_repositories={}",
            bool_label(run.feature_flags.composer_auto_repositories)
        ),
        format!(
            "composer_safe_install={}",
            bool_label(run.feature_flags.composer_safe_install)
        ),
    ];
    flags.join(", ")
}

fn render_failure_details_card(run: &RunHistoryRecord) -> String {
    if run.result.as_deref() != Some("error") {
        return String::new();
    }
    let details = run
        .error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Run finished with result error, but no failure details were recorded.");
    format!(
        "<section class=\"card failure-card\"><h2>Failure details</h2><pre class=\"codeblock failure-details\">{}</pre></section>",
        escape_html(details)
    )
}

fn render_related_runs(runs: &[RunHistoryRecord], current_id: i64) -> String {
    let filtered = runs
        .iter()
        .filter(|run| run.id != current_id)
        .map(|run| {
            format!(
                "<li><a href=\"/history/{}\">{} {} {}</a></li>",
                run.id,
                escape_html(run_kind_label(run.kind)),
                escape_html(run.result.as_deref().unwrap_or(&run.status)),
                render_unix_timestamp(run.started_at)
            )
        })
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        "<p class=\"empty\">No other recorded sessions for this MR.</p>".to_string()
    } else {
        format!("<ul class=\"simple-list\">{}</ul>", filtered.join(""))
    }
}

fn render_trigger_card(run: &RunHistoryRecord, gitlab_base_url: &str) -> String {
    if run.kind != RunHistoryKind::Mention {
        return String::new();
    }
    format!(
        "<section class=\"card\"><h2>Trigger note</h2>\
         <dl>{}</dl>\
         {}</section>",
        render_definition_list(&[
            (
                "Discussion".to_string(),
                escape_html(run.discussion_id.as_deref().unwrap_or("-")),
            ),
            (
                "Trigger note".to_string(),
                escape_html(
                    &run.trigger_note_id
                        .map_or_else(|| "-".to_string(), |value| value.to_string()),
                ),
            ),
            (
                "Author".to_string(),
                escape_html(run.trigger_note_author_name.as_deref().unwrap_or("-")),
            ),
        ]),
        render_markdown_block(
            run.trigger_note_body
                .as_deref()
                .unwrap_or("(no trigger note body)"),
            "trigger-note-body",
            gitlab_base_url,
        )
    )
}

fn render_security_context_card(
    run: &RunHistoryRecord,
    preview: Option<&SecurityContextPreview>,
) -> String {
    let Some(preview) = preview else {
        return String::new();
    };
    let source = match preview.source_run_history_id {
        Some(source_run_id) if source_run_id > 0 && source_run_id != run.id => {
            format!("<a href=\"/history/{source_run_id}\">run {source_run_id}</a>")
        }
        Some(source_run_id) if source_run_id == run.id => "generated in this run".to_string(),
        _ => "legacy cached context".to_string(),
    };
    let pretty_payload = pretty_print_json(preview.payload_json.as_str());
    format!(
        "<section class=\"card\"><h2>Security context</h2>\
         <p class=\"muted\">Exact cached threat-model payload injected into the security review prompt.</p>\
         <dl>{}</dl>\
         <pre class=\"codeblock\">{}</pre></section>",
        render_definition_list(&[
            ("Base branch".to_string(), escape_html(&preview.base_branch)),
            (
                "Base head".to_string(),
                format!("<code>{}</code>", escape_html(&preview.base_head_sha))
            ),
            (
                "Prompt version".to_string(),
                format!("<code>{}</code>", escape_html(&preview.prompt_version))
            ),
            ("Source".to_string(), source),
            (
                "Generated".to_string(),
                render_unix_timestamp(preview.generated_at)
            ),
            (
                "Expires".to_string(),
                render_unix_timestamp(preview.expires_at)
            ),
        ]),
        escape_html(&pretty_payload),
    )
}

fn render_markdown_block(body: &str, class_name: &str, gitlab_base_url: &str) -> String {
    if body.is_empty() {
        return String::new();
    }
    format!(
        "<div class=\"{} markdown-body\">{}</div>",
        class_name,
        render_safe_markdown(body, gitlab_base_url)
    )
}

fn render_thread_card(
    run: &RunHistoryRecord,
    thread: Option<&ThreadSnapshot>,
    transcript_backfill: Option<&TranscriptBackfillSnapshot>,
    gitlab_base_url: &str,
) -> String {
    let backfill_notice = render_transcript_backfill_notice(transcript_backfill);
    let security_context_banner = render_security_context_banner(run);
    let Some(thread) = thread else {
        return format!(
            "<section class=\"card transcript-panel\"><div class=\"transcript-header\"><div><h2>Session transcript</h2><p class=\"muted\">Persisted session detail is not available for this run.</p></div></div>{security_context_banner}{backfill_notice}<div class=\"thread-empty\"><p class=\"empty\">Codex thread detail is unavailable for this run.</p></div></section>"
        );
    };
    format!(
        "<section class=\"card transcript-panel\">\
         <div class=\"transcript-header\">\
         <div><h2>Session transcript</h2><p class=\"muted\">Conversation, reasoning, and execution artifacts captured for this run.</p></div>\
         <div class=\"transcript-thread-meta\">\
         <span class=\"meta-chip\"><span class=\"meta-chip-label\">Thread</span><code>{}</code></span>\
         <span class=\"status-pill status-{}\">{}</span>\
         {}\
         </div></div>{}{}\
         {}</section>",
        escape_html(&thread.id),
        thread_status_class(&thread.status),
        escape_html(&thread.status),
        render_optional_preview_chip(&thread.preview),
        security_context_banner,
        backfill_notice,
        render_thread_stream(thread, gitlab_base_url),
    )
}

fn render_security_context_banner(run: &RunHistoryRecord) -> String {
    let Some(source_run_id) = run.security_context_source_run_id else {
        return String::new();
    };
    if run.kind != RunHistoryKind::Security || source_run_id <= 0 || source_run_id == run.id {
        return String::new();
    }
    format!(
        "<div class=\"thread-empty\"><p class=\"empty\">Reused cached security context from <a href=\"/history/{source_run_id}\">run {source_run_id}</a>.</p></div>"
    )
}

fn render_transcript_backfill_notice(
    transcript_backfill: Option<&TranscriptBackfillSnapshot>,
) -> String {
    let Some(transcript_backfill) = transcript_backfill else {
        return String::new();
    };
    match transcript_backfill.state {
        crate::state::TranscriptBackfillState::InProgress => {
            "<div class=\"thread-empty\"><p class=\"empty\">Transcript backfill is in progress.</p></div>"
                .to_string()
        }
        crate::state::TranscriptBackfillState::Failed => format!(
            "<div class=\"thread-empty\"><p class=\"empty\">Transcript backfill failed{}.</p></div>",
            transcript_backfill
                .error
                .as_deref()
                .map(|error| format!(": {}", escape_html(error)))
                .unwrap_or_default()
        ),
        crate::state::TranscriptBackfillState::NotRequested
        | crate::state::TranscriptBackfillState::Complete => String::new(),
    }
}

fn render_optional_preview_chip(preview: &str) -> String {
    if preview.is_empty() {
        String::new()
    } else {
        format!(
            "<span class=\"meta-chip\"><span class=\"meta-chip-label\">Preview</span>{}</span>",
            escape_html(preview)
        )
    }
}

fn thread_status_class(status: &str) -> &'static str {
    match status {
        "completed" | "success" => "success",
        "failed" | "error" => "danger",
        "in_progress" | "running" => "info",
        _ => "neutral",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FeatureFlagSnapshot;
    use crate::http::status::{RunDetailSnapshot, SecurityContextPreview};
    use crate::state::{RunHistoryKind, RunHistoryRecord, TranscriptBackfillState};

    fn sample_run(kind: RunHistoryKind) -> RunHistoryRecord {
        RunHistoryRecord {
            id: 7,
            kind,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "abc123".to_string(),
            status: "done".to_string(),
            result: Some("pass".to_string()),
            started_at: 0,
            finished_at: Some(0),
            updated_at: 0,
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            security_context_base_branch: None,
            security_context_base_head_sha: None,
            security_context_prompt_version: None,
            security_context_payload_json: None,
            security_context_generated_at: None,
            security_context_expires_at: None,
            preview: Some("Preview".to_string()),
            summary: Some("Summary".to_string()),
            error: None,
            auth_account_name: Some("primary".to_string()),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            commit_sha: None,
            feature_flags: FeatureFlagSnapshot::default(),
            events_persisted_cleanly: true,
            transcript_backfill_state: TranscriptBackfillState::Complete,
            transcript_backfill_error: None,
        }
    }

    #[test]
    fn run_detail_page_renders_security_context_source_banner_for_security_runs() {
        let mut run = sample_run(RunHistoryKind::Security);
        run.security_context_source_run_id = Some(42);
        let snapshot = RunDetailSnapshot {
            generated_at: "2026-03-23T00:00:00Z".to_string(),
            run,
            related_runs: Vec::new(),
            security_context_preview: None,
            thread: None,
            transcript_backfill: None,
        };

        let html =
            render_run_detail_page(&snapshot, "https://gitlab.example.com/api/v4", None, false);

        assert!(html.contains("Reused cached security context from"));
        assert!(html.contains("/history/42"));
    }

    #[test]
    fn run_detail_page_renders_security_context_preview() {
        let run = sample_run(RunHistoryKind::Security);
        let snapshot = RunDetailSnapshot {
            generated_at: "2026-03-23T00:00:00Z".to_string(),
            run,
            related_runs: Vec::new(),
            security_context_preview: Some(SecurityContextPreview {
                base_branch: "main".to_string(),
                base_head_sha: "deadbeef".to_string(),
                prompt_version: "security-review-context-v1".to_string(),
                payload_json: "{\"components\":[\"api\"],\"focus_paths\":[\"src/auth.rs\"]}"
                    .to_string(),
                source_run_history_id: Some(42),
                generated_at: 1_711_152_000,
                expires_at: 1_712_361_600,
            }),
            thread: None,
            transcript_backfill: None,
        };

        let html =
            render_run_detail_page(&snapshot, "https://gitlab.example.com/api/v4", None, false);

        assert!(html.contains("Security context"));
        assert!(html.contains("main"));
        assert!(html.contains("deadbeef"));
        assert!(html.contains("&quot;components&quot;"));
        assert!(html.contains("/history/42"));
    }

    #[test]
    fn run_detail_page_renders_trigger_note_markdown_images() {
        let mut run = sample_run(RunHistoryKind::Mention);
        run.discussion_id = Some("discussion-1".to_string());
        run.trigger_note_id = Some(77);
        run.trigger_note_author_name = Some("Alice".to_string());
        run.trigger_note_body = Some("![shot](/uploads/hash/screenshot.png)".to_string());
        let snapshot = RunDetailSnapshot {
            generated_at: "2026-03-23T00:00:00Z".to_string(),
            run,
            related_runs: Vec::new(),
            security_context_preview: None,
            thread: None,
            transcript_backfill: None,
        };

        let html =
            render_run_detail_page(&snapshot, "https://gitlab.example.com/api/v4", None, false);

        assert!(html.contains("trigger-note-body"));
        assert!(html.contains("<img"));
        assert!(html.contains("https://gitlab.example.com/uploads/hash/screenshot.png"));
    }
}

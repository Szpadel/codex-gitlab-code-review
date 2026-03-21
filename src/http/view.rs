use super::status::{
    HistorySnapshot, MrHistorySnapshot, RunDetailSnapshot, StatusFeatureFlagSnapshot,
    StatusSnapshot, ThreadItemSnapshot, ThreadSnapshot, TranscriptBackfillSnapshot,
};
use super::timestamp::{self, UiTimestamp};
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, ProjectCatalogSummary,
    RunHistoryKind, RunHistoryListItem, RunHistoryRecord,
};
use serde::Deserialize;
use urlencoding::encode;

const FEATURE_FLAG_SCRIPT: &str = include_str!("assets/feature_flag.js");
const PAGE_STYLE: &str = include_str!("assets/page.css");

pub(super) fn render_status_page(snapshot: &StatusSnapshot, csrf_token: Option<&str>) -> String {
    let scan = &snapshot.scan;
    let config = &snapshot.config;
    let scan_summary = vec![
        ("State".to_string(), escape_html(&scan.scan_state)),
        (
            "Mode".to_string(),
            escape_html(scan.mode.as_deref().unwrap_or("-")),
        ),
        (
            "Started".to_string(),
            render_rfc3339_timestamp(scan.started_at.as_deref()),
        ),
        (
            "Finished".to_string(),
            render_rfc3339_timestamp(scan.finished_at.as_deref()),
        ),
        (
            "Outcome".to_string(),
            escape_html(scan.outcome.as_deref().unwrap_or("-")),
        ),
        (
            "Error".to_string(),
            escape_html(scan.error.as_deref().unwrap_or("-")),
        ),
        (
            "Next scan".to_string(),
            render_rfc3339_timestamp(scan.next_scan_at.as_deref()),
        ),
    ];
    let config_summary = vec![
        ("GitLab".to_string(), escape_html(&config.gitlab_base_url)),
        ("Bind".to_string(), escape_html(&config.bind_addr)),
        (
            "Run once".to_string(),
            escape_html(bool_label(config.run_once)),
        ),
        (
            "Dry run".to_string(),
            escape_html(bool_label(config.dry_run)),
        ),
        (
            "Mention commands".to_string(),
            escape_html(bool_label(config.mention_commands_enabled)),
        ),
        (
            "Browser MCP".to_string(),
            escape_html(bool_label(config.browser_mcp_enabled)),
        ),
        (
            "GitLab Discovery MCP".to_string(),
            escape_html(bool_label(config.gitlab_discovery_mcp_configured)),
        ),
        (
            "Max concurrent".to_string(),
            escape_html(&config.max_concurrent.to_string()),
        ),
        ("Cron".to_string(), escape_html(&config.schedule_cron)),
        (
            "Timezone".to_string(),
            escape_html(&config.schedule_timezone),
        ),
        (
            "Created after".to_string(),
            render_rfc3339_timestamp(config.created_after.as_deref()),
        ),
        (
            "Repo targets".to_string(),
            escape_html(&target_label(config.repo_targets_all, config.repo_targets)),
        ),
        (
            "Group targets".to_string(),
            escape_html(&target_label(
                config.group_targets_all,
                config.group_targets,
            )),
        ),
    ];
    let body = format!(
        "<section class=\"hero\"><h1>Service status</h1><p class=\"muted\">Generated {}</p></section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>Scan</h2><dl>{}</dl></article>\
         <article class=\"card\"><h2>Configuration</h2><dl>{}</dl></article>\
         </section>\
         {}{}{}{}{}",
        render_rfc3339_timestamp(Some(&snapshot.generated_at)),
        render_definition_list(&scan_summary),
        render_definition_list(&config_summary),
        render_feature_flags_section(&config.feature_flags),
        render_reviews_section(&snapshot.in_progress_reviews),
        render_mentions_section(&snapshot.in_progress_mentions),
        render_auth_section(&snapshot.auth_limit_resets),
        render_catalog_section(&snapshot.project_catalogs),
    );
    render_shell("Status", NavItem::Status, body, csrf_token)
}

pub(super) fn render_history_page(snapshot: &HistorySnapshot, csrf_token: Option<&str>) -> String {
    let filters = &snapshot.filters;
    let body = format!(
        "<section class=\"hero\"><h1>Run history</h1><p class=\"muted\">Append-only review and mention sessions.</p></section>\
         {}\
         {}\
         {}",
        render_history_filters(filters),
        render_history_run_table("All runs", &snapshot.runs),
        render_history_pagination(snapshot)
    );
    render_shell("History", NavItem::History, body, csrf_token)
}

pub(super) fn render_mr_history_page(
    snapshot: &MrHistorySnapshot,
    csrf_token: Option<&str>,
) -> String {
    let body = format!(
        "<section class=\"hero\"><h1>MR history</h1><p class=\"muted\">{} !{} has {} recorded session(s).</p></section>{}",
        escape_html(&snapshot.repo),
        snapshot.iid,
        snapshot.runs.len(),
        render_record_run_table("Sessions for this MR", &snapshot.runs)
    );
    render_shell("MR History", NavItem::History, body, csrf_token)
}

pub(super) fn render_run_detail_page(
    snapshot: &RunDetailSnapshot,
    csrf_token: Option<&str>,
) -> String {
    let run = &snapshot.run;
    let body = format!(
        "<section class=\"hero\"><h1>Run {}</h1><p class=\"muted\">{} run for {} !{}.</p></section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>Run metadata</h2>{}</article>\
         <article class=\"card\"><h2>Related sessions</h2>{}</article>\
         </section>\
         {}{}",
        run.id,
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        run.iid,
        render_run_metadata(run),
        render_related_runs(&snapshot.related_runs, run.id),
        render_trigger_card(run),
        render_thread_card(
            snapshot.thread.as_ref(),
            snapshot.transcript_backfill.as_ref(),
        ),
    );
    render_shell("Run Detail", NavItem::History, body, csrf_token)
}

pub(super) fn encode_repo_key(repo: &str) -> String {
    let mut output = String::with_capacity(repo.len() * 2);
    for byte in repo.as_bytes() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn render_reviews_section(reviews: &[InProgressReview]) -> String {
    render_table_section(
        "In-progress reviews",
        if reviews.is_empty() {
            "<p class=\"empty\">No in-progress reviews.</p>".to_string()
        } else {
            let rows = reviews
                .iter()
                .map(|review| {
                    format!(
                        "<tr><td>{}</td><td><a href=\"{}\">!{}</a></td><td><code>{}</code></td></tr>",
                        escape_html(&review.repo),
                        mr_history_href(&review.repo, review.iid),
                        review.iid,
                        escape_html(&review.head_sha)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Repo</th><th>MR</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_mentions_section(mentions: &[InProgressMentionCommand]) -> String {
    render_table_section(
        "In-progress mention commands",
        if mentions.is_empty() {
            "<p class=\"empty\">No in-progress mention commands.</p>".to_string()
        } else {
            let rows = mentions
                .iter()
                .map(|mention| {
                    format!(
                        "<tr><td>{}</td><td><a href=\"{}\">!{}</a></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                        escape_html(&mention.key.repo),
                        mr_history_href(&mention.key.repo, mention.key.iid),
                        mention.key.iid,
                        escape_html(&mention.key.discussion_id),
                        mention.key.trigger_note_id,
                        escape_html(&mention.head_sha)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Repo</th><th>MR</th><th>Discussion</th><th>Trigger note</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_auth_section(entries: &[AuthLimitResetEntry]) -> String {
    render_table_section(
        "Auth fallback cooldowns",
        if entries.is_empty() {
            "<p class=\"empty\">No auth cooldowns are currently tracked.</p>".to_string()
        } else {
            let rows = entries
                .iter()
                .map(|entry| {
                    format!(
                        "<tr><td>{}</td><td>{}</td></tr>",
                        escape_html(&entry.account_name),
                        render_rfc3339_timestamp(Some(&entry.reset_at))
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Account</th><th>Reset at</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_catalog_section(catalogs: &[ProjectCatalogSummary]) -> String {
    render_table_section(
        "Project catalog cache",
        if catalogs.is_empty() {
            "<p class=\"empty\">No cached project catalogs.</p>".to_string()
        } else {
            let rows = catalogs
                .iter()
                .map(|catalog| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        escape_html(&catalog.cache_key),
                        catalog.project_count,
                        render_unix_timestamp(catalog.fetched_at)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Cache key</th><th>Projects</th><th>Fetched at</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_history_filters(filters: &HistorySnapshotFilters) -> String {
    format!(
        "<section class=\"card\"><h2>Filters</h2>\
         <form class=\"filters\" method=\"get\" action=\"/history\">\
         <input type=\"hidden\" name=\"limit\" value=\"{}\">\
         <label class=\"filter-field\"><span>Repo</span><input name=\"repo\" value=\"{}\"></label>\
         <label class=\"filter-field\"><span>MR IID</span><input name=\"iid\" value=\"{}\"></label>\
         <label class=\"filter-field\"><span>Kind</span><select name=\"kind\">{}</select></label>\
         <label class=\"filter-field\"><span>Result</span><input name=\"result\" value=\"{}\"></label>\
         <label class=\"filter-field filter-field-wide\"><span>Search</span><input name=\"q\" value=\"{}\"></label>\
         <div class=\"filter-actions\"><button type=\"submit\">Apply</button></div>\
         </form></section>",
        filters.limit,
        escape_html(filters.repo.as_deref().unwrap_or("")),
        filters
            .iid
            .map(|value| value.to_string())
            .unwrap_or_default(),
        render_kind_options(filters.kind),
        escape_html(filters.result.as_deref().unwrap_or("")),
        escape_html(filters.search.as_deref().unwrap_or(""))
    )
}

type HistorySnapshotFilters = super::status::HistoryQuery;

fn render_history_pagination(snapshot: &HistorySnapshot) -> String {
    let summary = if snapshot.runs.is_empty() {
        "0 matching runs".to_string()
    } else {
        format!("Showing up to {} matching runs", snapshot.limit)
    };
    let previous = if let Some(cursor) = snapshot.previous_cursor.as_deref() {
        let href = history_page_href(&snapshot.filters, Some(cursor), None);
        format!(
            "<a class=\"pagination-link\" href=\"{}\">Previous</a>",
            escape_html(&href)
        )
    } else {
        "<span class=\"pagination-link pagination-link-disabled\">Previous</span>".to_string()
    };
    let next = if let Some(cursor) = snapshot.next_cursor.as_deref() {
        let href = history_page_href(&snapshot.filters, None, Some(cursor));
        format!(
            "<a class=\"pagination-link\" href=\"{}\">Next</a>",
            escape_html(&href)
        )
    } else {
        "<span class=\"pagination-link pagination-link-disabled\">Next</span>".to_string()
    };
    format!(
        "<section class=\"card\"><div class=\"pagination\"><p class=\"muted\">{}</p><div class=\"pagination-links\">{}{}</div></div></section>",
        escape_html(&summary),
        previous,
        next
    )
}

fn history_page_href(
    filters: &HistorySnapshotFilters,
    before: Option<&str>,
    after: Option<&str>,
) -> String {
    let mut params = vec![format!("limit={}", filters.limit)];
    if let Some(repo) = filters.repo.as_deref() {
        params.push(format!("repo={}", encode(repo)));
    }
    if let Some(iid) = filters.iid {
        params.push(format!("iid={iid}"));
    }
    if let Some(kind) = filters.kind {
        params.push(format!("kind={}", run_kind_label(kind)));
    }
    if let Some(result) = filters.result.as_deref() {
        params.push(format!("result={}", encode(result)));
    }
    if let Some(search) = filters.search.as_deref() {
        params.push(format!("q={}", encode(search)));
    }
    if let Some(before) = before {
        params.push(format!("before={}", encode(before)));
    }
    if let Some(after) = after {
        params.push(format!("after={}", encode(after)));
    }
    format!("/history?{}", params.join("&"))
}

fn render_kind_options(selected: Option<RunHistoryKind>) -> String {
    let values = [
        (None, "all"),
        (Some(RunHistoryKind::Review), "review"),
        (Some(RunHistoryKind::Mention), "mention"),
    ];
    values
        .iter()
        .map(|(value, label)| {
            let selected_attr = if *value == selected { " selected" } else { "" };
            format!(
                "<option value=\"{}\"{}>{}</option>",
                label, selected_attr, label
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_history_run_table(title: &str, runs: &[RunHistoryListItem]) -> String {
    render_table_section(
        title,
        if runs.is_empty() {
            "<p class=\"empty\">No recorded sessions matched this view.</p>".to_string()
        } else {
            let rows = runs
                .iter()
                .map(render_history_run_row)
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Kind</th><th>Repo</th><th>MR</th><th>Result</th><th>Started</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_history_run_row(run: &RunHistoryListItem) -> String {
    format!(
        "<tr>\
         <td><span class=\"badge badge-{}\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"{}\">!{}</a></td>\
         <td><span class=\"badge badge-result\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"/history/{}\">{}</a></td>\
         </tr>",
        escape_html(run_kind_label(run.kind)),
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        mr_history_href(&run.repo, run.iid),
        run.iid,
        escape_html(run.result.as_deref().unwrap_or(&run.status)),
        render_unix_timestamp(run.started_at),
        run.id,
        escape_html(
            run.preview
                .as_deref()
                .or(run.summary.as_deref())
                .unwrap_or("(no preview)")
        )
    )
}

fn render_record_run_table(title: &str, runs: &[RunHistoryRecord]) -> String {
    render_table_section(
        title,
        if runs.is_empty() {
            "<p class=\"empty\">No recorded sessions matched this view.</p>".to_string()
        } else {
            let rows = runs
                .iter()
                .map(render_record_run_row)
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Kind</th><th>Repo</th><th>MR</th><th>Result</th><th>Started</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_record_run_row(run: &RunHistoryRecord) -> String {
    format!(
        "<tr>\
         <td><span class=\"badge badge-{}\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"{}\">!{}</a></td>\
         <td><span class=\"badge badge-result\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"/history/{}\">{}</a></td>\
         </tr>",
        escape_html(run_kind_label(run.kind)),
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        mr_history_href(&run.repo, run.iid),
        run.iid,
        escape_html(run.result.as_deref().unwrap_or(&run.status)),
        render_unix_timestamp(run.started_at),
        run.id,
        escape_html(
            run.preview
                .as_deref()
                .or(run.summary.as_deref())
                .unwrap_or("(no preview)")
        )
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

fn render_feature_flags_section(flags: &[StatusFeatureFlagSnapshot]) -> String {
    render_table_section(
        "Feature flags",
        if flags.is_empty() {
            "<p class=\"empty\">No runtime feature flags are registered.</p>".to_string()
        } else {
            let rows = flags
                .iter()
                .map(|flag| {
                    let runtime_override = match flag.runtime_override {
                        Some(value) => bool_label(value),
                        None => "default",
                    };
                    format!(
                        "<tr>\
                         <td><code>{}</code></td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         </tr>",
                        escape_html(&flag.name),
                        escape_html(bool_label(flag.available)),
                        escape_html(bool_label(flag.default_enabled)),
                        escape_html(runtime_override),
                        escape_html(bool_label(flag.effective_enabled)),
                        render_feature_flag_controls(flag),
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<p class=\"muted\">Runtime changes apply only to newly started runs.</p>\
                 <table><thead><tr><th>Flag</th><th>Available</th><th>Default</th><th>Runtime override</th><th>Effective</th><th>Controls</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_feature_flag_controls(flag: &StatusFeatureFlagSnapshot) -> String {
    if !flag.available {
        return "<span class=\"muted\">Unavailable</span>".to_string();
    }
    [
        ("true", "Enable"),
        ("false", "Disable"),
        ("default", "Default"),
    ]
    .into_iter()
    .map(|(value, label)| {
        format!(
            "<button type=\"button\" data-feature-flag=\"{name}\" data-feature-flag-value=\"{value}\" style=\"margin-right:0.4rem;\">{label}</button>",
            name = escape_html(&flag.name),
            value = value,
            label = label,
        )
    })
    .collect::<Vec<_>>()
    .join("")
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

fn render_trigger_card(run: &RunHistoryRecord) -> String {
    if run.kind != RunHistoryKind::Mention {
        return String::new();
    }
    format!(
        "<section class=\"card\"><h2>Trigger note</h2>\
         <dl>{}</dl>\
         <pre class=\"codeblock\">{}</pre></section>",
        render_definition_list(&[
            (
                "Discussion".to_string(),
                escape_html(run.discussion_id.as_deref().unwrap_or("-")),
            ),
            (
                "Trigger note".to_string(),
                escape_html(
                    &run.trigger_note_id
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
            ),
            (
                "Author".to_string(),
                escape_html(run.trigger_note_author_name.as_deref().unwrap_or("-")),
            ),
        ]),
        escape_html(
            run.trigger_note_body
                .as_deref()
                .unwrap_or("(no trigger note body)")
        )
    )
}

fn render_thread_card(
    thread: Option<&ThreadSnapshot>,
    transcript_backfill: Option<&TranscriptBackfillSnapshot>,
) -> String {
    let backfill_notice = render_transcript_backfill_notice(transcript_backfill);
    let Some(thread) = thread else {
        return format!(
            "<section class=\"card transcript-panel\"><div class=\"transcript-header\"><div><h2>Session transcript</h2><p class=\"muted\">Persisted session detail is not available for this run.</p></div></div>{backfill_notice}<div class=\"thread-empty\"><p class=\"empty\">Codex thread detail is unavailable for this run.</p></div></section>"
        );
    };
    let multiple_turns = thread.turns.len() > 1;
    let items = thread
        .turns
        .iter()
        .enumerate()
        .flat_map(|(index, turn)| {
            let mut rendered = Vec::new();
            if multiple_turns {
                rendered.push(render_turn_divider(&turn.id, &turn.status, index == 0));
            }
            rendered.extend(turn.items.iter().map(render_thread_item));
            rendered
        })
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<section class=\"card transcript-panel\">\
         <div class=\"transcript-header\">\
         <div><h2>Session transcript</h2><p class=\"muted\">Conversation, reasoning, and execution artifacts captured for this run.</p></div>\
         <div class=\"transcript-thread-meta\">\
         <span class=\"meta-chip\"><span class=\"meta-chip-label\">Thread</span><code>{}</code></span>\
         <span class=\"status-pill status-{}\">{}</span>\
         {}\
         </div></div>{}\
         <div class=\"transcript-stream\">{}</div></section>",
        escape_html(&thread.id),
        status_class(&thread.status),
        escape_html(&thread.status),
        render_optional_preview_chip(&thread.preview),
        backfill_notice,
        if items.is_empty() {
            "<div class=\"thread-empty\"><p class=\"empty\">No persisted items.</p></div>"
                .to_string()
        } else {
            items
        }
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

fn render_thread_item(item: &ThreadItemSnapshot) -> String {
    match item.item_type.as_str() {
        "userMessage" => render_message_entry("User", "user", item),
        "agentMessage" | "AgentMessage" => render_message_entry("Agent", "agent", item),
        "reasoning" => render_reasoning_entry(item),
        "commandExecution" => render_terminal_entry(item),
        "mcpToolCall" => render_mcp_entry(item),
        "dynamicToolCall" => render_dynamic_tool_entry(item),
        "fileChange" => render_file_change_entry(item),
        "webSearch" => render_web_search_entry(item),
        _ => render_activity_entry(item),
    }
}

fn render_turn_divider(turn_id: &str, status: &str, is_first: bool) -> String {
    format!(
        "<div class=\"turn-divider{}\"><span class=\"turn-divider-label\">Turn {}</span><span class=\"status-pill status-{}\">{}</span></div>",
        if is_first { " turn-divider-first" } else { "" },
        escape_html(turn_id),
        status_class(status),
        escape_html(status)
    )
}

fn render_message_entry(role: &str, role_class: &str, item: &ThreadItemSnapshot) -> String {
    format!(
        "<article class=\"transcript-entry message-entry message-entry-{}\">\
         <header class=\"message-header\">\
         <div class=\"message-identity\"><span class=\"message-role\">{}</span></div>\
         <div class=\"entry-meta-cluster\">{}{}</div>\
         </header>{}</article>",
        role_class,
        escape_html(role),
        render_meta_pills(&item.meta),
        render_entry_timestamp(item),
        render_text_block(item.body.as_deref(), "message-body")
    )
}

fn render_mcp_entry(item: &ThreadItemSnapshot) -> String {
    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "mcp-entry",
            summary_class: "tool-summary",
            kicker: "MCP tool",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        Some(render_tool_preview_box(
            item.preview
                .as_deref()
                .unwrap_or("No argument preview available."),
        )),
        render_entry_meta(item, &item.meta),
        item.body
            .as_deref()
            .map(|body| {
                format!(
                    "<pre class=\"activity-body mcp-body\">{}</pre>",
                    escape_html(body)
                )
            })
            .unwrap_or_default(),
    )
}

fn render_dynamic_tool_entry(item: &ThreadItemSnapshot) -> String {
    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "dynamic-tool-entry",
            summary_class: "tool-summary",
            kicker: "Dynamic tool",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        Some(render_tool_preview_box(
            item.preview.as_deref().unwrap_or("No preview available."),
        )),
        render_entry_meta(item, &item.meta),
        item.body
            .as_deref()
            .map(|body| {
                format!(
                    "<pre class=\"activity-body tool-body\">{}</pre>",
                    escape_html(body)
                )
            })
            .unwrap_or_default(),
    )
}

fn render_reasoning_entry(item: &ThreadItemSnapshot) -> String {
    let (summary, detail) = split_reasoning_content(item.body.as_deref());
    let open = detail.is_none();
    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "reasoning-entry",
            summary_class: "reasoning-summary",
            kicker: "Reasoning",
            open,
        },
        format!(
            "<span class=\"entry-title reasoning-summary-text\">{}</span>",
            escape_html(summary.as_deref().unwrap_or(&item.title))
        ),
        None,
        render_entry_meta(item, &item.meta),
        detail
            .map(|body| format!("<div class=\"reasoning-body\">{}</div>", escape_html(&body)))
            .unwrap_or_default(),
    )
}

fn render_web_search_entry(item: &ThreadItemSnapshot) -> String {
    if let Some(body) = item.body.as_deref() {
        return render_expandable_entry(
            ExpandableEntryOptions {
                entry_class: "web-search-entry",
                summary_class: "web-search-summary",
                kicker: "Web search",
                open: false,
            },
            format!(
                "<span class=\"entry-title\">{}</span>",
                escape_html(item.preview.as_deref().unwrap_or(&item.title))
            ),
            None,
            render_entry_meta(item, &[]),
            format!(
                "<pre class=\"activity-body compact-activity-body\">{}</pre>",
                escape_html(body)
            ),
        );
    }
    render_static_entry(
        "web-search-entry",
        "Web search",
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(item.preview.as_deref().unwrap_or(&item.title))
        ),
        None,
        render_entry_meta(item, &[]),
        String::new(),
    )
}

fn render_terminal_entry(item: &ThreadItemSnapshot) -> String {
    let status_value = meta_value(&item.meta, "status").unwrap_or("unknown");
    let exit_value = meta_value(&item.meta, "exit");
    let cwd_value = meta_value(&item.meta, "cwd");
    let duration_value = meta_value(&item.meta, "durationMs");
    let mut header_meta = Vec::new();
    if let Some(duration) = duration_value {
        header_meta.push(("duration".to_string(), duration.to_string()));
    }
    if let Some(exit) = exit_value {
        header_meta.push(("exit".to_string(), exit.to_string()));
    }
    render_static_entry(
        "terminal-entry",
        "Command",
        format!(
            "<span class=\"entry-title\"><code>{}</code></span>",
            escape_html(&item.title)
        ),
        None,
        format!(
            "<span class=\"status-pill status-{}\">{}</span>{}{}",
            terminal_status_class(status_value, exit_value),
            escape_html(terminal_status_label(status_value, exit_value)),
            render_meta_pills(&header_meta),
            render_entry_timestamp(item)
        ),
        format!(
            "<div class=\"terminal-surface\">\
             {}\
             <div class=\"terminal-command-line\"><span class=\"term-prompt\">$</span><code>{}</code></div>\
             {}\
             </div>",
            cwd_value
                .map(|cwd| format!("<div class=\"terminal-path\">{}</div>", escape_html(cwd)))
                .unwrap_or_default(),
            escape_html(&item.title),
            item.body
                .as_deref()
                .map(|body| format!("<pre class=\"terminal-output\">{}</pre>", escape_html(body)))
                .unwrap_or_else(|| {
                    "<p class=\"terminal-empty\">No aggregated output was captured.</p>".to_string()
                })
        ),
    )
}

fn terminal_status_class(status: &str, exit: Option<&str>) -> &'static str {
    if terminal_exit_failed(exit) {
        "danger"
    } else {
        status_class(status)
    }
}

fn terminal_status_label<'a>(status: &'a str, exit: Option<&str>) -> &'a str {
    if terminal_exit_failed(exit) {
        "failed"
    } else {
        status
    }
}

fn terminal_exit_failed(exit: Option<&str>) -> bool {
    exit.and_then(|value| value.parse::<i64>().ok())
        .is_some_and(|value| value != 0)
}

fn render_file_change_entry(item: &ThreadItemSnapshot) -> String {
    let visible_meta = item
        .meta
        .iter()
        .filter(|(label, _)| {
            !matches!(label.as_str(), "bodyFormat" | "addedLines" | "removedLines")
        })
        .cloned()
        .collect::<Vec<_>>();
    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "file-change-entry",
            summary_class: "file-change-summary",
            kicker: "File change",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(item.preview.as_deref().unwrap_or(&item.title))
        ),
        None,
        format!(
            "{}{}{}{}",
            render_file_change_stats(item),
            render_optional_body_badge(meta_value(&item.meta, "bodyFormat")),
            render_meta_pills(&visible_meta),
            render_entry_timestamp(item)
        ),
        render_file_change_body(item),
    )
}

fn render_activity_entry(item: &ThreadItemSnapshot) -> String {
    render_static_entry(
        &format!(
            "activity-entry activity-entry-{}",
            css_token(&item.item_type)
        ),
        activity_label(&item.item_type),
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        None,
        format!(
            "{}{}{}",
            render_optional_preview_badge(item.preview.as_deref()),
            render_meta_pills(&item.meta),
            render_entry_timestamp(item)
        ),
        format!(
            "{}{}",
            render_optional_preview_text(item.preview.as_deref()),
            item.body
                .as_deref()
                .map(|body| format!("<pre class=\"activity-body\">{}</pre>", escape_html(body)))
                .unwrap_or_default()
        ),
    )
}

fn render_static_entry(
    entry_class: &str,
    kicker: &str,
    title_html: String,
    preview_html: Option<String>,
    meta_html: String,
    body_html: String,
) -> String {
    format!(
        "<article class=\"transcript-entry {}\">{}{}</article>",
        entry_class,
        render_entry_header_shell(kicker, &title_html, preview_html.as_deref(), &meta_html),
        body_html
    )
}

struct ExpandableEntryOptions<'a> {
    entry_class: &'a str,
    summary_class: &'a str,
    kicker: &'a str,
    open: bool,
}

fn render_expandable_entry(
    options: ExpandableEntryOptions<'_>,
    title_html: String,
    preview_html: Option<String>,
    meta_html: String,
    body_html: String,
) -> String {
    format!(
        "<details class=\"transcript-entry {}\"{}>\
         <summary class=\"entry-summary {}\">{}\
         </summary>\
         {}\
         </details>",
        options.entry_class,
        if options.open { " open" } else { "" },
        options.summary_class,
        render_entry_header_content(
            options.kicker,
            &title_html,
            preview_html.as_deref(),
            &meta_html,
        ),
        body_html
    )
}

fn render_entry_header_shell(
    kicker: &str,
    title_html: &str,
    preview_html: Option<&str>,
    meta_html: &str,
) -> String {
    format!(
        "<header class=\"entry-header-shell\">{}</header>",
        render_entry_header_content(kicker, title_html, preview_html, meta_html)
    )
}

fn render_entry_header_content(
    kicker: &str,
    title_html: &str,
    preview_html: Option<&str>,
    meta_html: &str,
) -> String {
    format!(
        "<span class=\"entry-summary-content\">\
         <span class=\"entry-heading entry-summary-main\">\
         <span class=\"entry-kicker\">{}</span>{}\
         </span>\
         {}\
         </span>\
         <span class=\"entry-meta-cluster entry-summary-meta\">{}</span>",
        escape_html(kicker),
        title_html,
        preview_html.unwrap_or_default(),
        meta_html
    )
}

fn render_entry_meta(item: &ThreadItemSnapshot, meta: &[(String, String)]) -> String {
    format!(
        "{}{}",
        render_meta_pills(meta),
        render_entry_timestamp(item)
    )
}

fn render_text_block(body: Option<&str>, class_name: &str) -> String {
    body.map(|body| format!("<div class=\"{}\">{}</div>", class_name, escape_html(body)))
        .unwrap_or_default()
}

fn render_tool_preview_box(preview: &str) -> String {
    format!(
        "<span class=\"tool-preview-box\">{}</span>",
        escape_html(preview)
    )
}

fn render_meta_pills(meta: &[(String, String)]) -> String {
    if meta.is_empty() {
        return String::new();
    }
    let pills = meta
        .iter()
        .map(|(label, value)| {
            format!(
                "<span class=\"meta-pill\"><span class=\"meta-pill-label\">{}</span>{}</span>",
                escape_html(display_meta_label(label)),
                escape_html(&display_meta_value(label, value))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<span class=\"meta-pills\">{pills}</span>")
}

fn render_entry_timestamp(item: &ThreadItemSnapshot) -> String {
    item.ui_timestamp
        .as_ref()
        .map(|timestamp| timestamp::render(timestamp, &["message-timestamp"]))
        .or_else(|| {
            item.timestamp.as_deref().map(|timestamp| {
                format!(
                    "<span class=\"message-timestamp\">{}</span>",
                    escape_html(timestamp)
                )
            })
        })
        .unwrap_or_default()
}

fn render_optional_preview_text(preview: Option<&str>) -> String {
    preview
        .map(|preview| {
            format!(
                "<span class=\"activity-preview\">{}</span>",
                escape_html(preview)
            )
        })
        .unwrap_or_default()
}

fn render_optional_preview_badge(preview: Option<&str>) -> String {
    preview
        .map(|preview| {
            format!(
                "<span class=\"meta-pill preview-pill\" title=\"{}\">preview</span>",
                escape_html(preview)
            )
        })
        .unwrap_or_default()
}

fn render_optional_body_badge(body_format: Option<&str>) -> String {
    matches!(body_format, Some("diff" | "mixed"))
        .then(|| "<span class=\"meta-pill preview-pill\">diff</span>".to_string())
        .unwrap_or_default()
}

fn render_file_change_stats(item: &ThreadItemSnapshot) -> String {
    let added = meta_value(&item.meta, "addedLines")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let removed = meta_value(&item.meta, "removedLines")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if added == 0 && removed == 0 {
        return String::new();
    }
    format!(
        "<span class=\"meta-pill diff-stats-pill\">\
         <span class=\"diff-stats-add\">+{}</span>\
         <span class=\"diff-stats-remove\">-{}\
         </span></span>",
        added, removed
    )
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

fn render_colored_diff(body: &str) -> String {
    let lines = body
        .lines()
        .map(|line| {
            let class_name = if line.starts_with('+') && !is_diff_metadata_line(line) {
                "diff-line diff-line-add"
            } else if line.starts_with('-') && !is_diff_metadata_line(line) {
                "diff-line diff-line-remove"
            } else if line.starts_with("@@") {
                "diff-line diff-line-hunk"
            } else if is_diff_metadata_line(line) {
                "diff-line diff-line-meta"
            } else {
                "diff-line"
            };
            format!("<div class=\"{}\">{}</div>", class_name, escape_html(line))
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<div class=\"diff-view\">{lines}</div>")
}

fn render_file_change_body(item: &ThreadItemSnapshot) -> String {
    let Some(body) = item.body.as_deref() else {
        return String::new();
    };
    match meta_value(&item.meta, "bodyFormat") {
        Some("diff") => render_colored_diff(body),
        Some("mixed") => render_mixed_file_change_body(body),
        _ => format!("<pre class=\"activity-body\">{}</pre>", escape_html(body)),
    }
}

fn is_diff_metadata_line(line: &str) -> bool {
    if line.starts_with("diff --git ") {
        return true;
    }
    let Some(path) = line
        .strip_prefix("+++ ")
        .or_else(|| line.strip_prefix("--- "))
    else {
        return false;
    };
    let path = path.trim();
    path == "/dev/null" || path.starts_with("a/") || path.starts_with("b/")
}

#[derive(Deserialize)]
struct FileChangeBodySection {
    kind: String,
    path: String,
    body: String,
}

fn render_mixed_file_change_body(body: &str) -> String {
    let Ok(sections) = serde_json::from_str::<Vec<FileChangeBodySection>>(body) else {
        return format!("<pre class=\"activity-body\">{}</pre>", escape_html(body));
    };
    sections
        .iter()
        .map(|section| {
            let content = if section.kind == "diff" {
                render_colored_diff(&section.body)
            } else {
                format!(
                    "<pre class=\"activity-body\">{}</pre>",
                    escape_html(&section.body)
                )
            };
            format!(
                "<section class=\"file-change-section\">\
                 <div class=\"file-change-section-path\"><code>{}</code></div>\
                 {}\
                 </section>",
                escape_html(&section.path),
                content
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn split_reasoning_content(body: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(body) = body.map(str::trim).filter(|body| !body.is_empty()) else {
        return (None, None);
    };
    if let Some((summary, detail)) = body.split_once("\n\n") {
        return (
            Some(summary.trim().to_string()),
            Some(detail.trim().to_string()),
        );
    }
    let summary = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .unwrap_or_else(|| body.to_string());
    let detail = (summary != body).then(|| body.to_string());
    (Some(summary), detail)
}

fn meta_value<'a>(meta: &'a [(String, String)], label: &str) -> Option<&'a str> {
    meta.iter()
        .find(|(candidate, _)| candidate == label)
        .map(|(_, value)| value.as_str())
}

fn display_meta_label(label: &str) -> &str {
    match label {
        "durationMs" => "duration",
        _ => label,
    }
}

fn display_meta_value(label: &str, value: &str) -> String {
    match label {
        "duration" | "durationMs" => format_duration_ms(value),
        _ => value.to_string(),
    }
}

fn format_duration_ms(value: &str) -> String {
    let Ok(ms) = value.parse::<u64>() else {
        return format!("{value} ms");
    };
    if ms < 1_000 {
        return format!("{ms} ms");
    }
    if ms % 1_000 == 0 {
        return format!("{} s", ms / 1_000);
    }
    format!("{:.1} s", ms as f64 / 1_000.0)
}

fn activity_label(item_type: &str) -> &'static str {
    match item_type {
        "mcpToolCall" => "MCP tool",
        "dynamicToolCall" => "Dynamic tool",
        "webSearch" => "Web search",
        "fileChange" => "File change",
        "enteredReviewMode" | "exitedReviewMode" => "Review mode",
        "contextCompaction" => "System",
        _ => "Activity",
    }
}

fn status_class(status: &str) -> &'static str {
    match status {
        "completed" | "success" => "success",
        "failed" | "error" => "danger",
        "in_progress" | "running" => "info",
        _ => "neutral",
    }
}

fn css_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn render_table_section(title: &str, content: String) -> String {
    format!(
        "<section class=\"card\"><h2>{}</h2>{}</section>",
        escape_html(title),
        content
    )
}

fn render_definition_list(items: &[(String, String)]) -> String {
    items
        .iter()
        .map(|(label, value)| {
            format!(
                "<div class=\"pair\"><dt>{}</dt><dd>{}</dd></div>",
                escape_html(label),
                value
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn render_shell(title: &str, active: NavItem, content: String, csrf_token: Option<&str>) -> String {
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Codex GitLab Review {}</title>{}<style>{}{}</style></head><body>\
         <div class=\"layout\">\
         <aside class=\"sidebar\"><div class=\"brand\">Codex GitLab Review</div>{}</aside>\
         <main class=\"content\">{}</main>\
         </div>{}\
         <script>{}</script></body></html>",
        escape_html(title),
        render_feature_flag_csrf_meta_tag(csrf_token),
        page_style(),
        timestamp::style_fragment(),
        render_nav(active),
        content,
        timestamp::script_tag(),
        feature_flag_script(),
    )
}

fn render_rfc3339_timestamp(timestamp: Option<&str>) -> String {
    match timestamp {
        Some(value) => UiTimestamp::from_rfc3339_text(value)
            .map(|timestamp| timestamp::render(&timestamp, &[]))
            .unwrap_or_else(|| escape_html(value)),
        None => "-".to_string(),
    }
}

fn render_unix_timestamp(timestamp: i64) -> String {
    UiTimestamp::from_unix_timestamp(timestamp)
        .map(|timestamp| timestamp::render(&timestamp, &[]))
        .unwrap_or_else(|| escape_html(&timestamp.to_string()))
}

fn render_optional_unix_timestamp(timestamp: Option<i64>) -> String {
    timestamp
        .map(render_unix_timestamp)
        .unwrap_or_else(|| "-".to_string())
}

fn render_nav(active: NavItem) -> String {
    let items = [
        (NavItem::Status, "/status", "Status"),
        (NavItem::History, "/history", "History"),
    ];
    let links = items
        .iter()
        .map(|(item, href, label)| {
            let class = if *item == active {
                "nav-link active"
            } else {
                "nav-link"
            };
            format!(
                "<a class=\"{}\" href=\"{}\">{}</a>",
                class,
                href,
                escape_html(label)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    format!("<nav class=\"nav\">{links}</nav>")
}

fn mr_history_href(repo: &str, iid: u64) -> String {
    format!("/mr/{}/{}/history", encode_repo_key(repo), iid)
}

fn target_label(include_all: bool, count: usize) -> String {
    if include_all {
        "all".to_string()
    } else {
        count.to_string()
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn run_kind_label(kind: RunHistoryKind) -> &'static str {
    match kind {
        RunHistoryKind::Review => "review",
        RunHistoryKind::Mention => "mention",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_feature_flag_csrf_meta_tag(csrf_token: Option<&str>) -> String {
    csrf_token
        .map(|csrf_token| {
            format!(
                "<meta name=\"codex-status-csrf\" content=\"{}\">",
                escape_html(csrf_token)
            )
        })
        .unwrap_or_default()
}

fn feature_flag_script() -> &'static str {
    FEATURE_FLAG_SCRIPT
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NavItem {
    Status,
    History,
}

fn page_style() -> &'static str {
    PAGE_STYLE
}

use super::super::status::StatusRateLimitSnapshot;
use super::html::{
    NavItem, escape_html, render_csrf_hidden_input, render_shell, render_table_section,
    render_unix_timestamp,
};
use crate::review::ReviewLane;
use crate::state::{
    ReviewRateLimitBucketMode, ReviewRateLimitBucketSnapshot, ReviewRateLimitPendingEntry,
    ReviewRateLimitRule, ReviewRateLimitScope, ReviewRateLimitTarget, ReviewRateLimitTargetKind,
};

const RATE_LIMITS_SCRIPT: &str = include_str!("../assets/rate_limits.js");

pub(super) fn rate_limits_script() -> &'static str {
    RATE_LIMITS_SCRIPT
}

pub(in crate::http) fn render_rate_limits_page(
    snapshot: &StatusRateLimitSnapshot,
    target_suggestions: &[ReviewRateLimitTarget],
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let summary = format!(
        "<div class=\"rate-limit-summary\">\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Rules</span><strong>{}</strong></div>\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Active buckets</span><strong>{}</strong></div>\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Queued</span><strong>{}</strong></div>\
         </div>",
        snapshot.rules.len(),
        snapshot.active_buckets.len(),
        snapshot.pending.len(),
    );
    let body = format!(
        "<section class=\"hero hero-actions-bar rate-limit-hero\"><div><h1>Review rate limits</h1><p class=\"muted\">Manage repository- and merge-request scoped review throughput without exposing raw-second configuration.</p>{}</div><div class=\"hero-toolbar\"><button class=\"primary-button\" type=\"button\" data-open-rate-limit-modal=\"create\" aria-label=\"Open create rule modal\">Create rule</button></div></section>\
         <section class=\"rate-limit-page-stack\">\
         {}\
         {}\
         {}\
         </section>\
         {}",
        summary,
        render_rate_limit_rules_section(&snapshot.rules, csrf_token),
        render_rate_limit_buckets_section(&snapshot.active_buckets, csrf_token),
        render_rate_limit_pending_section(&snapshot.pending),
        render_rate_limit_modal(snapshot.rules.as_slice(), target_suggestions, csrf_token),
    );
    render_shell(
        "Review Rate Limits",
        NavItem::RateLimits,
        body,
        csrf_token,
        development_enabled,
    )
}

const GLOBAL_RATE_LIMIT_TARGET_UI_PATH: &str = "*";

fn render_rate_limit_modal(
    rules: &[ReviewRateLimitRule],
    target_suggestions: &[ReviewRateLimitTarget],
    csrf_token: Option<&str>,
) -> String {
    let rules_json =
        json_script_content(&serde_json::to_string(rules).unwrap_or_else(|_| "[]".to_string()));
    let suggestions_json = json_script_content(
        &serde_json::to_string(target_suggestions).unwrap_or_else(|_| "[]".to_string()),
    );
    format!(
        "<script id=\"rate-limit-rules-json\" type=\"application/json\">{rules_json}</script>\
         <script id=\"rate-limit-target-suggestions-json\" type=\"application/json\">{suggestions_json}</script>\
         <dialog class=\"rate-limit-modal\" data-role=\"rate-limit-modal\">\
         <form class=\"rate-limit-modal-form\" method=\"post\" action=\"/rate-limits/create\" data-role=\"rate-limit-form\">\
         <div class=\"rate-limit-modal-shell\">\
         <header class=\"rate-limit-modal-header\">\
         <div class=\"rate-limit-modal-heading\"><p class=\"modal-eyebrow\">Runtime control</p><h2 data-role=\"rate-limit-modal-title\">Create rule</h2><p class=\"muted\">Define throughput limits without forcing one-target rules or raw-second inputs.</p></div>\
         <button class=\"icon-button icon-button-square\" type=\"button\" data-close-rate-limit-modal aria-label=\"Close\">&times;</button>\
         </header>\
         <div class=\"rate-limit-modal-body\">\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{}\">\
         <input type=\"hidden\" name=\"targets_json\" value=\"[]\" data-role=\"rate-limit-targets-json\">\
         <input type=\"hidden\" name=\"bucket_mode\" value=\"shared\" data-role=\"rate-limit-bucket-mode\">\
         <section class=\"modal-section modal-section-emphasis\">\
         <label class=\"modal-field\"><span>Label</span><input name=\"label\" required data-role=\"rate-limit-label\"></label>\
         <label class=\"modal-field\"><span>Scope</span><select name=\"scope\" data-role=\"rate-limit-scope\"><option value=\"project\">Per repository</option><option value=\"merge_request\">Per merge request</option></select><small data-role=\"rate-limit-scope-help\">Per repository creates one bucket per matched repository.</small></label>\
         </section>\
         <section class=\"modal-section modal-section-emphasis\">\
         <div class=\"modal-section-header\"><div><h3>Targets</h3><p class=\"muted\">Add repositories or groups to scope the rule. Leave the list empty to make it global.</p></div></div>\
         <div class=\"target-composer\">\
         <label class=\"modal-field target-kind-field\"><span>Target type</span><select data-role=\"rate-limit-target-kind\"><option value=\"repo\">Repository</option><option value=\"group\">Group</option></select></label>\
         <label class=\"modal-field target-value-field\"><span>Target path</span><input list=\"rate-limit-target-suggestions\" placeholder=\"group/repo or group/subgroup\" data-role=\"rate-limit-target-input\"></label>\
         <div class=\"target-composer-actions\"><button class=\"secondary-button\" type=\"button\" data-role=\"rate-limit-add-target\">Add target</button></div>\
         </div>\
         <datalist id=\"rate-limit-target-suggestions\"></datalist>\
         <div class=\"target-chip-list\" data-role=\"rate-limit-target-list\"></div>\
         </section>\
         <section class=\"modal-section\">\
         <div class=\"modal-section-header\"><div><h3>Bucket behavior</h3><p class=\"muted\" data-role=\"rate-limit-bucket-mode-help\">Choose whether all selected targets share one pool or each target keeps its own pool.</p></div></div>\
         <label class=\"checkbox-row\" data-role=\"rate-limit-shared-row\"><input type=\"checkbox\" checked data-role=\"rate-limit-shared-toggle\"><span>Share one bucket across all selected targets</span></label>\
         </section>\
         <section class=\"modal-section modal-section-emphasis\">\
         <div class=\"modal-grid-two\">\
         <label class=\"modal-field\"><span>Capacity</span><input name=\"capacity\" type=\"number\" min=\"1\" required data-role=\"rate-limit-capacity\"><small>Whole reviews allowed in each scope window.</small></label>\
         <label class=\"modal-field\"><span>Time window</span><input name=\"window_text\" required placeholder=\"2h 15m\" data-role=\"rate-limit-window-text\"><small>Examples: 45m, 2h, 2h 15m.</small></label>\
         </div>\
         </section>\
         <section class=\"modal-section modal-section-emphasis\">\
         <div class=\"modal-section-header\"><div><h3>Applies to</h3><p class=\"muted\">Enable review, security, or both lanes for this rule.</p></div></div>\
         <div class=\"checkbox-stack\">\
         <label class=\"checkbox-row\"><input type=\"checkbox\" name=\"applies_to_review\" value=\"true\" checked data-role=\"rate-limit-review\"><span>Review lane</span></label>\
         <label class=\"checkbox-row\"><input type=\"checkbox\" name=\"applies_to_security\" value=\"true\" data-role=\"rate-limit-security\"><span>Security lane</span></label>\
         </div>\
         </section>\
         </div>\
         <footer class=\"rate-limit-modal-footer\">\
         <button class=\"secondary-button\" type=\"button\" data-close-rate-limit-modal>Cancel</button>\
         <button class=\"primary-button\" type=\"submit\" data-role=\"rate-limit-submit\">Create rule</button>\
         </footer>\
         </div>\
         </form>\
         </dialog>",
        escape_html(csrf_token.unwrap_or_default()),
    )
}

fn json_script_content(raw: &str) -> String {
    raw.replace('<', "\\u003c")
}

fn render_rate_limit_rules_section(
    rules: &[ReviewRateLimitRule],
    csrf_token: Option<&str>,
) -> String {
    render_table_section(
        "Existing rules",
        if rules.is_empty() {
            "<p class=\"empty\">No rules configured.</p>".to_string()
        } else {
            let rows = rules
                .iter()
                .map(|rule| {
                    let rule_id = escape_html(&rule.id);
                    let csrf = render_csrf_hidden_input(csrf_token);
                    format!(
                        "<tr>\
                         <td>{0}</td>\
                         <td>{1}</td>\
                         <td>{2}</td>\
                         <td>{3}</td>\
                         <td>{4}</td>\
                         <td>{5}</td>\
                         <td>{6}</td>\
                         <td>\
                        <div class=\"table-actions\">\
                         <button class=\"secondary-button\" type=\"button\" data-open-rate-limit-modal=\"edit\" data-rule-id=\"{7}\">Edit</button>\
                         <form method=\"post\" action=\"/rate-limits/{7}/delete\">{8}<button class=\"danger-button\" type=\"submit\">Delete</button></form>\
                         </div>\
                        </td>\
                         </tr>",
                        escape_html(&rule.label),
                        escape_html(&render_rate_limit_scope_label(rule)),
                        render_rate_limit_target_badges(&rule.targets),
                        render_rate_limit_bucket_mode_badge(rule.bucket_mode),
                        render_rate_limit_applies(rule.applies_to_review, rule.applies_to_security),
                        rule.capacity,
                        escape_html(&format_duration_compact(rule.window_seconds)),
                        rule_id,
                        csrf,
                    )
                })
                .collect::<String>();
            format!(
                "<div class=\"table-scroll\"><table><thead><tr><th>Label</th><th>Scope</th><th>Targets</th><th>Bucket mode</th><th>Applies</th><th>Capacity</th><th>Window</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        },
    )
}

fn render_rate_limit_target_badges(targets: &[ReviewRateLimitTarget]) -> String {
    if targets.is_empty() {
        return render_rate_limit_target_badge(None, None);
    }
    let badges = targets
        .iter()
        .map(|target| render_rate_limit_target_badge(Some(target.kind), Some(&target.path)))
        .collect::<String>();
    format!("<div class=\"target-badge-list\">{badges}</div>")
}

fn render_rate_limit_target_badge(
    kind: Option<ReviewRateLimitTargetKind>,
    path: Option<&str>,
) -> String {
    if path.is_none_or(|value| value == GLOBAL_RATE_LIMIT_TARGET_UI_PATH) {
        return "<span class=\"target-badge\"><span class=\"target-badge-kind\">Scope</span>Global</span>"
            .to_string();
    }
    let kind_label = match kind.unwrap_or(ReviewRateLimitTargetKind::Repo) {
        ReviewRateLimitTargetKind::Repo => "Repo",
        ReviewRateLimitTargetKind::Group => "Group",
    };
    format!(
        "<span class=\"target-badge\"><span class=\"target-badge-kind\">{}</span>{}</span>",
        escape_html(kind_label),
        escape_html(path.unwrap_or_default())
    )
}

fn render_rate_limit_bucket_mode_badge(bucket_mode: ReviewRateLimitBucketMode) -> String {
    let label = match bucket_mode {
        ReviewRateLimitBucketMode::Shared => "Shared",
        ReviewRateLimitBucketMode::Independent => "Independent",
    };
    format!("<span class=\"badge\">{}</span>", escape_html(label))
}

fn render_rate_limit_scope_label(rule: &ReviewRateLimitRule) -> String {
    match rule.scope {
        ReviewRateLimitScope::Project => "Per repository".to_string(),
        ReviewRateLimitScope::MergeRequest => "Per merge request".to_string(),
    }
}

fn format_duration_compact(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if secs > 0 || parts.is_empty() {
        parts.push(format!("{secs}s"));
    }
    parts.join(" ")
}

fn render_rate_limit_buckets_section(
    active_buckets: &[ReviewRateLimitBucketSnapshot],
    csrf_token: Option<&str>,
) -> String {
    render_table_section(
        "Active buckets",
        if active_buckets.is_empty() {
            "<p class=\"empty\">No active buckets.</p>".to_string()
        } else {
            let rows = active_buckets
                .iter()
                .map(|bucket| {
                    let csrf = render_csrf_hidden_input(csrf_token);
                    format!(
                        "<tr>\
                         <td>{0}</td>\
                         <td>{1}</td>\
                         <td>{2}</td>\
                         <td>{3}</td>\
                         <td>{4}</td>\
                         <td>{5}</td>\
                         <td>{6}</td>\
                         <td>{7}</td>\
                         <td><form method=\"post\" action=\"/rate-limits/buckets/regen\">{8}<input type=\"hidden\" name=\"bucket_id\" value=\"{9}\"><button class=\"secondary-button\" type=\"submit\">Regen 1 slot</button></form></td>\
                         </tr>",
                        escape_html(&bucket.rule_label),
                        escape_html(&bucket.scope_subject),
                        render_rate_limit_target_badge(
                            Some(bucket.target_kind),
                            Some(&bucket.target_path),
                        ),
                        render_rate_limit_bucket_mode_badge(bucket.bucket_mode),
                        escape_html(&format_duration_compact(bucket.window_seconds)),
                        escape_html(&format!(
                            "{:.2} / {}",
                            bucket.available_slots, bucket.capacity
                        )),
                        bucket
                            .next_slot_at.map_or_else(|| "-".to_string(), render_unix_timestamp),
                        render_rate_limit_applies(
                            bucket.applies_to_review,
                            bucket.applies_to_security
                        ),
                        csrf,
                        escape_html(&bucket.bucket_id),
                    )
                })
                .collect::<String>();
            format!(
                "<div class=\"table-scroll\"><table><thead><tr><th>Rule</th><th>Scope</th><th>Target</th><th>Bucket mode</th><th>Window</th><th>Slots</th><th>Next slot</th><th>Applies</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        },
    )
}

fn render_rate_limit_pending_section(pending: &[ReviewRateLimitPendingEntry]) -> String {
    render_table_section(
        "Pending queue",
        if pending.is_empty() {
            "<p class=\"empty\">No pending review items.</p>".to_string()
        } else {
            let rows = pending
                .iter()
                .map(|item| {
                    format!(
                        "<tr>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         </tr>",
                        render_review_lane_label(item.lane),
                        escape_html(&item.repo),
                        item.iid,
                        escape_html(&item.last_seen_head_sha),
                        render_unix_timestamp(item.first_blocked_at),
                        render_unix_timestamp(item.last_blocked_at),
                        render_unix_timestamp(item.next_retry_at),
                    )
                })
                .collect::<String>();
            format!(
                "<div class=\"table-scroll\"><table><thead><tr><th>Lane</th><th>Repo</th><th>IID</th><th>Head SHA</th><th>First blocked</th><th>Last blocked</th><th>Next retry</th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        },
    )
}

fn render_rate_limit_applies(review: bool, security: bool) -> &'static str {
    match (review, security) {
        (true, true) => "review + security",
        (true, false) => "review",
        (false, true) => "security",
        (false, false) => "-",
    }
}

fn render_review_lane_label(lane: ReviewLane) -> &'static str {
    lane.review_label()
}

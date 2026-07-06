use super::html::{
    NavItem, escape_html, render_csrf_hidden_input, render_optional_unix_timestamp,
    render_rfc3339_timestamp, render_shell,
};
use crate::codex_runner::{CodexUsageLimitSnapshot, CodexUsageSnapshot, CodexUsageWindow};
use crate::http::status::{UsageAccountSnapshot, UsagePageSnapshot};
use serde_json::Value;
use std::fmt::Write as _;

pub(in crate::http) fn render_usage_page(
    snapshot: &UsagePageSnapshot,
    reset_notice: Option<(&str, &str)>,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let accounts_with_usage = snapshot
        .accounts
        .iter()
        .filter(|account| account.usage.is_ok())
        .count();
    let reset_eligible_accounts = snapshot
        .accounts
        .iter()
        .filter(|account| account.usage.as_ref().is_ok_and(usage_can_reset))
        .count();
    let summary = format!(
        "<div class=\"rate-limit-summary\">\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Accounts</span><strong>{}</strong></div>\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Loaded</span><strong>{}</strong></div>\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Reset eligible</span><strong>{}</strong></div>\
         <div class=\"summary-chip\"><span class=\"summary-chip-label\">Updated</span><strong>{}</strong></div>\
         </div>",
        snapshot.accounts.len(),
        accounts_with_usage,
        reset_eligible_accounts,
        render_rfc3339_timestamp(Some(&snapshot.generated_at)),
    );
    let body = format!(
        "<section class=\"hero usage-hero\"><h1>Usage limits</h1><p class=\"muted\">Live Codex account limits and reset credits for each configured auth account.</p>{summary}</section>\
         {}\
         <section class=\"rate-limit-page-stack\">{}</section>",
        render_reset_notice(reset_notice),
        snapshot
            .accounts
            .iter()
            .map(|account| render_account(account, csrf_token))
            .collect::<String>(),
    );
    render_shell(
        "Usage Limits",
        NavItem::Usage,
        body,
        csrf_token,
        development_enabled,
    )
}

fn render_reset_notice(reset_notice: Option<(&str, &str)>) -> String {
    let Some((account, outcome)) = reset_notice else {
        return String::new();
    };
    let label = match outcome {
        "reset" => "Reset applied",
        "alreadyRedeemed" => "Reset was already redeemed",
        "nothingToReset" => "Codex reported nothing to reset",
        "noCredit" => "Codex reported no reset credit",
        _ => "Reset request completed",
    };
    format!(
        "<section class=\"notice notice-info\"><strong>{}</strong><span>{}</span></section>",
        escape_html(label),
        escape_html(account),
    )
}

fn render_account(account: &UsageAccountSnapshot, csrf_token: Option<&str>) -> String {
    let usage = match &account.usage {
        Ok(usage) => usage,
        Err(err) => {
            return format!(
                "<section class=\"card usage-account-card\">\
                 <header class=\"usage-account-header\"><div><h2>{}</h2><p class=\"muted\"><code>{}</code></p></div><span class=\"status-pill status-danger\">Unavailable</span></header>\
                 <p class=\"failure-details\">{}</p>\
                 </section>",
                escape_html(&account.name),
                escape_html(&account.auth_host_path),
                escape_html(err),
            );
        }
    };
    let credits_label = usage.rate_limit_reset_credits.as_ref().map_or_else(
        || "reset credits unknown".to_string(),
        |credits| format!("{} reset credits", credits.available_count),
    );
    let weekly_exhausted = usage.has_exhausted_weekly_limit();
    let can_submit = usage_can_reset(usage);
    let action = render_reset_action(&account.name, csrf_token, can_submit);
    format!(
        "<section class=\"card usage-account-card\">\
         <header class=\"usage-account-header\"><div><h2>{}</h2><p class=\"muted\"><code>{}</code></p></div><div class=\"usage-account-badges\"><span class=\"badge\">{}</span>{}</div></header>\
         <div class=\"usage-account-meta\">{}{}{}\
         </div>\
         {}\
         </section>",
        escape_html(&account.name),
        escape_html(&account.auth_host_path),
        escape_html(&credits_label),
        if weekly_exhausted {
            "<span class=\"status-pill status-danger\">Weekly exhausted</span>"
        } else {
            "<span class=\"status-pill status-neutral\">Weekly available</span>"
        },
        render_meta_pair(
            "Local cooldown",
            &render_rfc3339_timestamp(account.local_limit_reset_at.as_deref())
        ),
        render_meta_pair("Limits", &usage.rate_limits_by_limit_id.len().to_string()),
        action,
        render_usage_table(usage),
    )
}

fn render_reset_action(account_name: &str, csrf_token: Option<&str>, can_submit: bool) -> String {
    let disabled = if can_submit { "" } else { " disabled" };
    let help = if can_submit {
        "Weekly limit is exhausted; a reset credit can be consumed."
    } else {
        "Reset is available only when a weekly limit is fully exhausted and a reset credit exists."
    };
    format!(
        "<div class=\"usage-reset-panel\"><form method=\"post\" action=\"/usage/reset\">{}\
         <input type=\"hidden\" name=\"account_name\" value=\"{}\">\
         <button class=\"primary-button\" type=\"submit\"{}>Use reset</button>\
         </form><p class=\"muted\">{}</p></div>",
        render_csrf_hidden_input(csrf_token),
        escape_html(account_name),
        disabled,
        escape_html(help),
    )
}

fn usage_can_reset(usage: &CodexUsageSnapshot) -> bool {
    usage.has_exhausted_weekly_limit()
        && usage
            .rate_limit_reset_credits
            .as_ref()
            .is_some_and(|credits| credits.available_count > 0)
}

fn render_meta_pair(label: &str, value: &str) -> String {
    format!(
        "<div class=\"usage-meta-pair\"><span>{}</span><strong>{}</strong></div>",
        escape_html(label),
        value,
    )
}

fn render_usage_table(usage: &CodexUsageSnapshot) -> String {
    if usage.rate_limits_by_limit_id.is_empty() {
        return "<p class=\"empty\">No usage limits returned.</p>".to_string();
    }
    let rows = usage
        .rate_limits_by_limit_id
        .iter()
        .map(|(limit_id, limit)| render_limit_rows(limit_id, limit))
        .collect::<String>();
    format!(
        "<div class=\"table-scroll\"><table><thead><tr><th>Limit</th><th>Bucket</th><th>Window</th><th>Used</th><th>Remaining</th><th>Resets</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>"
    )
}

fn render_limit_rows(limit_id: &str, limit: &CodexUsageLimitSnapshot) -> String {
    let mut rows = String::new();
    if let Some(primary) = &limit.primary {
        rows.push_str(&render_window_row(limit_id, "Primary", primary, limit));
    }
    if let Some(secondary) = &limit.secondary {
        rows.push_str(&render_window_row(limit_id, "Secondary", secondary, limit));
    }
    if let Some(credits) = &limit.credits {
        rows.push_str(&render_metadata_row(limit_id, "Credits", credits));
    }
    if let Some(individual_limit) = &limit.individual_limit {
        rows.push_str(&render_metadata_row(
            limit_id,
            "Individual limit",
            individual_limit,
        ));
    }
    if rows.is_empty() {
        let _ = write!(
            rows,
            "<tr><td><code>{}</code></td><td colspan=\"6\" class=\"muted\">Limit returned no window data.</td></tr>",
            escape_html(limit_id)
        );
    }
    rows
}

fn render_window_row(
    limit_id: &str,
    bucket: &str,
    window: &CodexUsageWindow,
    limit: &CodexUsageLimitSnapshot,
) -> String {
    let used = window.used_percent.max(0.0);
    let remaining = (100.0 - used).max(0.0);
    let status = if window.is_exhausted_weekly() {
        "<span class=\"status-pill status-danger\">0% weekly remaining</span>".to_string()
    } else {
        limit.rate_limit_reached_type.as_ref().map_or_else(
            || "<span class=\"status-pill status-neutral\">Available</span>".to_string(),
            |reached_type| {
                format!(
                    "<span class=\"status-pill status-info\">{}</span>",
                    escape_html(reached_type)
                )
            },
        )
    };
    format!(
        "<tr>\
         <td><code>{}</code></td>\
         <td>{}</td>\
         <td>{}</td>\
         <td>{:.2}% used</td>\
         <td>{:.2}% left</td>\
         <td>{}</td>\
         <td>{}</td>\
         </tr>",
        escape_html(limit_id),
        escape_html(bucket),
        escape_html(&window_label(window.window_duration_mins)),
        used,
        remaining,
        render_optional_unix_timestamp(window.resets_at),
        status,
    )
}

fn render_metadata_row(limit_id: &str, label: &str, value: &Value) -> String {
    format!(
        "<tr><td><code>{}</code></td><td>{}</td><td colspan=\"5\"><code>{}</code></td></tr>",
        escape_html(limit_id),
        escape_html(label),
        escape_html(&json_compact(value)),
    )
}

fn window_label(window_duration_mins: Option<i64>) -> String {
    let Some(minutes) = window_duration_mins else {
        return "-".to_string();
    };
    if approximately(minutes, 300) {
        "5h".to_string()
    } else if approximately(minutes, 1_440) {
        "Daily".to_string()
    } else if approximately(minutes, 10_080) {
        "Weekly".to_string()
    } else if approximately(minutes, 43_200) {
        "Monthly".to_string()
    } else if approximately(minutes, 525_600) {
        "Annual".to_string()
    } else if minutes % 60 == 0 {
        format!("{}h", minutes / 60)
    } else {
        format!("{minutes}m")
    }
}

fn approximately(actual: i64, expected: i64) -> bool {
    let tolerance = (expected as f64 * 0.05).ceil() as i64;
    (actual - expected).abs() <= tolerance
}

fn json_compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

use super::status;
use crate::state::{
    ReviewRateLimitBucketMode, ReviewRateLimitRuleUpsert, ReviewRateLimitScope,
    ReviewRateLimitTarget,
};
use anyhow::Context;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct HistoryQueryParams {
    pub(crate) repo: Option<String>,
    pub(crate) iid: Option<u64>,
    pub(crate) kind: Option<String>,
    pub(crate) result: Option<String>,
    pub(crate) q: Option<String>,
    pub(crate) limit: Option<usize>,
    pub(crate) page: Option<usize>,
    pub(crate) after: Option<String>,
    pub(crate) before: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FeatureFlagUpdateJson {
    pub(crate) enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CsrfForm {
    pub(crate) csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CsrfBucketForm {
    pub(crate) csrf_token: String,
    pub(crate) bucket_id: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DevelopmentRepoForm {
    pub(crate) csrf_token: String,
    pub(crate) repo_path: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RateLimitRuleForm {
    pub(crate) csrf_token: String,
    pub(crate) label: String,
    pub(crate) scope: String,
    pub(crate) targets_json: String,
    pub(crate) bucket_mode: String,
    pub(crate) applies_to_review: Option<bool>,
    pub(crate) applies_to_security: Option<bool>,
    pub(crate) capacity: u64,
    pub(crate) window_text: String,
}

pub(crate) fn parse_rate_limit_rule_upsert(
    form: RateLimitRuleForm,
) -> anyhow::Result<ReviewRateLimitRuleUpsert> {
    let scope_input = form.scope.trim();
    let scope = ReviewRateLimitScope::from_str(scope_input)
        .with_context(|| format!("invalid scope: {scope_input}"))?;
    let capacity = u32::try_from(form.capacity).context("invalid capacity: must fit in u32")?;
    let targets = serde_json::from_str::<Vec<ReviewRateLimitTarget>>(&form.targets_json)
        .with_context(|| "invalid targets_json")?;
    let bucket_mode = ReviewRateLimitBucketMode::from_str(form.bucket_mode.trim())
        .with_context(|| format!("invalid bucket_mode: {}", form.bucket_mode.trim()))?;
    let window_seconds = parse_duration_text_to_seconds(&form.window_text)
        .with_context(|| format!("invalid window_text: {}", form.window_text.trim()))?;
    Ok(ReviewRateLimitRuleUpsert {
        id: None,
        label: form.label,
        targets,
        bucket_mode,
        scope_iid: None,
        applies_to_review: form.applies_to_review.unwrap_or(false),
        applies_to_security: form.applies_to_security.unwrap_or(false),
        scope,
        capacity,
        window_seconds,
    })
}

fn parse_duration_text_to_seconds(raw: &str) -> anyhow::Result<u64> {
    let mut chars = raw.trim().chars().peekable();
    let mut total = 0u64;
    let mut parsed_any = false;
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut value = String::new();
        while chars.peek().is_some_and(char::is_ascii_digit) {
            value.push(chars.next().expect("peeked digit"));
        }
        if value.is_empty() {
            anyhow::bail!("duration must use value-unit pairs like `2h 15m`");
        }
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut unit = String::new();
        while chars.peek().is_some_and(char::is_ascii_alphabetic) {
            unit.push(chars.next().expect("peeked unit"));
        }
        if unit.is_empty() {
            anyhow::bail!("duration must include a unit after each number");
        }
        let factor = match unit.as_str() {
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600u64,
            "m" | "min" | "mins" | "minute" | "minutes" => 60u64,
            "s" | "sec" | "secs" | "second" | "seconds" => 1u64,
            _ => anyhow::bail!("unsupported duration unit: {unit}"),
        };
        let numeric = value
            .parse::<u64>()
            .with_context(|| format!("invalid duration value: {value}"))?;
        total = total
            .checked_add(numeric.saturating_mul(factor))
            .context("duration is too large")?;
        parsed_any = true;
    }
    if !parsed_any || total == 0 {
        anyhow::bail!("duration must be greater than zero");
    }
    Ok(total)
}

impl HistoryQueryParams {
    pub(crate) fn into_query(self) -> anyhow::Result<status::HistoryQuery> {
        if self.page.is_some() {
            anyhow::bail!("invalid history query: page-based pagination is no longer supported");
        }
        if self.after.is_some() && self.before.is_some() {
            anyhow::bail!("invalid history query: cannot include both after and before cursors");
        }
        Ok(status::HistoryQuery {
            repo: self.repo,
            iid: self.iid,
            kind: match self
                .kind
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                Some("all") => None,
                Some("review") => Some(crate::state::RunHistoryKind::Review),
                Some("security") => Some(crate::state::RunHistoryKind::Security),
                Some("mention") => Some(crate::state::RunHistoryKind::Mention),
                Some(other) => anyhow::bail!("invalid kind filter: {other}"),
                None => None,
            },
            result: self.result.filter(|value| !value.trim().is_empty()),
            search: self.q.filter(|value| !value.trim().is_empty()),
            limit: self.limit.unwrap_or(100),
            after: self.after.filter(|value| !value.trim().is_empty()),
            before: self.before.filter(|value| !value.trim().is_empty()),
        })
    }
}

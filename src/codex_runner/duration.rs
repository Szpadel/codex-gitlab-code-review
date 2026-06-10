pub(crate) fn parse_duration_seconds_from_text(text: &str) -> Option<i64> {
    let tokens = text
        .split_whitespace()
        .map(|raw_token| {
            raw_token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    ',' | ';' | '.' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
                )
            })
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let mut total = 0i64;
    let mut consumed = false;
    let mut idx = 0usize;
    while idx < tokens.len() {
        if let Some(seconds) = parse_duration_token_seconds(tokens[idx]) {
            total = total.saturating_add(seconds);
            consumed = true;
            idx += 1;
            continue;
        }

        if let Ok(value) = tokens[idx].parse::<f64>()
            && let Some(unit_token) = tokens.get(idx + 1)
            && let Some(unit_seconds) = duration_unit_seconds(unit_token)
        {
            total = total.saturating_add(seconds_from_numeric_value(value, unit_seconds));
            consumed = true;
            idx += 2;
            continue;
        }

        if consumed && matches!(tokens[idx], "and" | "then") {
            idx += 1;
            continue;
        }

        if consumed {
            break;
        }
        idx += 1;
    }

    if consumed && total > 0 {
        Some(total)
    } else {
        None
    }
}

pub(crate) fn parse_duration_token_seconds(token: &str) -> Option<i64> {
    let mut numeric_end = 0usize;
    let mut seen_digit = false;
    let mut seen_dot = false;
    for (idx, ch) in token.char_indices() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        if ch == '.' && seen_digit && !seen_dot {
            seen_dot = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        break;
    }
    if !seen_digit || numeric_end == 0 || numeric_end >= token.len() {
        return None;
    }
    let value = token[..numeric_end].parse::<f64>().ok()?;
    let unit = &token[numeric_end..];
    duration_unit_seconds(unit).map(|seconds| seconds_from_numeric_value(value, seconds))
}

pub(crate) fn duration_unit_seconds(unit: &str) -> Option<i64> {
    match unit {
        "d" | "day" | "days" => Some(86_400),
        "h" | "hr" | "hrs" | "hour" | "hours" => Some(3_600),
        "m" | "min" | "mins" | "minute" | "minutes" => Some(60),
        "s" | "sec" | "secs" | "second" | "seconds" => Some(1),
        _ => None,
    }
}

pub(crate) fn seconds_from_numeric_value(value: f64, unit_seconds: i64) -> i64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let seconds = u32::try_from(unit_seconds).ok().unwrap_or(u32::MAX);
    let total = std::time::Duration::from_secs_f64(value * f64::from(seconds));
    let rounded_up = total
        .as_secs()
        .saturating_add(u64::from(total.subsec_nanos() > 0));
    i64::try_from(rounded_up).ok().unwrap_or(i64::MAX)
}

pub(crate) fn safe_cooldown_duration(cooldown_seconds: u64) -> ChronoDuration {
    let seconds = i64::try_from(cooldown_seconds).ok().unwrap_or(i64::MAX);
    safe_duration_from_seconds(seconds)
}

pub(crate) fn safe_duration_from_seconds(seconds: i64) -> ChronoDuration {
    const MAX_CHRONO_SECONDS: i64 = i64::MAX / 1000;
    let clamped = seconds.clamp(0, MAX_CHRONO_SECONDS);
    ChronoDuration::seconds(clamped)
}
use chrono::Duration as ChronoDuration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;

const TIMESTAMP_SCRIPT_TAG: &str = concat!(
    "<script>\n",
    include_str!("assets/timestamp.js"),
    "</script>"
);
const TIMESTAMP_STYLE_FRAGMENT: &str = include_str!("assets/timestamp.css");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UiTimestamp {
    pub(crate) iso_value: String,
    pub(crate) fallback_text: String,
}

impl UiTimestamp {
    pub(crate) fn from_rfc3339_text(text: &str) -> Option<Self> {
        DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|value| Self::from_datetime(value.with_timezone(&Utc)))
    }

    pub(crate) fn from_unix_timestamp(timestamp: i64) -> Option<Self> {
        DateTime::<Utc>::from_timestamp(normalize_unix_timestamp(timestamp), 0)
            .map(Self::from_datetime)
    }

    pub(crate) fn from_history_value(value: &Value) -> Option<Self> {
        match value {
            Value::Number(number) => number.as_i64().and_then(Self::from_unix_timestamp),
            Value::String(text) => Self::from_rfc3339_text(text),
            _ => None,
        }
    }

    pub(crate) fn from_datetime(value: DateTime<Utc>) -> Self {
        Self {
            iso_value: value.to_rfc3339_opts(SecondsFormat::Secs, true),
            fallback_text: value.format("%b %-d, %Y, %-I:%M %p UTC").to_string(),
        }
    }
}

pub(crate) fn render(timestamp: &UiTimestamp, extra_classes: &[&str]) -> String {
    let mut classes = vec!["localized-timestamp"];
    classes.extend(extra_classes.iter().copied());
    format!(
        "<span class=\"{}\" data-timestamp=\"{}\"><time datetime=\"{}\">{}</time><span class=\"timestamp-relative\"></span></span>",
        classes.join(" "),
        escape_html(&timestamp.iso_value),
        escape_html(&timestamp.iso_value),
        escape_html(&timestamp.fallback_text)
    )
}

pub(crate) fn script_tag() -> &'static str {
    TIMESTAMP_SCRIPT_TAG
}

pub(crate) fn style_fragment() -> &'static str {
    TIMESTAMP_STYLE_FRAGMENT
}

fn normalize_unix_timestamp(timestamp: i64) -> i64 {
    if timestamp.unsigned_abs() >= 1_000_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_rfc3339_timestamps_for_ui_display() {
        let timestamp =
            UiTimestamp::from_rfc3339_text("2026-03-10T12:54:00Z").expect("parse rfc3339");
        assert_eq!(timestamp.iso_value, "2026-03-10T12:54:00Z");
        assert_eq!(timestamp.fallback_text, "Mar 10, 2026, 12:54 PM UTC");
    }

    #[test]
    fn normalizes_millisecond_timestamps_for_ui_display() {
        let timestamp =
            UiTimestamp::from_unix_timestamp(1_773_233_640_000).expect("parse milliseconds");
        assert_eq!(timestamp.iso_value, "2026-03-11T12:54:00Z");
        assert_eq!(timestamp.fallback_text, "Mar 11, 2026, 12:54 PM UTC");
    }

    #[test]
    fn ignores_invalid_history_timestamp_values() {
        assert_eq!(UiTimestamp::from_history_value(&json!("not-a-date")), None);
        assert_eq!(UiTimestamp::from_history_value(&json!({"bad": true})), None);
    }
}

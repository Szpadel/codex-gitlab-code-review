//! Publication boundary between untrusted comment text and service-owned markers.

use crate::config::Config;
use crate::flow::review_comments::REVIEW_FINDING_MARKER_PREFIX;

/// Prevents untrusted text from creating review metadata in published comments.
/// Apply this before adding service-owned marker trailers.
pub(crate) fn sanitize_comment_text(config: &Config, text: &str) -> String {
    let prefixes = [
        config.review.comment_marker_prefix.as_str(),
        config.review.security.comment_marker_prefix.as_str(),
        config.review.security.finding_marker_prefix.as_str(),
        REVIEW_FINDING_MARKER_PREFIX,
    ];
    let mut sanitized = text.to_string();
    for prefix in prefixes {
        // Remove reserved prefixes so unclosed markers cannot consume service trailers.
        sanitized = sanitized.replace(prefix, "\u{200b}");
    }
    sanitized
}

//! Shared line classification for diff statistics and rendering.

pub(super) enum DiffLineKind {
    Addition,
    Removal,
    Hunk,
    Metadata,
    Context,
}

/// Treats file headers as metadata only before the first hunk in a file section.
/// A `diff --git` line starts a new file section.
pub(super) fn classified_diff_lines(diff: &str) -> impl Iterator<Item = (&str, DiffLineKind)> {
    let mut in_hunk = false;
    diff.lines().map(move |line| {
        let kind = if line.starts_with("diff --git ") {
            in_hunk = false;
            DiffLineKind::Metadata
        } else if line.starts_with("@@") {
            in_hunk = true;
            DiffLineKind::Hunk
        } else if !in_hunk && is_file_header(line) {
            DiffLineKind::Metadata
        } else if line.starts_with('+') {
            DiffLineKind::Addition
        } else if line.starts_with('-') {
            DiffLineKind::Removal
        } else {
            DiffLineKind::Context
        };
        (line, kind)
    })
}

fn is_file_header(line: &str) -> bool {
    let Some(path) = line
        .strip_prefix("+++ ")
        .or_else(|| line.strip_prefix("--- "))
    else {
        return false;
    };
    let path = path.trim();
    path == "/dev/null" || path.starts_with("a/") || path.starts_with("b/")
}

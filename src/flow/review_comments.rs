use crate::codex_runner::{ReviewComment, repo_checkout_root};
use crate::config::Config;
use crate::flow::comment_text::sanitize_comment_text;
use crate::flow::review_project::ResolvedReviewProject;
use crate::gitlab::{
    DiffDiscussionPosition, GitLabApi, MergeRequest, MergeRequestDiff, MergeRequestDiffDiscussion,
    MergeRequestDiffVersion,
};
use crate::review_deduplication::{
    ReviewDiscussionSource, finding_marker, finding_markers_from_text,
};
use crate::review_finding::ReviewFinding;
use crate::review_lane::ReviewLane;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use tracing::warn;

pub(crate) const REVIEW_FINDING_MARKER_PREFIX: &str = "<!-- codex-review-finding:sha=";
const MAX_INLINE_FINDING_LINE_SPAN: usize = 500;

#[derive(Clone, Copy)]
struct ReviewCommentPostingOptions<'a> {
    config: &'a Config,
    review_label: &'a str,
    comment_marker_prefix: &'a str,
    finding_marker_prefix: &'a str,
}

/// Uses the project identity resolved before Codex runs. Publication does not resolve it again.
pub(crate) struct PostReviewCommentRequest<'a> {
    pub inline_review_comments_enabled: bool,
    pub lane: ReviewLane,
    pub config: &'a Config,
    pub gitlab: &'a dyn GitLabApi,
    pub bot_user_id: u64,
    pub project: &'a ResolvedReviewProject,
    pub repo: &'a str,
    pub mr: &'a MergeRequest,
    pub head_sha: &'a str,
    pub comment: &'a ReviewComment,
    pub discussion_source: Option<&'a ReviewDiscussionSource>,
}

struct FallbackNoteRequest<'a> {
    options: ReviewCommentPostingOptions<'a>,
    repo: &'a str,
    iid: u64,
    head_sha: &'a str,
    comment: &'a ReviewComment,
    fallback_findings: &'a [ReviewFinding],
    project_web_base: &'a str,
    worktree_root: &'a str,
}

#[derive(Debug, Clone)]
struct DiffAnchor {
    old_line: Option<usize>,
    new_line: usize,
}

#[derive(Debug, Clone)]
struct DiffFileAnchors {
    old_path: String,
    new_path: String,
    anchors_by_new_line: HashMap<usize, DiffAnchor>,
}

/// Publishes findings and summary text with the prepared source links.
/// Returns an error if GitLab cannot accept a required comment.
pub(crate) async fn post_review_comment(request: PostReviewCommentRequest<'_>) -> Result<()> {
    let options = posting_options(request.config, request.lane);
    let project_web_base = &request.project.source_web_base;
    let worktree_root = repo_checkout_root(&request.project.project_path);
    if !request.inline_review_comments_enabled {
        let full_body = legacy_note_body(options, request.head_sha, &request.comment.body);
        request
            .gitlab
            .create_note(request.repo, request.mr.iid, &full_body)
            .await?;
        return Ok(());
    }
    if request.comment.findings.is_empty() {
        create_fallback_note(
            request.gitlab,
            FallbackNoteRequest {
                options,
                repo: request.repo,
                iid: request.mr.iid,
                head_sha: request.head_sha,
                comment: request.comment,
                fallback_findings: &[],
                project_web_base: project_web_base.as_str(),
                worktree_root: worktree_root.as_str(),
            },
        )
        .await?;
        return Ok(());
    }

    let mut seen_finding_markers = match load_existing_finding_markers(
        request.gitlab,
        request.repo,
        request.mr.iid,
        request.bot_user_id,
        options.finding_marker_prefix,
        request.discussion_source,
    )
    .await
    {
        Ok(markers) => markers,
        Err(err) => {
            warn!(
                request.repo,
                iid = request.mr.iid,
                head_sha = request.head_sha,
                error = %err,
                "failed to load existing inline review markers; falling back to regular MR note"
            );
            create_fallback_note(
                request.gitlab,
                FallbackNoteRequest {
                    options,
                    repo: request.repo,
                    iid: request.mr.iid,
                    head_sha: request.head_sha,
                    comment: request.comment,
                    fallback_findings: &request.comment.findings,
                    project_web_base: project_web_base.as_str(),
                    worktree_root: worktree_root.as_str(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    let (latest_version, anchors_by_path) = match load_inline_review_context(
        request.gitlab,
        request.repo,
        request.mr.iid,
        request.head_sha,
    )
    .await
    {
        Ok(Some((latest_version, anchors_by_path))) => (Some(latest_version), anchors_by_path),
        Ok(None) => (None, HashMap::new()),
        Err(err) => {
            warn!(
                request.repo,
                iid = request.mr.iid,
                head_sha = request.head_sha,
                error = %err,
                "failed to load inline review metadata; falling back to regular MR note"
            );
            (None, HashMap::new())
        }
    };

    let mut fallback_findings = Vec::new();
    let mut findings = request.comment.findings.iter().peekable();
    while let Some(finding) = findings.next() {
        let marker = finding_marker(options.finding_marker_prefix, request.head_sha, finding);
        if !seen_finding_markers.insert(marker.clone()) {
            continue;
        }

        let Some(discussion) = build_inline_discussion(
            finding,
            latest_version.as_ref(),
            &anchors_by_path,
            options,
            request.head_sha,
            project_web_base.as_str(),
            worktree_root.as_str(),
        ) else {
            fallback_findings.push(finding.clone());
            continue;
        };
        if let Err(err) = request
            .gitlab
            .create_diff_discussion(request.repo, request.mr.iid, &discussion)
            .await
        {
            warn!(
                request.repo,
                iid = request.mr.iid,
                head_sha = request.head_sha,
                error = %err,
                "failed to post inline review discussion; falling back to regular MR note"
            );
            fallback_findings.push(finding.clone());
            for remaining in findings {
                let marker =
                    finding_marker(options.finding_marker_prefix, request.head_sha, remaining);
                if seen_finding_markers.insert(marker) {
                    fallback_findings.push(remaining.clone());
                }
            }
            break;
        }
    }

    if !fallback_findings.is_empty()
        || request.comment.overall_explanation.is_some()
        || request.comment.omitted_duplicate_count > 0
    {
        create_fallback_note(
            request.gitlab,
            FallbackNoteRequest {
                options,
                repo: request.repo,
                iid: request.mr.iid,
                head_sha: request.head_sha,
                comment: request.comment,
                fallback_findings: &fallback_findings,
                project_web_base: project_web_base.as_str(),
                worktree_root: worktree_root.as_str(),
            },
        )
        .await?;
    }

    Ok(())
}

async fn load_inline_review_context(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    head_sha: &str,
) -> Result<Option<(MergeRequestDiffVersion, HashMap<String, DiffFileAnchors>)>> {
    let diff_versions = gitlab.list_mr_diff_versions(repo, iid).await?;
    let Some(latest_version) = select_inline_diff_version(diff_versions, head_sha) else {
        return Ok(None);
    };
    let diff_files = gitlab.list_mr_diffs(repo, iid).await?;
    Ok(Some((latest_version, build_anchor_maps(&diff_files))))
}

fn select_inline_diff_version(
    diff_versions: Vec<MergeRequestDiffVersion>,
    head_sha: &str,
) -> Option<MergeRequestDiffVersion> {
    let latest_version = diff_versions.into_iter().max_by_key(|version| version.id)?;
    (latest_version.head_commit_sha == head_sha).then_some(latest_version)
}

fn build_inline_discussion(
    finding: &ReviewFinding,
    latest_version: Option<&MergeRequestDiffVersion>,
    anchors_by_path: &HashMap<String, DiffFileAnchors>,
    options: ReviewCommentPostingOptions<'_>,
    head_sha: &str,
    project_web_base: &str,
    worktree_root: &str,
) -> Option<MergeRequestDiffDiscussion> {
    let latest_version = latest_version?;
    let relative_path = normalize_repo_path(
        finding.code_location.absolute_file_path.as_str(),
        worktree_root,
    )?;
    let anchors = anchors_by_path.get(relative_path.as_str())?;
    let anchor = select_anchor(anchors, finding)?;

    let content = format!(
        "{}\n\n{}",
        inline_discussion_title(options, finding),
        rewrite_code_references(
            &finding.body,
            relative_path.as_str(),
            project_web_base,
            head_sha,
            worktree_root,
        ),
    );
    let body = format!(
        "{}\n\n{}",
        sanitize_comment_text(options.config, &content),
        finding_marker(options.finding_marker_prefix, head_sha, finding)
    );

    Some(MergeRequestDiffDiscussion {
        body,
        position: DiffDiscussionPosition {
            base_sha: latest_version.base_commit_sha.clone(),
            head_sha: latest_version.head_commit_sha.clone(),
            start_sha: latest_version.start_commit_sha.clone(),
            old_path: anchors.old_path.clone(),
            new_path: anchors.new_path.clone(),
            old_line: anchor.old_line,
            new_line: Some(anchor.new_line),
            line_range: None,
        },
    })
}

fn build_anchor_maps(diff_files: &[MergeRequestDiff]) -> HashMap<String, DiffFileAnchors> {
    diff_files
        .iter()
        .filter(|diff| !diff.collapsed && !diff.too_large && !diff.deleted_file)
        .filter_map(parse_diff_file_anchors)
        .map(|anchors| (anchors.new_path.clone(), anchors))
        .collect()
}

fn parse_diff_file_anchors(diff: &MergeRequestDiff) -> Option<DiffFileAnchors> {
    let mut anchors_by_new_line = HashMap::new();
    let mut old_line = 0usize;
    let mut new_line = 0usize;
    let mut in_hunk = false;

    for line in diff.diff.lines() {
        if let Some((next_old, next_new)) = parse_hunk_header(line) {
            old_line = next_old;
            new_line = next_new;
            in_hunk = true;
            continue;
        }
        if !in_hunk || line == r"\ No newline at end of file" {
            continue;
        }
        match line.chars().next() {
            Some(' ') => {
                anchors_by_new_line.insert(
                    new_line,
                    DiffAnchor {
                        old_line: Some(old_line),
                        new_line,
                    },
                );
                old_line += 1;
                new_line += 1;
            }
            Some('+') => {
                anchors_by_new_line.insert(
                    new_line,
                    DiffAnchor {
                        old_line: None,
                        new_line,
                    },
                );
                new_line += 1;
            }
            Some('-') => {
                old_line += 1;
            }
            _ => {}
        }
    }

    if anchors_by_new_line.is_empty() {
        return None;
    }

    Some(DiffFileAnchors {
        old_path: diff.old_path.clone(),
        new_path: diff.new_path.clone(),
        anchors_by_new_line,
    })
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    if !line.starts_with("@@ ") {
        return None;
    }
    let end = line[3..].find(" @@")?;
    let header = &line[3..(end + 3)];
    let mut parts = header.split(' ');
    let old_part = parts.next()?;
    let new_part = parts.next()?;
    Some((parse_hunk_start(old_part)?, parse_hunk_start(new_part)?))
}

fn parse_hunk_start(part: &str) -> Option<usize> {
    let value = part
        .strip_prefix('-')
        .or_else(|| part.strip_prefix('+'))
        .unwrap_or(part);
    let start = value.split(',').next()?;
    start.parse().ok()
}

fn select_anchor(anchors: &DiffFileAnchors, finding: &ReviewFinding) -> Option<DiffAnchor> {
    let span = finding
        .code_location
        .line_range
        .end
        .saturating_sub(finding.code_location.line_range.start);
    if span > MAX_INLINE_FINDING_LINE_SPAN {
        return None;
    }
    (finding.code_location.line_range.start..=finding.code_location.line_range.end)
        .find_map(|line| anchors.anchors_by_new_line.get(&line).cloned())
}

fn build_fallback_note_body(
    options: ReviewCommentPostingOptions<'_>,
    head_sha: &str,
    comment: &ReviewComment,
    fallback_findings: &[ReviewFinding],
    project_web_base: &str,
    worktree_root: &str,
) -> Option<String> {
    if fallback_findings.is_empty()
        && comment.overall_explanation.is_none()
        && comment.omitted_duplicate_count == 0
    {
        return None;
    }

    let mut sections = Vec::new();
    if let Some(overall_explanation) = &comment.overall_explanation {
        sections.push(rewrite_code_references(
            overall_explanation,
            "",
            project_web_base,
            head_sha,
            worktree_root,
        ));
    }
    if !fallback_findings.is_empty() {
        sections.push(render_fallback_findings(
            options,
            head_sha,
            fallback_findings,
            project_web_base,
            worktree_root,
        ));
    }
    if comment.omitted_duplicate_count > 0 {
        let notice = if comment.omitted_duplicate_count == 1 {
            "_Omitted 1 finding as a duplicate of an existing review thread._".to_string()
        } else {
            format!(
                "_Omitted {} findings as duplicates of existing review threads._",
                comment.omitted_duplicate_count
            )
        };
        sections.push(notice);
    }

    let mut body = sanitize_comment_text(options.config, &sections.join("\n\n"));
    if !body.is_empty() {
        body.push_str("\n\n");
    }
    for finding in fallback_findings {
        body.push_str(&finding_marker(
            options.finding_marker_prefix,
            head_sha,
            finding,
        ));
        body.push('\n');
    }
    let _ = write!(body, "{}{} -->", options.comment_marker_prefix, head_sha);
    Some(body)
}

async fn create_fallback_note(
    gitlab: &dyn GitLabApi,
    request: FallbackNoteRequest<'_>,
) -> Result<()> {
    let body = build_fallback_note_body(
        request.options,
        request.head_sha,
        request.comment,
        request.fallback_findings,
        request.project_web_base,
        request.worktree_root,
    )
    .unwrap_or_else(|| legacy_note_body(request.options, request.head_sha, &request.comment.body));
    gitlab.create_note(request.repo, request.iid, &body).await
}

fn legacy_note_body(
    options: ReviewCommentPostingOptions<'_>,
    head_sha: &str,
    body: &str,
) -> String {
    let body = sanitize_comment_text(options.config, body);
    if options.review_label == "Review" {
        format!(
            "{body}\n\n{}{} -->",
            options.comment_marker_prefix, head_sha
        )
    } else {
        format!(
            "{}\n\n{}\n\n{}{} -->",
            options.review_label, body, options.comment_marker_prefix, head_sha
        )
    }
}

fn render_fallback_findings(
    options: ReviewCommentPostingOptions<'_>,
    head_sha: &str,
    findings: &[ReviewFinding],
    project_web_base: &str,
    worktree_root: &str,
) -> String {
    let mut lines = vec![if options.review_label == "Review" {
        if findings.len() > 1 {
            "Full review comments:".to_string()
        } else {
            "Review comment:".to_string()
        }
    } else if findings.len() > 1 {
        format!("Full {} comments:", options.review_label.to_lowercase())
    } else {
        format!("{} comment:", options.review_label)
    }];

    for finding in findings {
        lines.push(String::new());
        lines.push(format!(
            "- {} — {}",
            finding.title,
            markdown_reference(head_sha, finding, project_web_base, worktree_root)
        ));
        let rewritten_body =
            rewrite_code_references(&finding.body, "", project_web_base, head_sha, worktree_root);
        for body_line in rewritten_body.lines() {
            lines.push(format!("  {body_line}"));
        }
    }

    lines.join("\n")
}

fn markdown_reference(
    head_sha: &str,
    finding: &ReviewFinding,
    project_web_base: &str,
    worktree_root: &str,
) -> String {
    let location = format_location(finding, worktree_root);
    match normalize_repo_path(
        finding.code_location.absolute_file_path.as_str(),
        worktree_root,
    ) {
        Some(relative_path) => format!(
            "[{location}]({})",
            blob_url(
                project_web_base,
                head_sha,
                relative_path.as_str(),
                finding.code_location.line_range.start,
            )
        ),
        None => location,
    }
}

fn format_location(finding: &ReviewFinding, worktree_root: &str) -> String {
    let path = normalize_repo_path(
        finding.code_location.absolute_file_path.as_str(),
        worktree_root,
    )
    .unwrap_or_else(|| finding.code_location.absolute_file_path.clone());
    format!(
        "{path}:{}-{}",
        finding.code_location.line_range.start, finding.code_location.line_range.end
    )
}

fn load_existing_finding_markers_from_text(text: &str, prefix: &str) -> HashSet<String> {
    finding_markers_from_text(text, prefix)
        .into_iter()
        .map(|marker| marker.raw)
        .collect()
}

async fn load_existing_finding_markers(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    bot_user_id: u64,
    finding_marker_prefix: &str,
    discussion_source: Option<&ReviewDiscussionSource>,
) -> Result<HashSet<String>> {
    let mut markers = HashSet::new();
    for note in gitlab.list_notes(repo, iid).await? {
        if note.author.id == bot_user_id {
            markers.extend(load_existing_finding_markers_from_text(
                &note.body,
                finding_marker_prefix,
            ));
        }
    }
    let discussions = if let Some(source) = discussion_source {
        source.discussions().await?
    } else {
        std::sync::Arc::new(gitlab.list_discussions(repo, iid).await?)
    };
    for discussion in discussions.iter() {
        for note in &discussion.notes {
            if note.author.id == bot_user_id {
                markers.extend(load_existing_finding_markers_from_text(
                    &note.body,
                    finding_marker_prefix,
                ));
            }
        }
    }
    Ok(markers)
}

fn posting_options(config: &Config, lane: ReviewLane) -> ReviewCommentPostingOptions<'_> {
    if lane.is_security() {
        ReviewCommentPostingOptions {
            config,
            review_label: lane.review_label(),
            comment_marker_prefix: &config.review.security.comment_marker_prefix,
            finding_marker_prefix: &config.review.security.finding_marker_prefix,
        }
    } else {
        ReviewCommentPostingOptions {
            config,
            review_label: lane.review_label(),
            comment_marker_prefix: &config.review.comment_marker_prefix,
            finding_marker_prefix: REVIEW_FINDING_MARKER_PREFIX,
        }
    }
}

fn inline_discussion_title(
    options: ReviewCommentPostingOptions<'_>,
    finding: &ReviewFinding,
) -> String {
    if options.review_label == "Review" {
        finding.title.clone()
    } else {
        format!("Security finding: {}", finding.title)
    }
}

fn normalize_repo_path(path: &str, worktree_root: &str) -> Option<String> {
    path.strip_prefix(worktree_root)?
        .strip_prefix('/')
        .map(ToOwned::to_owned)
}

fn rewrite_code_references(
    text: &str,
    default_relative_path: &str,
    project_web_base: &str,
    head_sha: &str,
    worktree_root: &str,
) -> String {
    let mut rewritten = String::with_capacity(text.len());
    let mut token_start = None;

    for (idx, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(start) = token_start.take() {
                rewritten.push_str(&rewrite_reference_token(
                    &text[start..idx],
                    default_relative_path,
                    project_web_base,
                    head_sha,
                    worktree_root,
                ));
            }
            rewritten.push(ch);
        } else if token_start.is_none() {
            token_start = Some(idx);
        }
    }

    if let Some(start) = token_start {
        rewritten.push_str(&rewrite_reference_token(
            &text[start..],
            default_relative_path,
            project_web_base,
            head_sha,
            worktree_root,
        ));
    }

    rewritten
}

fn rewrite_reference_token(
    token: &str,
    default_relative_path: &str,
    project_web_base: &str,
    head_sha: &str,
    worktree_root: &str,
) -> String {
    let (trimmed, suffix) = trim_token_suffix(token);
    let Some((relative_path, start_line, end_line, code_label)) =
        parse_reference_token(trimmed, default_relative_path, worktree_root)
            .map(|(relative_path, start_line, end_line)| {
                (relative_path, start_line, end_line, false)
            })
            .or_else(|| parse_backticked_repo_reference_token(trimmed, worktree_root))
    else {
        return token.to_string();
    };
    let label = if start_line == end_line {
        format!("{relative_path}:{start_line}")
    } else {
        format!("{relative_path}:{start_line}-{end_line}")
    };
    let label = if code_label {
        format!("`{label}`")
    } else {
        label
    };
    format!(
        "[{label}]({}){suffix}",
        blob_url(
            project_web_base,
            head_sha,
            relative_path.as_str(),
            start_line
        )
    )
}

fn parse_reference_token(
    token: &str,
    default_relative_path: &str,
    worktree_root: &str,
) -> Option<(String, usize, usize)> {
    let (path, line_range) = token.rsplit_once(':')?;
    let relative_path = if let Some(relative_path) = normalize_repo_path(path, worktree_root) {
        relative_path
    } else if !default_relative_path.is_empty() && path.is_empty() {
        default_relative_path.to_string()
    } else {
        return None;
    };
    let (start, end) = line_range.split_once('-').map_or_else(
        || Some((line_range, line_range)),
        |(start, end)| Some((start, end)),
    )?;
    Some((relative_path, start.parse().ok()?, end.parse().ok()?))
}

fn parse_backticked_repo_reference_token(
    token: &str,
    worktree_root: &str,
) -> Option<(String, usize, usize, bool)> {
    let inner = token.strip_prefix('`')?.strip_suffix('`')?;
    let (path, _) = inner.rsplit_once(':')?;
    normalize_repo_path(path, worktree_root)?;
    parse_reference_token(inner, "", worktree_root)
        .map(|(relative_path, start_line, end_line)| (relative_path, start_line, end_line, true))
}

fn trim_token_suffix(token: &str) -> (&str, &str) {
    let trimmed_len = token.trim_end_matches([',', '.', ')']).len();
    (&token[..trimmed_len], &token[trimmed_len..])
}

fn blob_url(project_web_base: &str, head_sha: &str, relative_path: &str, line: usize) -> String {
    let encoded_path = relative_path
        .split('/')
        .map(|segment| urlencoding::encode(segment).to_string())
        .collect::<Vec<_>>()
        .join("/");
    format!("{project_web_base}/-/blob/{head_sha}/{encoded_path}#L{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publication_uses_resolved_source_links_without_project_lookup() -> Result<()> {
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_string_contains, method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/target%2Frepo/merge_requests/50/notes",
            ))
            .and(body_string_contains(
                "https://gitlab.example.com/fork/source/-/blob/head/src/lib.rs#L10",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 1})))
            .expect(1)
            .mount(&server)
            .await;
        let gitlab = crate::gitlab::GitLabClient::new(&server.uri(), "token")?;
        let config = crate::config::test_builder::ConfigBuilder::for_review_tests().build();
        let mr = serde_json::from_value(json!({
            "iid": 50, "source_project_id": 123, "target_project_id": 456,
            "web_url": "https://gitlab.example.com/target/repo/-/merge_requests/50"
        }))?;
        let project = ResolvedReviewProject {
            project_path: "fork/source".to_string(),
            source_web_base: "https://gitlab.example.com/fork/source".to_string(),
        };
        let comment = ReviewComment {
            summary: "needs changes".to_string(),
            overall_explanation: Some("See /work/repo/fork/source/src/lib.rs:10.".to_string()),
            overall_confidence_score: None,
            findings: Vec::new(),
            body: "legacy body".to_string(),
            omitted_duplicate_count: 0,
        };
        post_review_comment(PostReviewCommentRequest {
            inline_review_comments_enabled: true,
            lane: ReviewLane::General,
            config: &config,
            gitlab: &gitlab,
            bot_user_id: 1,
            project: &project,
            repo: "target/repo",
            mr: &mr,
            head_sha: "head",
            comment: &comment,
            discussion_source: None,
        })
        .await?;
        server.verify().await;
        Ok(())
    }

    #[test]
    fn parse_hunk_header_extracts_old_and_new_starts() {
        assert_eq!(
            parse_hunk_header("@@ -10,4 +12,6 @@ fn demo"),
            Some((10, 12))
        );
    }

    #[test]
    fn parse_diff_file_anchors_maps_context_and_added_lines() {
        let anchors = parse_diff_file_anchors(&MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,2 +10,3 @@\n context\n-old\n+new\n+more\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        })
        .expect("anchors");
        assert_eq!(anchors.anchors_by_new_line[&10].old_line, Some(10));
        assert_eq!(anchors.anchors_by_new_line[&11].old_line, None);
        assert_eq!(anchors.anchors_by_new_line[&12].old_line, None);
    }

    #[test]
    fn select_inline_diff_version_uses_latest_version_when_order_is_unstable() {
        let version = select_inline_diff_version(
            vec![
                MergeRequestDiffVersion {
                    id: 1,
                    head_commit_sha: "older".to_string(),
                    base_commit_sha: "base1".to_string(),
                    start_commit_sha: "start1".to_string(),
                },
                MergeRequestDiffVersion {
                    id: 2,
                    head_commit_sha: "target".to_string(),
                    base_commit_sha: "base2".to_string(),
                    start_commit_sha: "start2".to_string(),
                },
            ],
            "target",
        )
        .expect("matching version");
        assert_eq!(version.id, 2);
    }

    #[test]
    fn finding_markers_round_trip_from_text() {
        let worktree_root = repo_checkout_root("group/repo");
        let finding = ReviewFinding {
            title: "Title".to_string(),
            body: "Body".to_string(),
            confidence_score: None,
            priority: None,
            code_location: crate::review_finding::ReviewCodeLocation {
                absolute_file_path: format!("{worktree_root}/src/lib.rs"),
                line_range: crate::review_finding::ReviewLineRange { start: 3, end: 4 },
            },
        };
        let head_sha = "0123456789abcdef0123456789abcdef01234567";
        let marker = finding_marker(REVIEW_FINDING_MARKER_PREFIX, head_sha, &finding);
        let markers = load_existing_finding_markers_from_text(
            &format!("note\n{marker}\nother"),
            REVIEW_FINDING_MARKER_PREFIX,
        );
        assert!(markers.contains(&marker));
    }

    #[test]
    fn rewrite_code_references_preserves_whitespace_layout() {
        let worktree_root = repo_checkout_root("group/repo");
        let rewritten = rewrite_code_references(
            format!("Paragraph one.\n\n- {worktree_root}/src/lib.rs:10\n- keep").as_str(),
            "",
            "https://gitlab.example.com/group/repo",
            "sha1",
            worktree_root.as_str(),
        );
        assert!(rewritten.contains("\n\n- [src/lib.rs:10]"));
        assert!(rewritten.ends_with("\n- keep"));
    }

    #[test]
    fn rewrite_code_references_does_not_link_arbitrary_word_number_tokens() {
        let worktree_root = repo_checkout_root("group/repo");
        let rewritten = rewrite_code_references(
            "RFC:2119 and step:3 stay plain, but :10 links.",
            "src/lib.rs",
            "https://gitlab.example.com/group/repo",
            "sha1",
            worktree_root.as_str(),
        );
        assert!(rewritten.contains("RFC:2119"));
        assert!(rewritten.contains("step:3"));
        assert!(rewritten.contains("[src/lib.rs:10]"));
    }

    #[test]
    fn normalize_repo_path_strips_nested_project_prefix() {
        let worktree_root = repo_checkout_root("group/repo");
        assert_eq!(
            normalize_repo_path("/work/repo/group/repo/src/lib.rs", worktree_root.as_str()),
            Some("src/lib.rs".to_string())
        );
    }

    #[test]
    fn rewrite_code_references_strips_nested_project_prefix() {
        let worktree_root = repo_checkout_root("group/repo");
        let rewritten = rewrite_code_references(
            "Paragraph one.\n\n- /work/repo/group/repo/src/lib.rs:10\n- keep",
            "",
            "https://gitlab.example.com/group/repo",
            "sha1",
            worktree_root.as_str(),
        );
        assert!(rewritten.contains("\n\n- [src/lib.rs:10]"));
        assert!(rewritten.ends_with("\n- keep"));
    }

    #[test]
    fn rewrite_code_references_links_backticked_nested_project_prefix() {
        let worktree_root = repo_checkout_root("group/repo");
        let rewritten = rewrite_code_references(
            format!("Paragraph one.\n\n- `{worktree_root}/src/lib.rs:10-12`\n- keep").as_str(),
            "",
            "https://gitlab.example.com/group/repo",
            "sha1",
            worktree_root.as_str(),
        );
        assert!(rewritten.contains("\n\n- [`src/lib.rs:10-12`]"));
        assert!(rewritten.ends_with("\n- keep"));
    }

    #[test]
    fn rewrite_code_references_keeps_non_reference_backticks_plain() {
        let worktree_root = repo_checkout_root("group/repo");
        let text = "Leave `RFC:2119` and `step:3` unchanged.";
        let rewritten = rewrite_code_references(
            text,
            "",
            "https://gitlab.example.com/group/repo",
            "sha1",
            worktree_root.as_str(),
        );
        assert_eq!(rewritten, text);
    }

    #[test]
    fn legacy_note_body_preserves_markdown_images() {
        let body = legacy_note_body(
            ReviewCommentPostingOptions {
                config: &crate::config::test_builder::ConfigBuilder::for_review_tests().build(),
                review_label: "Review",
                comment_marker_prefix: "<!-- codex-review:sha=",
                finding_marker_prefix: REVIEW_FINDING_MARKER_PREFIX,
            },
            "sha1",
            "![shot](/uploads/hash/screenshot.png)",
        );

        assert!(body.contains("![shot](/uploads/hash/screenshot.png)"));
        assert!(body.contains("<!-- codex-review:sha=sha1 -->"));
    }

    #[test]
    fn select_anchor_rejects_excessive_line_ranges() {
        let worktree_root = repo_checkout_root("group/repo");
        let anchors = DiffFileAnchors {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            anchors_by_new_line: HashMap::from([(
                10,
                DiffAnchor {
                    old_line: Some(10),
                    new_line: 10,
                },
            )]),
        };
        let finding = ReviewFinding {
            title: "Too wide".to_string(),
            body: "Body".to_string(),
            confidence_score: None,
            priority: None,
            code_location: crate::review_finding::ReviewCodeLocation {
                absolute_file_path: format!("{worktree_root}/src/lib.rs"),
                line_range: crate::review_finding::ReviewLineRange {
                    start: 1,
                    end: MAX_INLINE_FINDING_LINE_SPAN + 2,
                },
            },
        };
        assert!(select_anchor(&anchors, &finding).is_none());
    }

    #[test]
    fn fallback_note_discloses_duplicate_omissions_without_repeating_findings() {
        let options = ReviewCommentPostingOptions {
            config: &crate::config::test_builder::ConfigBuilder::for_review_tests().build(),
            review_label: "Review",
            comment_marker_prefix: "<!-- codex-review:sha=",
            finding_marker_prefix: REVIEW_FINDING_MARKER_PREFIX,
        };
        let comment = ReviewComment {
            summary: "duplicates omitted".to_string(),
            overall_explanation: None,
            overall_confidence_score: None,
            findings: Vec::new(),
            body: "old duplicate body".to_string(),
            omitted_duplicate_count: 1,
        };

        let body = build_fallback_note_body(
            options,
            "head",
            &comment,
            &[],
            "https://gitlab.example.com/group/repo",
            "/work/repo/group/repo",
        )
        .expect("omission note");

        assert!(body.contains("_Omitted 1 finding as a duplicate of an existing review thread._"));
        assert!(!body.contains("old duplicate body"));
    }

    #[test]
    fn fallback_note_pluralizes_duplicate_omissions() {
        let comment = ReviewComment {
            summary: "duplicates omitted".to_string(),
            overall_explanation: None,
            overall_confidence_score: None,
            findings: Vec::new(),
            body: String::new(),
            omitted_duplicate_count: 2,
        };
        let body = build_fallback_note_body(
            ReviewCommentPostingOptions {
                config: &crate::config::test_builder::ConfigBuilder::for_review_tests().build(),
                review_label: "Review",
                comment_marker_prefix: "<!-- codex-review:sha=",
                finding_marker_prefix: REVIEW_FINDING_MARKER_PREFIX,
            },
            "head",
            &comment,
            &[],
            "https://gitlab.example.com/group/repo",
            "/work/repo/group/repo",
        )
        .expect("omission note");

        assert!(body.contains("_Omitted 2 findings as duplicates of existing review threads._"));
    }
}

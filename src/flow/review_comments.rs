use crate::codex_runner::{ReviewComment, ReviewFinding, repo_checkout_root};
use crate::config::Config;
use crate::gitlab::{
    DiffDiscussionPosition, GitLabApi, MergeRequest, MergeRequestDiff, MergeRequestDiffDiscussion,
    MergeRequestDiffVersion,
};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use tracing::warn;
use url::Url;

const REVIEW_FINDING_MARKER_PREFIX: &str = "<!-- codex-review-finding:sha=";
const MAX_INLINE_FINDING_LINE_SPAN: usize = 500;

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

pub(crate) async fn post_review_comment(
    inline_review_comments_enabled: bool,
    config: &Config,
    gitlab: &dyn GitLabApi,
    bot_user_id: u64,
    project_path: &str,
    repo: &str,
    mr: &MergeRequest,
    head_sha: &str,
    comment: &ReviewComment,
) -> Result<()> {
    let project_web_base = resolve_project_web_base(config, gitlab, repo, mr).await;
    let worktree_root = repo_checkout_root(project_path);
    if !inline_review_comments_enabled || comment.findings.is_empty() {
        let full_body = legacy_note_body(config, head_sha, &comment.body);
        gitlab.create_note(repo, mr.iid, &full_body).await?;
        return Ok(());
    }

    let mut seen_finding_markers =
        match load_existing_finding_markers(gitlab, repo, mr.iid, bot_user_id).await {
            Ok(markers) => markers,
            Err(err) => {
                warn!(
                    repo,
                    iid = mr.iid,
                    head_sha,
                    error = %err,
                    "failed to load existing inline review markers; falling back to regular MR note"
                );
                create_fallback_note(
                    config,
                    gitlab,
                    repo,
                    mr.iid,
                    head_sha,
                    comment,
                    &comment.findings,
                    project_web_base.as_str(),
                    worktree_root.as_str(),
                )
                .await?;
                return Ok(());
            }
        };
    let (latest_version, anchors_by_path) =
        match load_inline_review_context(gitlab, repo, mr.iid, head_sha).await {
            Ok(Some((latest_version, anchors_by_path))) => (Some(latest_version), anchors_by_path),
            Ok(None) => (None, HashMap::new()),
            Err(err) => {
                warn!(
                    repo,
                    iid = mr.iid,
                    head_sha,
                    error = %err,
                    "failed to load inline review metadata; falling back to regular MR note"
                );
                (None, HashMap::new())
            }
        };

    let mut fallback_findings = Vec::new();
    let mut findings = comment.findings.iter().peekable();
    while let Some(finding) = findings.next() {
        let marker = finding_marker(head_sha, finding);
        if !seen_finding_markers.insert(marker.clone()) {
            continue;
        }

        let Some(request) = build_inline_discussion(
            finding,
            latest_version.as_ref(),
            &anchors_by_path,
            head_sha,
            project_web_base.as_str(),
            worktree_root.as_str(),
        ) else {
            fallback_findings.push(finding.clone());
            continue;
        };
        if let Err(err) = gitlab.create_diff_discussion(repo, mr.iid, &request).await {
            warn!(
                repo,
                iid = mr.iid,
                head_sha,
                error = %err,
                "failed to post inline review discussion; falling back to regular MR note"
            );
            fallback_findings.push(finding.clone());
            for remaining in findings {
                let marker = finding_marker(head_sha, remaining);
                if seen_finding_markers.insert(marker) {
                    fallback_findings.push(remaining.clone());
                }
            }
            break;
        }
    }

    if !fallback_findings.is_empty() || comment.overall_explanation.is_some() {
        create_fallback_note(
            config,
            gitlab,
            repo,
            mr.iid,
            head_sha,
            comment,
            &fallback_findings,
            project_web_base.as_str(),
            worktree_root.as_str(),
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

    let body = format!(
        "{}\n\n{}\n\n{}",
        finding.title,
        rewrite_code_references(
            &finding.body,
            relative_path.as_str(),
            project_web_base,
            head_sha,
            worktree_root,
        ),
        finding_marker(head_sha, finding)
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
    config: &Config,
    head_sha: &str,
    comment: &ReviewComment,
    fallback_findings: &[ReviewFinding],
    project_web_base: &str,
    worktree_root: &str,
) -> Option<String> {
    if fallback_findings.is_empty() && comment.overall_explanation.is_none() {
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
            head_sha,
            fallback_findings,
            project_web_base,
            worktree_root,
        ));
    }

    let mut body = sections.join("\n\n");
    if !body.is_empty() {
        body.push_str("\n\n");
    }
    for finding in fallback_findings {
        body.push_str(&finding_marker(head_sha, finding));
        body.push('\n');
    }
    body.push_str(&format!(
        "{}{} -->",
        config.review.comment_marker_prefix, head_sha
    ));
    Some(body)
}

async fn create_fallback_note(
    config: &Config,
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    head_sha: &str,
    comment: &ReviewComment,
    fallback_findings: &[ReviewFinding],
    project_web_base: &str,
    worktree_root: &str,
) -> Result<()> {
    let body = build_fallback_note_body(
        config,
        head_sha,
        comment,
        fallback_findings,
        project_web_base,
        worktree_root,
    )
    .unwrap_or_else(|| legacy_note_body(config, head_sha, &comment.body));
    gitlab.create_note(repo, iid, &body).await
}

fn legacy_note_body(config: &Config, head_sha: &str, body: &str) -> String {
    format!(
        "{}\n\n{}{} -->",
        body, config.review.comment_marker_prefix, head_sha
    )
}

fn render_fallback_findings(
    head_sha: &str,
    findings: &[ReviewFinding],
    project_web_base: &str,
    worktree_root: &str,
) -> String {
    let mut lines = vec![if findings.len() > 1 {
        "Full review comments:".to_string()
    } else {
        "Review comment:".to_string()
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

fn load_existing_finding_markers_from_text(text: &str) -> HashSet<String> {
    let mut markers = HashSet::new();
    let mut remaining = text;
    while let Some(start) = remaining.find(REVIEW_FINDING_MARKER_PREFIX) {
        let slice = &remaining[start..];
        let Some(end) = slice.find(" -->") else {
            break;
        };
        markers.insert(slice[..(end + 4)].to_string());
        remaining = &slice[(end + 4)..];
    }
    markers
}

async fn load_existing_finding_markers(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    bot_user_id: u64,
) -> Result<HashSet<String>> {
    let mut markers = HashSet::new();
    for note in gitlab.list_notes(repo, iid).await? {
        if note.author.id == bot_user_id {
            markers.extend(load_existing_finding_markers_from_text(&note.body));
        }
    }
    for discussion in gitlab.list_discussions(repo, iid).await? {
        for note in discussion.notes {
            if note.author.id == bot_user_id {
                markers.extend(load_existing_finding_markers_from_text(&note.body));
            }
        }
    }
    Ok(markers)
}

fn finding_marker(head_sha: &str, finding: &ReviewFinding) -> String {
    let fingerprint = finding_fingerprint(finding);
    format!("{REVIEW_FINDING_MARKER_PREFIX}{head_sha} key={fingerprint} -->")
}

fn finding_fingerprint(finding: &ReviewFinding) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in canonical_finding_key(finding).bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn canonical_finding_key(finding: &ReviewFinding) -> String {
    format!(
        "{}\n{}\n{}:{}",
        finding.title,
        finding.code_location.absolute_file_path,
        finding.code_location.line_range.start,
        finding.code_location.line_range.end
    )
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
    let Some((relative_path, start_line, end_line)) =
        parse_reference_token(trimmed, default_relative_path, worktree_root)
    else {
        return token.to_string();
    };
    let label = if start_line == end_line {
        format!("{relative_path}:{start_line}")
    } else {
        format!("{relative_path}:{start_line}-{end_line}")
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
    let (start, end) = line_range
        .split_once('-')
        .map(|(start, end)| Some((start, end)))
        .unwrap_or_else(|| Some((line_range, line_range)))?;
    Some((relative_path, start.parse().ok()?, end.parse().ok()?))
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

async fn resolve_project_web_base(
    config: &Config,
    gitlab: &dyn GitLabApi,
    repo: &str,
    mr: &MergeRequest,
) -> String {
    if let (Some(source_project_id), Some(target_project_id)) =
        (mr.source_project_id, mr.target_project_id)
        && source_project_id != target_project_id
        && let Ok(project) = gitlab.get_project(&source_project_id.to_string()).await
        && let Some(path_with_namespace) = project.path_with_namespace
    {
        return format!(
            "{}/{}",
            gitlab_web_base(&config.gitlab.base_url),
            path_with_namespace
        );
    }
    project_web_base(config, repo, mr)
}

fn project_web_base(config: &Config, repo: &str, mr: &MergeRequest) -> String {
    if let Some(web_url) = &mr.web_url
        && let Some((base, _)) = web_url.split_once("/-/merge_requests/")
    {
        return base.to_string();
    }
    format!("{}/{}", gitlab_web_base(&config.gitlab.base_url), repo)
}

fn gitlab_web_base(base_url: &str) -> String {
    match Url::parse(base_url) {
        Ok(mut url) => {
            let path = url.path().trim_end_matches('/').to_string();
            let stripped = path.strip_suffix("/api/v4").unwrap_or(&path);
            url.set_path(stripped);
            url.to_string().trim_end_matches('/').to_string()
        }
        Err(_) => base_url
            .trim_end_matches('/')
            .strip_suffix("/api/v4")
            .unwrap_or(base_url.trim_end_matches('/'))
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            code_location: crate::codex_runner::ReviewCodeLocation {
                absolute_file_path: format!("{worktree_root}/src/lib.rs"),
                line_range: crate::codex_runner::ReviewLineRange { start: 3, end: 4 },
            },
        };
        let marker = finding_marker("sha1", &finding);
        let markers = load_existing_finding_markers_from_text(&format!("note\n{marker}\nother"));
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
    fn gitlab_web_base_strips_api_suffix() {
        assert_eq!(
            gitlab_web_base("https://gitlab.example.com/api/v4"),
            "https://gitlab.example.com"
        );
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
            code_location: crate::codex_runner::ReviewCodeLocation {
                absolute_file_path: format!("{worktree_root}/src/lib.rs"),
                line_range: crate::codex_runner::ReviewLineRange {
                    start: 1,
                    end: MAX_INLINE_FINDING_LINE_SPAN + 2,
                },
            },
        };
        assert!(select_anchor(&anchors, &finding).is_none());
    }
}

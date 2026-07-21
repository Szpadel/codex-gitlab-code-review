use crate::codex_runner::ReviewFinding;
use crate::gitlab::{GitLabApi, MergeRequestDiscussion};
use anyhow::Result;
use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingMarker {
    pub raw: String,
    pub head_sha: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExistingReviewThread {
    pub discussion_id: String,
    pub body: String,
    pub reviewed_head_sha: Option<String>,
}

pub(crate) fn finding_marker(
    finding_marker_prefix: &str,
    head_sha: &str,
    finding: &ReviewFinding,
) -> String {
    let fingerprint = finding_fingerprint(finding);
    format!("{finding_marker_prefix}{head_sha} key={fingerprint} -->")
}

fn finding_fingerprint(finding: &ReviewFinding) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in canonical_finding_key(finding).bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
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

pub(crate) struct ReviewDiscussionSource {
    gitlab: Option<Arc<dyn GitLabApi>>,
    repo: String,
    iid: u64,
    bot_user_id: u64,
    current_finding_marker_prefix: String,
    finding_marker_prefixes: Vec<String>,
    cached_discussions: Mutex<Option<Arc<Vec<MergeRequestDiscussion>>>>,
}

impl fmt::Debug for ReviewDiscussionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReviewDiscussionSource")
            .field("repo", &self.repo)
            .field("iid", &self.iid)
            .field("bot_user_id", &self.bot_user_id)
            .field(
                "current_finding_marker_prefix",
                &self.current_finding_marker_prefix,
            )
            .field("finding_marker_prefixes", &self.finding_marker_prefixes)
            .finish_non_exhaustive()
    }
}

impl ReviewDiscussionSource {
    pub(crate) fn new(
        gitlab: Arc<dyn GitLabApi>,
        repo: String,
        iid: u64,
        bot_user_id: u64,
        current_finding_marker_prefix: String,
        finding_marker_prefixes: Vec<String>,
    ) -> Self {
        Self {
            gitlab: Some(gitlab),
            repo,
            iid,
            bot_user_id,
            current_finding_marker_prefix,
            finding_marker_prefixes,
            cached_discussions: Mutex::new(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_discussions(
        discussions: Vec<MergeRequestDiscussion>,
        bot_user_id: u64,
        current_finding_marker_prefix: String,
        finding_marker_prefixes: Vec<String>,
    ) -> Self {
        Self {
            gitlab: None,
            repo: "group/repo".to_string(),
            iid: 11,
            bot_user_id,
            current_finding_marker_prefix,
            finding_marker_prefixes,
            cached_discussions: Mutex::new(Some(Arc::new(discussions))),
        }
    }

    pub(crate) async fn discussions(&self) -> Result<Arc<Vec<MergeRequestDiscussion>>> {
        let mut cached = self.cached_discussions.lock().await;
        if let Some(discussions) = cached.as_ref() {
            return Ok(Arc::clone(discussions));
        }
        let gitlab = self
            .gitlab
            .as_ref()
            .expect("uncached review discussion source has a GitLab client");
        let discussions = Arc::new(gitlab.list_discussions(&self.repo, self.iid).await?);
        *cached = Some(Arc::clone(&discussions));
        Ok(discussions)
    }

    pub(crate) async fn existing_threads(&self) -> Result<Vec<ExistingReviewThread>> {
        let discussions = self.discussions().await?;
        Ok(existing_review_threads(
            discussions.as_ref(),
            self.bot_user_id,
            &self.finding_marker_prefixes,
        ))
    }

    pub(crate) fn current_finding_marker_prefix(&self) -> &str {
        &self.current_finding_marker_prefix
    }
}

pub(crate) fn finding_markers_from_text(text: &str, prefix: &str) -> Vec<FindingMarker> {
    if prefix.is_empty() {
        return Vec::new();
    }

    let mut markers = Vec::new();
    let mut remaining = text;
    while let Some(prefix_offset) = remaining.find(prefix) {
        let candidate = &remaining[prefix_offset..];
        let Some(end_offset) = candidate.find(" -->") else {
            break;
        };
        let raw = &candidate[..end_offset + 4];
        let contents = &candidate[prefix.len()..end_offset];
        if let Some((head_sha, fingerprint)) = contents.split_once(" key=")
            && valid_commit_sha(head_sha)
            && valid_fingerprint(fingerprint)
        {
            markers.push(FindingMarker {
                raw: raw.to_string(),
                head_sha: head_sha.to_string(),
                fingerprint: fingerprint.to_string(),
            });
        }
        remaining = &candidate[end_offset + 4..];
    }
    markers
}

pub(crate) fn existing_review_threads(
    discussions: &[MergeRequestDiscussion],
    bot_user_id: u64,
    finding_marker_prefixes: &[String],
) -> Vec<ExistingReviewThread> {
    if bot_user_id == 0 {
        return Vec::new();
    }

    discussions
        .iter()
        .filter(|discussion| !discussion.individual_note)
        .filter_map(|discussion| {
            let root = discussion
                .notes
                .iter()
                .find(|note| note.in_reply_to_id.is_none())?;
            if root.system || root.author.id != bot_user_id {
                return None;
            }
            let reviewed_head_sha = finding_marker_prefixes.iter().find_map(|prefix| {
                finding_markers_from_text(&root.body, prefix)
                    .into_iter()
                    .next()
                    .map(|marker| marker.head_sha)
            });
            Some(ExistingReviewThread {
                discussion_id: discussion.id.clone(),
                body: root.body.clone(),
                reviewed_head_sha,
            })
        })
        .collect()
}

fn valid_commit_sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::{DiscussionNote, GitLabUser};

    const PREFIX: &str = "<!-- codex-review-finding:sha=";
    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    fn note(id: u64, author_id: u64, body: &str) -> DiscussionNote {
        DiscussionNote {
            id,
            body: body.to_string(),
            author: GitLabUser {
                id: author_id,
                username: None,
                name: None,
            },
            system: false,
            in_reply_to_id: None,
            created_at: None,
        }
    }

    #[test]
    fn parses_only_well_formed_markers_with_valid_commit_shas() {
        let valid = format!("{PREFIX}{SHA} key=0123456789abcdef -->");
        let markers = finding_markers_from_text(
            &format!(
                "before {valid} after {PREFIX}not-a-sha key=0123456789abcdef -->\n{PREFIX}{SHA} key= -->"
            ),
            PREFIX,
        );

        assert_eq!(
            markers,
            vec![FindingMarker {
                raw: valid,
                head_sha: SHA.to_string(),
                fingerprint: "0123456789abcdef".to_string(),
            }]
        );
    }

    #[test]
    fn extracts_only_real_bot_root_threads() {
        let security_prefix = "<!-- codex-security-review-finding:sha=";
        let marker = format!("{security_prefix}{SHA} key=0123456789abcdef -->");
        let eligible = MergeRequestDiscussion {
            id: "eligible".to_string(),
            individual_note: false,
            notes: vec![
                note(1, 7, &format!("finding\n{marker}")),
                note(2, 9, "human reply"),
            ],
        };
        let individual = MergeRequestDiscussion {
            id: "individual".to_string(),
            individual_note: true,
            notes: vec![note(3, 7, &marker)],
        };
        let human_root = MergeRequestDiscussion {
            id: "human".to_string(),
            individual_note: false,
            notes: vec![note(4, 9, &marker), note(5, 7, "bot reply")],
        };
        let mut system_root = note(6, 7, &marker);
        system_root.system = true;
        let system = MergeRequestDiscussion {
            id: "system".to_string(),
            individual_note: false,
            notes: vec![system_root],
        };

        let threads = existing_review_threads(
            &[eligible, individual, human_root, system],
            7,
            &[PREFIX.to_string(), security_prefix.to_string()],
        );

        assert_eq!(
            threads,
            vec![ExistingReviewThread {
                discussion_id: "eligible".to_string(),
                body: format!("finding\n{marker}"),
                reviewed_head_sha: Some(SHA.to_string()),
            }]
        );
    }

    #[test]
    fn keeps_eligible_thread_without_marker_as_text_only_context() {
        let discussions = vec![MergeRequestDiscussion {
            id: "text-only".to_string(),
            individual_note: false,
            notes: vec![note(1, 7, "legacy finding")],
        }];

        assert_eq!(
            existing_review_threads(&discussions, 7, &[PREFIX.to_string()]),
            vec![ExistingReviewThread {
                discussion_id: "text-only".to_string(),
                body: "legacy finding".to_string(),
                reviewed_head_sha: None,
            }]
        );
    }
}

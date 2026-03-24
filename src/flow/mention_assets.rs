use crate::gitlab::DiscussionNote;
use crate::gitlab_links::{GitLabMarkdownImageUpload, extract_markdown_image_uploads};

pub(crate) fn collect_note_image_uploads(
    notes: &[DiscussionNote],
    gitlab_base_url: &str,
) -> Vec<GitLabMarkdownImageUpload> {
    let mut uploads = Vec::new();
    for note in notes {
        for upload in extract_markdown_image_uploads(note.body.as_str(), gitlab_base_url) {
            if !uploads.iter().any(|existing: &GitLabMarkdownImageUpload| {
                existing.absolute_url == upload.absolute_url
            }) {
                uploads.push(upload);
            }
        }
    }
    uploads
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gitlab::{DiscussionNote, GitLabUser};

    #[test]
    fn collect_note_image_uploads_deduplicates_across_notes() {
        let user = GitLabUser {
            id: 1,
            username: Some("reviewer".to_string()),
            name: Some("Reviewer".to_string()),
        };
        let notes = vec![
            DiscussionNote {
                id: 1,
                body: "![one](/uploads/hash/screenshot.png)".to_string(),
                author: user.clone(),
                system: false,
                in_reply_to_id: None,
                created_at: None,
            },
            DiscussionNote {
                id: 2,
                body: "same image ![two](/uploads/hash/screenshot.png)".to_string(),
                author: user,
                system: false,
                in_reply_to_id: None,
                created_at: None,
            },
        ];

        assert_eq!(
            collect_note_image_uploads(&notes, "https://gitlab.example.com"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "/uploads/hash/screenshot.png".to_string(),
                absolute_url: "https://gitlab.example.com/uploads/hash/screenshot.png".to_string(),
                secret: "hash".to_string(),
                filename: "screenshot.png".to_string(),
            }]
        );
    }
}

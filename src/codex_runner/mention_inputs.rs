use super::placeholders::render_placeholders;
use super::{DockerCodexRunner, MentionCommandContext, Url, shell_quote};
use serde_json::{Value, json};
use std::path::Path;
use tracing::warn;

// Limit attachment storage in each mention command.
/// Maximum upload download attempts in one mention command.
pub(crate) const MAX_MENTION_IMAGES: usize = 8;
/// Maximum retained file size in bytes. The downloader reads one extra byte
/// to detect larger responses.
pub(crate) const MAX_MENTION_IMAGE_BYTES: usize = 10 * 1024 * 1024;
/// The downloader returns this status without retaining an oversized image.
pub(crate) const MENTION_IMAGE_TOO_LARGE_EXIT_CODE: i64 = 87;

pub(crate) struct PreparedMentionInputs {
    pub(crate) turn_input: Vec<Value>,
}

impl PreparedMentionInputs {
    fn text_only(prompt: &str) -> Self {
        Self {
            turn_input: build_mention_turn_input(prompt, &[]),
        }
    }
}

pub(crate) fn build_mention_turn_input(prompt: &str, image_paths: &[String]) -> Vec<Value> {
    let mut input = vec![json!({ "type": "text", "text": prompt })];
    input.extend(
        image_paths
            .iter()
            .map(|path| json!({ "type": "localImage", "path": path })),
    );
    input
}

fn sanitized_attachment_filename(filename: &str, index: usize) -> String {
    let raw_name = Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("image");
    let sanitized = raw_name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('_');
    let fallback_name = if sanitized.is_empty() {
        "image".to_string()
    } else {
        sanitized.to_string()
    };
    format!("{:02}-{}", index + 1, fallback_name)
}

fn gitlab_project_upload_api_url(
    git_base: &Url,
    project: &str,
    secret: &str,
    filename: &str,
) -> String {
    let mut api_base = git_base.clone();
    let path = api_base.path().trim_end_matches('/');
    let api_path = if path.ends_with("/api/v4") {
        path.to_string()
    } else if path.is_empty() {
        "/api/v4".to_string()
    } else {
        format!("{path}/api/v4")
    };
    api_base.set_path(&api_path);
    format!(
        "{}/projects/{}/uploads/{}/{}",
        api_base.as_str().trim_end_matches('/'),
        urlencoding::encode(project),
        urlencoding::encode(secret),
        urlencoding::encode(filename),
    )
}

/// Returns the size-limit status for oversized responses. Removes partial files
/// on failure. Reads the GitLab token from the command environment.
pub(crate) fn mention_image_download_exec_command(destination: &str, url: &str) -> Vec<String> {
    let destination_q = shell_quote(destination);
    let url_q = shell_quote(url);
    let max_bytes = MAX_MENTION_IMAGE_BYTES.to_string();
    let too_large_exit_code = MENTION_IMAGE_TOO_LARGE_EXIT_CODE.to_string();
    let script = render_placeholders(
        include_str!("assets/mention_image_download.sh"),
        &[
            ("DESTINATION", &destination_q),
            ("URL", &url_q),
            ("MAX_BYTES", &max_bytes),
            ("TOO_LARGE_EXIT_CODE", &too_large_exit_code),
        ],
    )
    .expect("mention download template placeholders are valid");
    vec!["bash".to_string(), "-lc".to_string(), script]
}

impl DockerCodexRunner {
    pub(crate) async fn prepare_mention_inputs(
        &self,
        container_id: &str,
        repo_dir: &str,
        ctx: &MentionCommandContext,
    ) -> PreparedMentionInputs {
        let mut prompt = ctx.prompt.clone();
        if ctx.image_uploads.len() > MAX_MENTION_IMAGES {
            prompt.push_str(&format!(
                "\n\nSkipped image attachments: {}. The limit is {} images per command.",
                ctx.image_uploads.len() - MAX_MENTION_IMAGES,
                MAX_MENTION_IMAGES
            ));
        }
        let mut prepared = PreparedMentionInputs::text_only(&prompt);
        if ctx.image_uploads.is_empty() {
            return prepared;
        }
        let temp_dir = match self
            .exec_container_command(
                container_id,
                vec![
                    "mktemp".to_string(),
                    "-d".to_string(),
                    "/tmp/codex-mention-images-XXXXXX".to_string(),
                ],
                Some(repo_dir),
            )
            .await
        {
            Ok(output) => output.stdout.trim().to_string(),
            Err(err) => {
                warn!(
                    repo = ctx.discussion_project_path.as_str(),
                    discussion_id = ctx.discussion_id.as_str(),
                    trigger_note_id = ctx.trigger_note_id,
                    error = %err,
                    "failed to allocate mention image temp directory inside container"
                );
                return prepared;
            }
        };
        if temp_dir.is_empty() {
            warn!(
                repo = ctx.discussion_project_path.as_str(),
                discussion_id = ctx.discussion_id.as_str(),
                trigger_note_id = ctx.trigger_note_id,
                "mention image temp directory command returned an empty path"
            );
            return prepared;
        }
        let mut image_paths = Vec::new();
        for (index, upload) in ctx
            .image_uploads
            .iter()
            .take(MAX_MENTION_IMAGES)
            .enumerate()
        {
            let file_name = sanitized_attachment_filename(upload.filename.as_str(), index);
            let destination = format!("{temp_dir}/{file_name}");
            let url = gitlab_project_upload_api_url(
                &self.git_base,
                ctx.discussion_project_path.as_str(),
                upload.secret.as_str(),
                upload.filename.as_str(),
            );
            let command = mention_image_download_exec_command(&destination, &url);
            let download = self
                .exec_container_command_with_env_allow_failure(
                    container_id,
                    command.clone(),
                    Some(repo_dir),
                    Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
                )
                .await;
            if download
                .as_ref()
                .is_ok_and(|output| output.exit_code == MENTION_IMAGE_TOO_LARGE_EXIT_CODE)
            {
                prompt.push_str(&format!(
                    "\n\nImage {} was skipped because it exceeds the {}-byte limit.",
                    index + 1,
                    MAX_MENTION_IMAGE_BYTES
                ));
                continue;
            }
            let download = download.and_then(|output| {
                super::container::validate_container_exec_result(&command, Some(repo_dir), output)
            });
            if let Err(err) = download {
                warn!(
                    repo = ctx.discussion_project_path.as_str(),
                    discussion_id = ctx.discussion_id.as_str(),
                    trigger_note_id = ctx.trigger_note_id,
                    asset_url = upload.absolute_url.as_str(),
                    error = %err,
                    "failed to download mention image upload inside container"
                );
                continue;
            }
            image_paths.push(destination);
        }
        prepared.turn_input = build_mention_turn_input(&prompt, &image_paths);
        prepared
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn oversized_mention_image_download_is_skipped() -> anyhow::Result<()> {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let server = MockServer::start().await;
        for size in [MAX_MENTION_IMAGE_BYTES + 1, MAX_MENTION_IMAGE_BYTES] {
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0; size]))
                .expect(2)
                .mount(&server)
                .await;
            for disabled_tool in ["python3", "curl"] {
                let directory = tempfile::tempdir()?;
                let destination = directory.path().join("image.png");
                let command = mention_image_download_exec_command(
                    destination.to_str().expect("path"),
                    &server.uri(),
                );
                let script = format!(
                    "command() {{ if [ \"$1\" = '-v' ] && [ \"$2\" = '{disabled_tool}' ]; then return 1; fi; builtin command \"$@\"; }}\n{}",
                    command[2]
                );
                let output = tokio::task::spawn_blocking(move || {
                    std::process::Command::new("bash")
                        .arg("-lc")
                        .arg(script)
                        .env("GITLAB_TOKEN", "test-token")
                        .output()
                })
                .await??;

                assert_eq!(
                    output.status.code(),
                    Some(if size > MAX_MENTION_IMAGE_BYTES {
                        87
                    } else {
                        0
                    }),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                if size > MAX_MENTION_IMAGE_BYTES {
                    assert!(!destination.exists());
                } else {
                    assert_eq!(std::fs::read(destination)?, vec![0; size]);
                }
            }
            server.verify().await;
            server.reset().await;
        }
        Ok(())
    }

    #[test]
    fn build_mention_turn_input_appends_local_images_after_text() {
        assert_eq!(
            build_mention_turn_input(
                "Please inspect the screenshots",
                &[
                    "/tmp/codex-mention-images-1/01-first.png".to_string(),
                    "/tmp/codex-mention-images-1/02-second.jpg".to_string(),
                ],
            ),
            vec![
                json!({
                    "type": "text",
                    "text": "Please inspect the screenshots",
                }),
                json!({
                    "type": "localImage",
                    "path": "/tmp/codex-mention-images-1/01-first.png",
                }),
                json!({
                    "type": "localImage",
                    "path": "/tmp/codex-mention-images-1/02-second.jpg",
                }),
            ]
        );
    }

    #[test]
    fn gitlab_project_upload_api_url_uses_api_v4_path() {
        assert_eq!(
            gitlab_project_upload_api_url(
                &Url::parse("https://gitlab.example.com/gitlab").expect("git base"),
                "group/repo",
                "hash",
                "final shot.png",
            ),
            "https://gitlab.example.com/gitlab/api/v4/projects/group%2Frepo/uploads/hash/final%20shot.png"
        );
    }

    #[test]
    fn mention_image_download_exec_command_uses_env_token_reference() {
        let command = mention_image_download_exec_command(
            "/tmp/codex-mention-images-1/01-shot.png",
            "https://gitlab.example.com/api/v4/projects/group%2Frepo/uploads/hash/shot.png",
        );
        assert_eq!(command[0], "bash");
        assert_eq!(command[1], "-lc");
        assert!(command[2].contains("PRIVATE-TOKEN: $GITLAB_TOKEN"));
        assert!(!command[2].contains("token="));
    }

    #[test]
    fn sanitized_attachment_filename_strips_path_components() {
        assert_eq!(
            sanitized_attachment_filename("../screenshots/final shot.png", 1),
            "02-final_shot.png"
        );
    }
}

use super::*;
use serde_json::{Value, json};
use std::path::Path;
use tracing::warn;

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

pub(crate) fn mention_image_download_exec_command(destination: &str, url: &str) -> Vec<String> {
    let destination_q = shell_quote(destination);
    let url_q = shell_quote(url);
    vec![
        "bash".to_string(),
        "-lc".to_string(),
        format!(
            "set -euo pipefail\n\
dest={destination_q}\n\
url={url_q}\n\
if command -v curl >/dev/null 2>&1; then\n\
  curl --fail --silent --show-error --location --header \"PRIVATE-TOKEN: $GITLAB_TOKEN\" --output \"$dest\" \"$url\"\n\
elif command -v python3 >/dev/null 2>&1; then\n\
  DEST=\"$dest\" URL=\"$url\" python3 - <<'PY'\n\
import os\n\
import urllib.request\n\
\n\
request = urllib.request.Request(\n\
    os.environ['URL'],\n\
    headers={{'PRIVATE-TOKEN': os.environ['GITLAB_TOKEN']}},\n\
)\n\
with urllib.request.urlopen(request) as response, open(os.environ['DEST'], 'wb') as handle:\n\
    handle.write(response.read())\n\
PY\n\
else\n\
  printf 'missing curl and python3' >&2\n\
  exit 127\n\
fi"
        ),
    ]
}

impl DockerCodexRunner {
    pub(crate) async fn prepare_mention_inputs(
        &self,
        container_id: &str,
        repo_dir: &str,
        ctx: &MentionCommandContext,
    ) -> PreparedMentionInputs {
        let mut prepared = PreparedMentionInputs::text_only(&ctx.prompt);
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
        for (index, upload) in ctx.image_uploads.iter().enumerate() {
            let file_name = sanitized_attachment_filename(upload.filename.as_str(), index);
            let destination = format!("{temp_dir}/{file_name}");
            let url = gitlab_project_upload_api_url(
                &self.git_base,
                ctx.discussion_project_path.as_str(),
                upload.secret.as_str(),
                upload.filename.as_str(),
            );
            if let Err(err) = self
                .exec_container_command_with_env(
                    container_id,
                    mention_image_download_exec_command(destination.as_str(), url.as_str()),
                    Some(repo_dir),
                    Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
                )
                .await
            {
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
        if image_paths.is_empty() {
            return prepared;
        }
        prepared.turn_input = build_mention_turn_input(&ctx.prompt, &image_paths);
        prepared
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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

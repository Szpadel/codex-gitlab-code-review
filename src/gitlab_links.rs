use pulldown_cmark::{Event, Options, Parser, Tag};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitLabMarkdownImageUpload {
    pub(crate) markdown_path: String,
    pub(crate) absolute_url: String,
    pub(crate) secret: String,
    pub(crate) filename: String,
}

pub(crate) fn gitlab_web_base(base_url: &str) -> String {
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

pub(crate) fn absolutize_root_relative_url(url: &str, gitlab_base: &str) -> String {
    if !url.starts_with('/') || url.starts_with("//") {
        return url.to_string();
    }
    let Ok(mut gitlab_base_url) = Url::parse(gitlab_base) else {
        return format!("{}{}", gitlab_base.trim_end_matches('/'), url);
    };
    let (path, suffix) = split_url_suffix(url);
    let base_path = gitlab_base_url.path().trim_end_matches('/');
    let normalized_path = if base_path.is_empty()
        || path == base_path
        || path.starts_with(&format!("{base_path}/"))
    {
        path.to_string()
    } else {
        format!("{base_path}{path}")
    };
    gitlab_base_url.set_path(&normalized_path);
    gitlab_base_url.set_query(None);
    gitlab_base_url.set_fragment(None);
    format!("{}{}", gitlab_base_url, suffix)
}

pub(crate) fn extract_root_relative_markdown_urls(
    markdown: &str,
    gitlab_base: &str,
) -> Vec<String> {
    let mut urls = Vec::new();
    for event in Parser::new_ext(markdown, Options::empty()) {
        let destination = match event {
            Event::Start(Tag::Link { dest_url, .. })
            | Event::Start(Tag::Image { dest_url, .. }) => Some(dest_url),
            _ => None,
        };
        let Some(destination) = destination else {
            continue;
        };
        let destination = destination.as_ref();
        if !destination.starts_with('/') || destination.starts_with("//") {
            continue;
        }
        let absolute = absolutize_root_relative_url(destination, gitlab_base);
        if !urls.contains(&absolute) {
            urls.push(absolute);
        }
    }
    urls
}

pub(crate) fn extract_markdown_image_uploads(
    markdown: &str,
    gitlab_base: &str,
) -> Vec<GitLabMarkdownImageUpload> {
    let mut uploads = Vec::new();
    for event in Parser::new_ext(markdown, Options::empty()) {
        let Event::Start(Tag::Image { dest_url, .. }) = event else {
            continue;
        };
        let Some(upload) = parse_markdown_image_upload(dest_url.as_ref(), gitlab_base) else {
            continue;
        };
        if !uploads.iter().any(|existing: &GitLabMarkdownImageUpload| {
            existing.absolute_url == upload.absolute_url
        }) {
            uploads.push(upload);
        }
    }
    uploads
}

fn parse_markdown_image_upload(
    markdown_path: &str,
    gitlab_base: &str,
) -> Option<GitLabMarkdownImageUpload> {
    let (normalized_path, absolute_url) =
        normalize_gitlab_upload_image_url(markdown_path, gitlab_base)?;
    let stripped = normalized_path.strip_prefix("/uploads/")?;
    let (secret, filename) = stripped.split_once('/')?;
    if secret.is_empty() || filename.is_empty() {
        return None;
    }
    Some(GitLabMarkdownImageUpload {
        markdown_path: markdown_path.to_string(),
        absolute_url,
        secret: urlencoding::decode(secret).ok()?.into_owned(),
        filename: urlencoding::decode(filename).ok()?.into_owned(),
    })
}

pub(crate) fn normalize_gitlab_upload_image_url(
    markdown_path: &str,
    gitlab_base: &str,
) -> Option<(String, String)> {
    if markdown_path.starts_with("//") {
        return None;
    }
    if markdown_path.starts_with('/') {
        let absolute_url = absolutize_root_relative_url(markdown_path, gitlab_base);
        let gitlab_base = Url::parse(gitlab_base).ok()?;
        let absolute_url_parsed = Url::parse(&absolute_url).ok()?;
        let normalized_path = strip_gitlab_base_path(
            absolute_url_parsed.path(),
            gitlab_base.path().trim_end_matches('/'),
        )?;
        if !normalized_path.starts_with("/uploads/") {
            return None;
        }
        return Some((normalized_path, absolute_url));
    }

    let image_url = Url::parse(markdown_path).ok()?;
    if !matches!(image_url.scheme(), "http" | "https") {
        return None;
    }
    let gitlab_base = Url::parse(gitlab_base).ok()?;
    if image_url.scheme() != gitlab_base.scheme()
        || image_url.host_str() != gitlab_base.host_str()
        || image_url.port_or_known_default() != gitlab_base.port_or_known_default()
    {
        return None;
    }

    let normalized_path =
        strip_gitlab_base_path(image_url.path(), gitlab_base.path().trim_end_matches('/'))?;
    if !normalized_path.starts_with("/uploads/") {
        return None;
    }

    let mut absolute_url = image_url;
    absolute_url.set_fragment(None);
    Some((normalized_path, absolute_url.to_string()))
}

fn strip_gitlab_base_path(path: &str, gitlab_base_path: &str) -> Option<String> {
    if gitlab_base_path.is_empty() {
        return Some(path.to_string());
    }
    if path == gitlab_base_path {
        return Some("/".to_string());
    }
    path.strip_prefix(gitlab_base_path).map(str::to_string)
}

fn split_url_suffix(url: &str) -> (&str, &str) {
    let suffix_start = url.find(['?', '#']).unwrap_or(url.len());
    (&url[..suffix_start], &url[suffix_start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_web_base_strips_api_suffix() {
        assert_eq!(
            gitlab_web_base("https://gitlab.example.com/api/v4"),
            "https://gitlab.example.com"
        );
    }

    #[test]
    fn extract_root_relative_markdown_urls_absolutizes_image_destinations() {
        let markdown = "![shot](/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_root_relative_markdown_urls(markdown, "https://gitlab.example.com"),
            vec!["https://gitlab.example.com/uploads/hash/screenshot.png".to_string()]
        );
    }

    #[test]
    fn extract_root_relative_markdown_urls_preserves_prefixed_relative_url_root_paths() {
        let markdown = "![shot](/gitlab/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_root_relative_markdown_urls(markdown, "https://gitlab.example.com/gitlab"),
            vec!["https://gitlab.example.com/gitlab/uploads/hash/screenshot.png".to_string()]
        );
    }

    #[test]
    fn extract_root_relative_markdown_urls_keeps_absolute_destinations() {
        let markdown = "![shot](https://cdn.example.com/screenshot.png)";
        assert_eq!(
            extract_root_relative_markdown_urls(markdown, "https://gitlab.example.com"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn extract_markdown_image_uploads_returns_upload_metadata() {
        let markdown = "![shot](/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "/uploads/hash/screenshot.png".to_string(),
                absolute_url: "https://gitlab.example.com/uploads/hash/screenshot.png".to_string(),
                secret: "hash".to_string(),
                filename: "screenshot.png".to_string(),
            }]
        );
    }

    #[test]
    fn extract_markdown_image_uploads_decodes_url_encoded_filename() {
        let markdown = "![shot](/uploads/hash/screenshot%20final.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "/uploads/hash/screenshot%20final.png".to_string(),
                absolute_url: "https://gitlab.example.com/uploads/hash/screenshot%20final.png"
                    .to_string(),
                secret: "hash".to_string(),
                filename: "screenshot final.png".to_string(),
            }]
        );
    }

    #[test]
    fn extract_markdown_image_uploads_accepts_same_origin_absolute_urls() {
        let markdown = "![shot](https://gitlab.example.com/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "https://gitlab.example.com/uploads/hash/screenshot.png".to_string(),
                absolute_url: "https://gitlab.example.com/uploads/hash/screenshot.png".to_string(),
                secret: "hash".to_string(),
                filename: "screenshot.png".to_string(),
            }]
        );
    }

    #[test]
    fn extract_markdown_image_uploads_accepts_same_origin_absolute_urls_with_subpath() {
        let markdown = "![shot](https://gitlab.example.com/gitlab/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com/gitlab"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "https://gitlab.example.com/gitlab/uploads/hash/screenshot.png"
                    .to_string(),
                absolute_url: "https://gitlab.example.com/gitlab/uploads/hash/screenshot.png"
                    .to_string(),
                secret: "hash".to_string(),
                filename: "screenshot.png".to_string(),
            }]
        );
    }

    #[test]
    fn extract_markdown_image_uploads_accepts_prefixed_root_relative_urls_with_subpath() {
        let markdown = "![shot](/gitlab/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com/gitlab"),
            vec![GitLabMarkdownImageUpload {
                markdown_path: "/gitlab/uploads/hash/screenshot.png".to_string(),
                absolute_url: "https://gitlab.example.com/gitlab/uploads/hash/screenshot.png"
                    .to_string(),
                secret: "hash".to_string(),
                filename: "screenshot.png".to_string(),
            }]
        );
    }

    #[test]
    fn extract_markdown_image_uploads_rejects_foreign_absolute_urls() {
        let markdown = "![shot](https://cdn.example.com/uploads/hash/screenshot.png)";
        assert_eq!(
            extract_markdown_image_uploads(markdown, "https://gitlab.example.com"),
            Vec::<GitLabMarkdownImageUpload>::new()
        );
    }
}

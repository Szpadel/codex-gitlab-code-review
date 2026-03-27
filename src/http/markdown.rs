use crate::gitlab_links::{
    absolutize_root_relative_url, gitlab_web_base, normalize_gitlab_upload_image_url,
};
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, html};

pub(super) fn render_safe_markdown(markdown: &str, gitlab_base_url: &str) -> String {
    let gitlab_web_base = gitlab_web_base(gitlab_base_url);
    let parser = Parser::new_ext(markdown, markdown_options())
        .map(|event| sanitize_markdown_event(event, gitlab_web_base.as_str()));
    let mut rendered = String::new();
    html::push_html(&mut rendered, parser);
    rendered
}

fn markdown_options() -> Options {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    options
}

fn sanitize_markdown_event<'a>(event: Event<'a>, gitlab_web_base: &str) -> Event<'a> {
    match event {
        Event::Start(tag) => Event::Start(sanitize_tag(tag, gitlab_web_base)),
        Event::SoftBreak => Event::HardBreak,
        Event::Html(raw) | Event::InlineHtml(raw) => {
            Event::Text(CowStr::Boxed(raw.into_string().into_boxed_str()))
        }
        _ => event,
    }
}

fn sanitize_tag<'a>(tag: Tag<'a>, gitlab_web_base: &str) -> Tag<'a> {
    match tag {
        Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        } => Tag::Link {
            link_type,
            dest_url: sanitize_link_destination(dest_url, gitlab_web_base),
            title,
            id,
        },
        Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        } => Tag::Image {
            link_type,
            dest_url: sanitize_image_destination(dest_url, gitlab_web_base),
            title,
            id,
        },
        _ => tag,
    }
}

fn sanitize_link_destination<'a>(dest_url: CowStr<'a>, gitlab_web_base: &str) -> CowStr<'a> {
    let resolved = absolutize_root_relative_url(&dest_url, gitlab_web_base);
    if is_safe_link_destination(resolved.as_str()) {
        CowStr::Boxed(resolved.into_boxed_str())
    } else {
        CowStr::Boxed("#".to_string().into_boxed_str())
    }
}

fn sanitize_image_destination<'a>(dest_url: CowStr<'a>, gitlab_web_base: &str) -> CowStr<'a> {
    if let Some((_, absolute_url)) = normalize_gitlab_upload_image_url(&dest_url, gitlab_web_base) {
        CowStr::Boxed(absolute_url.into_boxed_str())
    } else {
        CowStr::Boxed("data:,".to_string().into_boxed_str())
    }
}

fn is_safe_link_destination(url: &str) -> bool {
    is_safe_http_like_destination(url) || url.starts_with('#') || url.starts_with("mailto:")
}

fn is_safe_http_like_destination(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_safe_markdown_absolutizes_gitlab_upload_images() {
        let html = render_safe_markdown(
            "![shot](/uploads/hash/screenshot.png)",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("img"));
        assert!(html.contains("https://gitlab.example.com/uploads/hash/screenshot.png"));
    }

    #[test]
    fn render_safe_markdown_escapes_raw_html() {
        let html = render_safe_markdown(
            "<script>alert(1)</script>\n\nsafe",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn render_safe_markdown_blocks_javascript_links() {
        let html = render_safe_markdown(
            "[bad](javascript:alert(1))",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("href=\"#\""));
        assert!(!html.contains("javascript:alert"));
    }

    #[test]
    fn render_safe_markdown_preserves_single_line_breaks() {
        let html = render_safe_markdown("line one\nline two", "https://gitlab.example.com/api/v4");

        assert!(html.contains("line one<br"));
        assert!(html.contains("line two"));
    }

    #[test]
    fn render_safe_markdown_blocks_remote_images() {
        let html = render_safe_markdown(
            "![shot](https://attacker.example/pixel.png)",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("<img src=\"data:,\""));
        assert!(!html.contains("attacker.example"));
    }

    #[test]
    fn render_safe_markdown_keeps_same_origin_absolute_images() {
        let html = render_safe_markdown(
            "![shot](https://gitlab.example.com/uploads/hash/screenshot.png)",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("https://gitlab.example.com/uploads/hash/screenshot.png"));
    }

    #[test]
    fn render_safe_markdown_keeps_prefixed_relative_url_root_upload_images() {
        let html = render_safe_markdown(
            "![shot](/gitlab/uploads/hash/screenshot.png)",
            "https://gitlab.example.com/gitlab/api/v4",
        );

        assert!(html.contains("https://gitlab.example.com/gitlab/uploads/hash/screenshot.png"));
    }

    #[test]
    fn render_safe_markdown_blocks_same_origin_non_upload_images() {
        let html = render_safe_markdown(
            "![shot](https://gitlab.example.com/api/v4/projects)",
            "https://gitlab.example.com/api/v4",
        );

        assert!(html.contains("<img src=\"data:,\""));
        assert!(!html.contains("https://gitlab.example.com/api/v4/projects"));
    }
}

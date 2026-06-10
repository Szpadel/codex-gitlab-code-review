use super::html::{
    NavItem, encode_repo_key, escape_html, render_csrf_hidden_input, render_rfc3339_timestamp,
    render_shell,
};
use crate::dev_mode::DevelopmentSnapshot;

pub(in crate::http) fn render_development_page(
    snapshot: &DevelopmentSnapshot,
    csrf_token: Option<&str>,
) -> String {
    let add_repo_form = format!(
        "<section class=\"card\"><h2>Add repository</h2>\
         <form class=\"filters\" method=\"post\" action=\"/development/repos/create\">\
         {}\
         <label class=\"filter-field filter-field-wide\"><span>Repo path</span><input name=\"repo_path\" required placeholder=\"group/project\"></label>\
         <div class=\"filter-actions\"><button type=\"submit\">Add repo</button></div>\
         </form></section>",
        render_csrf_hidden_input(csrf_token),
    );
    let repo_rows = snapshot
        .repos
        .iter()
        .map(|repo| {
            let repo_key = encode_repo_key(&repo.repo_path);
            let active_mr = repo
                .active_mr_iid.map_or_else(|| "No active synthetic MR.".to_string(), |iid| format!("Active MR !{iid}"));
            let revision = repo
                .active_revision.map_or_else(|| "-".to_string(), |revision| format!("Revision {revision}"));
            let head_sha = repo
                .active_head_sha
                .as_deref().map_or_else(|| "-".to_string(), |head_sha| format!("<code>{}</code>", escape_html(head_sha)));
            let updated_at = render_rfc3339_timestamp(repo.updated_at.as_deref());
            let csrf = render_csrf_hidden_input(csrf_token);
            format!(
                "<tr>\
                 <td>\
                 <form class=\"filters\" method=\"post\" action=\"/development/repos/{repo_key}/update\">\
                 {csrf}\
                 <label class=\"filter-field filter-field-wide\"><span>Repo path</span><input name=\"repo_path\" value=\"{repo_path}\" required></label>\
                 <div class=\"filter-actions\"><button type=\"submit\">Rename</button></div>\
                 </form>\
                 </td>\
                 <td>{active_mr}</td>\
                 <td>{revision}</td>\
                 <td>{head_sha}</td>\
                 <td>{updated_at}</td>\
                 <td>\
                 <form class=\"filter-actions\" method=\"post\" action=\"/development/repos/{repo_key}/simulate-mr\">{csrf}<button type=\"submit\">New MR</button></form>\
                 <form class=\"filter-actions\" method=\"post\" action=\"/development/repos/{repo_key}/simulate-commit\">{csrf}<button type=\"submit\">New commit</button></form>\
                 <form class=\"filter-actions\" method=\"post\" action=\"/development/repos/{repo_key}/delete\">{csrf}<button class=\"danger-button\" type=\"submit\">Delete</button></form>\
                 </td>\
                 </tr>",
                repo_path = escape_html(&repo.repo_path),
                active_mr = escape_html(&active_mr),
                revision = escape_html(&revision),
                head_sha = head_sha,
                updated_at = updated_at,
                csrf = csrf,
            )
        })
        .collect::<String>();
    let repo_table = format!(
        "<section class=\"card\"><h2>Repositories</h2>\
         <p class=\"muted\">Synthetic repos live in memory only. Restarting dev mode resets them to defaults.</p>\
         <table><thead><tr><th>Repo</th><th>Active MR</th><th>Revision</th><th>Head SHA</th><th>Updated</th><th>Actions</th></tr></thead><tbody>{repo_rows}</tbody></table>\
         </section>"
    );
    let body = format!(
        "<section class=\"hero\"><h1>Development tools</h1><p class=\"muted\">Mocked GitLab and mocked Codex are active. Runtime state database: <code>{}</code>.</p></section>{add_repo_form}{repo_table}",
        escape_html(&snapshot.database_path),
    );
    render_shell("Development", NavItem::Development, body, csrf_token, true)
}

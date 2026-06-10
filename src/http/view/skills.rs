use super::html::{
    NavItem, escape_html, render_csrf_hidden_input, render_definition_list, render_shell,
    render_table_section,
};
use crate::skills::{
    SkillAccountSnapshot, SkillListSnapshot, SkillPreviewSnapshot, SkillSyncState,
};

pub(in crate::http) fn render_skills_page(
    snapshot: &SkillListSnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let body = format!(
        "<section class=\"hero\"><h1>Skills</h1><p class=\"muted\">Upload, preview, and delete user-managed Codex skills.</p></section>\
         <section class=\"card\"><h2>Upload skill archive</h2>\
         <form class=\"filters upload-form\" method=\"post\" action=\"/skills/upload\" enctype=\"multipart/form-data\">\
         {}\
         <label class=\"filter-field filter-field-wide\"><span>Archive</span><input type=\"file\" name=\"archive\" accept=\".zip,.tar,.tar.gz,.tgz\" required></label>\
         <div class=\"filter-actions\"><button type=\"submit\">Upload</button></div>\
         </form></section>\
         {}",
        render_csrf_hidden_input(csrf_token),
        render_skill_table(snapshot)
    );
    render_shell(
        "Skills",
        NavItem::Skills,
        body,
        csrf_token,
        development_enabled,
    )
}

pub(in crate::http) fn render_skill_detail_page(
    snapshot: &SkillPreviewSnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let metadata = vec![
        ("Name".to_string(), escape_html(&snapshot.name)),
        (
            "Description".to_string(),
            escape_html(snapshot.description.as_deref().unwrap_or("-")),
        ),
        (
            "Sync state".to_string(),
            escape_html(skill_sync_state_label(snapshot.sync_state)),
        ),
        (
            "Canonical path".to_string(),
            escape_html(&snapshot.canonical_path),
        ),
        (
            "Files".to_string(),
            escape_html(&snapshot.file_paths.len().to_string()),
        ),
    ];
    let body = format!(
        "<section class=\"hero\"><h1>Skill preview</h1><p class=\"muted\"><code>{}</code> across {} configured Codex home(s).</p></section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>Overview</h2><dl>{}</dl></article>\
         <article class=\"card\"><h2>Accounts</h2>{}</article>\
         </section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>SKILL.md</h2><pre class=\"codeblock\">{}</pre></article>\
         <article class=\"card\"><h2>Installed files</h2>{}</article>\
         </section>\
         <section class=\"card\"><h2>Delete skill</h2>\
         <form method=\"post\" action=\"/skills/{}/delete\">{}<button class=\"danger-button\" type=\"submit\">Delete</button></form>\
         </section>",
        escape_html(&snapshot.name),
        snapshot.accounts.len(),
        render_definition_list(&metadata),
        render_skill_account_table(&snapshot.accounts),
        escape_html(&snapshot.skill_markdown),
        render_skill_file_list(&snapshot.file_paths),
        escape_html(&snapshot.name),
        render_csrf_hidden_input(csrf_token),
    );
    render_shell(
        "Skill Preview",
        NavItem::Skills,
        body,
        csrf_token,
        development_enabled,
    )
}

fn render_skill_table(snapshot: &SkillListSnapshot) -> String {
    render_table_section(
        "Installed skills",
        if snapshot.skills.is_empty() {
            "<p class=\"empty\">No user-managed skills are installed.</p>".to_string()
        } else {
            let rows = snapshot
                .skills
                .iter()
                .map(|skill| {
                    format!(
                        "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}/{}</td><td><a href=\"/skills/{}\">Preview</a></td></tr>",
                        escape_html(&skill.name),
                        escape_html(skill.description.as_deref().unwrap_or("-")),
                        render_skill_sync_state_badge(skill.sync_state),
                        skill.installed_accounts,
                        skill.total_accounts,
                        escape_html(&skill.name)
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Accounts</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_skill_account_table(accounts: &[SkillAccountSnapshot]) -> String {
    if accounts.is_empty() {
        return "<p class=\"empty\">No managed accounts configured.</p>".to_string();
    }
    let rows = accounts
        .iter()
        .map(|account| {
            let state = if !account.installed {
                render_skill_sync_state_badge(SkillSyncState::MissingOnSomeAccounts)
            } else if account.matches_canonical {
                render_skill_sync_state_badge(SkillSyncState::Synced)
            } else {
                render_skill_sync_state_badge(SkillSyncState::ContentMismatch)
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&account.account_name),
                state,
                escape_html(account.root_path.as_deref().unwrap_or("-"))
            )
        })
        .collect::<String>();
    format!(
        "<table><thead><tr><th>Account</th><th>Status</th><th>Path</th></tr></thead><tbody>{rows}</tbody></table>"
    )
}

fn render_skill_file_list(file_paths: &[String]) -> String {
    if file_paths.is_empty() {
        return "<p class=\"empty\">No files were detected.</p>".to_string();
    }
    let items = file_paths
        .iter()
        .map(|path| format!("<li><code>{}</code></li>", escape_html(path)))
        .collect::<String>();
    format!("<ul class=\"simple-list monospace-list\">{items}</ul>")
}

fn render_skill_sync_state_badge(state: SkillSyncState) -> String {
    let (class_name, label) = match state {
        SkillSyncState::Synced => ("status-success", "synced"),
        SkillSyncState::MissingOnSomeAccounts => ("status-neutral", "missing on some accounts"),
        SkillSyncState::ContentMismatch => ("status-danger", "content mismatch"),
    };
    format!(
        "<span class=\"status-pill {}\">{}</span>",
        class_name,
        escape_html(label)
    )
}

fn skill_sync_state_label(state: SkillSyncState) -> &'static str {
    match state {
        SkillSyncState::Synced => "synced",
        SkillSyncState::MissingOnSomeAccounts => "missing on some accounts",
        SkillSyncState::ContentMismatch => "content mismatch",
    }
}

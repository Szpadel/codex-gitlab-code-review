use crate::config::Config;
use crate::transcript_backfill::{SessionHistoryBackfillSource, TranscriptBackfillSource};
use std::collections::HashMap;
use std::sync::Arc;

pub(super) fn build_account_transcript_backfill_sources(
    config: &Config,
    default_source: Arc<dyn TranscriptBackfillSource>,
) -> HashMap<String, Arc<dyn TranscriptBackfillSource>> {
    let configured_session_history_path = config.codex.session_history_path.as_deref();
    let primary_session_history_path = primary_session_history_path(
        &config.codex.auth_host_path,
        &config.codex.auth_mount_path,
        configured_session_history_path,
    );

    let mut sources = HashMap::new();
    sources.insert("primary".to_string(), default_source);
    for account in &config.codex.fallback_auth_accounts {
        let session_history_path = fallback_session_history_path(
            &config.codex.auth_host_path,
            &config.codex.auth_mount_path,
            &primary_session_history_path,
            &account.auth_host_path,
        );
        sources.insert(
            account.name.clone(),
            Arc::new(SessionHistoryBackfillSource::new(session_history_path))
                as Arc<dyn TranscriptBackfillSource>,
        );
    }
    sources
}

pub(crate) fn primary_session_history_path(
    auth_host_path: &str,
    _auth_mount_path: &str,
    configured_session_history_path: Option<&str>,
) -> String {
    configured_session_history_path.map_or_else(
        || format!("{}/sessions", auth_host_path.trim_end_matches('/')),
        ToString::to_string,
    )
}

pub(crate) fn fallback_session_history_path(
    primary_auth_host_path: &str,
    primary_auth_mount_path: &str,
    primary_session_history_path: &str,
    fallback_auth_host_path: &str,
) -> String {
    let fallback_auth_host_path = fallback_auth_host_path.trim_end_matches('/');
    primary_session_history_path
        .strip_prefix(primary_auth_host_path.trim_end_matches('/'))
        .or_else(|| {
            primary_session_history_path.strip_prefix(primary_auth_mount_path.trim_end_matches('/'))
        })
        .map_or_else(
            || format!("{fallback_auth_host_path}/sessions"),
            |suffix| format!("{fallback_auth_host_path}{suffix}"),
        )
}

use super::api::GitLabApi;
use super::client::GitLabClient;
use super::types::{GitLabUser, GitLabUserDetail};
use crate::config::{Config, ReviewMentionCommandsConfig};
use anyhow::Result;
use async_trait::async_trait;
use tracing::{info, warn};

#[async_trait]
pub(crate) trait BotUserResolver: Send + Sync {
    async fn current_user(&self) -> Result<GitLabUser>;
    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail>;
}

#[async_trait]
impl BotUserResolver for GitLabClient {
    async fn current_user(&self) -> Result<GitLabUser> {
        GitLabApi::current_user(self).await
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        GitLabApi::get_user(self, user_id).await
    }
}

/// Resolve the bot ID and optional mention username before runtime startup.
/// Current-user errors propagate only when the bot ID is not configured.
pub(crate) async fn resolve_and_update_bot_user_config(
    config: &mut Config,
    user_resolver: &dyn BotUserResolver,
) -> Result<u64> {
    let current_user = resolve_current_user(config, user_resolver).await?;
    let bot_user_id = resolve_bot_user_id(config, current_user.as_ref())?;

    if mention_username_needs_resolution(&config.review.mention_commands) {
        config.review.mention_commands.bot_username =
            resolve_mention_bot_username(config, current_user.as_ref(), user_resolver).await;

        if config.review.mention_commands.bot_username.is_none() {
            warn!(
                "mention commands enabled but bot username could not be resolved; mention triggers will be skipped"
            );
        }
    }

    if config.review.mention_commands.enabled {
        log_enabled_mention_commands_status(&config.review.mention_commands);
    } else {
        info!("mention commands disabled");
    }
    Ok(bot_user_id)
}

fn mention_username_needs_resolution(mention_commands: &ReviewMentionCommandsConfig) -> bool {
    mention_commands.enabled && mention_commands.bot_username.is_none()
}

/// With a token, a missing bot ID requires a successful lookup.
/// Mention-only lookup failures are logged.
async fn resolve_current_user(
    config: &Config,
    user_resolver: &dyn BotUserResolver,
) -> Result<Option<GitLabUser>> {
    if config.gitlab.token.is_empty() {
        return Ok(None);
    }
    if config.gitlab.bot_user_id.is_none() {
        return user_resolver.current_user().await.map(Some);
    }
    if !mention_username_needs_resolution(&config.review.mention_commands) {
        return Ok(None);
    }

    let error = match user_resolver.current_user().await {
        Ok(user) => return Ok(Some(user)),
        Err(error) => error,
    };
    warn!(
        error = %error,
        "failed to resolve bot username for mention commands; mention triggers will be skipped"
    );
    Ok(None)
}

/// Return zero when neither a token nor a bot ID is configured.
/// Marker and award checks treat zero as unresolved.
fn resolve_bot_user_id(config: &Config, current_user: Option<&GitLabUser>) -> Result<u64> {
    match config.gitlab.bot_user_id {
        Some(id) => Ok(id),
        None if config.gitlab.token.is_empty() => {
            warn!("missing gitlab token; cannot determine bot user id");
            Ok(0)
        }
        None => current_user
            .map(|user| user.id)
            .ok_or_else(|| anyhow::anyhow!("failed to resolve bot user id")),
    }
}

/// Use the configured bot identity first. A failed lookup permits a matching current-user fallback.
async fn resolve_mention_bot_username(
    config: &Config,
    current_user: Option<&GitLabUser>,
    user_resolver: &dyn BotUserResolver,
) -> Option<String> {
    let Some(configured_bot_user_id) = config.gitlab.bot_user_id else {
        return current_user.and_then(|user| user.username.clone());
    };
    if config.gitlab.token.is_empty() {
        warn!(
            "mention commands enabled with configured bot_user_id but gitlab token is missing; mention triggers will be skipped"
        );
        return None;
    }

    lookup_mention_bot_username(configured_bot_user_id, current_user, user_resolver).await
}

/// A failed configured lookup permits only a matching current-user fallback.
async fn lookup_mention_bot_username(
    configured_bot_user_id: u64,
    current_user: Option<&GitLabUser>,
    user_resolver: &dyn BotUserResolver,
) -> Option<String> {
    let error = match user_resolver.get_user(configured_bot_user_id).await {
        Ok(user) => return user.username,
        Err(error) => error,
    };
    warn!(
        error = %error,
        bot_user_id = configured_bot_user_id,
        "failed to resolve mention bot username from configured bot_user_id"
    );
    matching_current_user_mention_username(configured_bot_user_id, current_user)
}

/// Log the fallback only when the current user has the configured identity and a username.
fn matching_current_user_mention_username(
    configured_bot_user_id: u64,
    current_user: Option<&GitLabUser>,
) -> Option<String> {
    let username = current_user
        .filter(|user| user.id == configured_bot_user_id)
        .and_then(|user| user.username.clone())?;
    warn!(
        bot_user_id = configured_bot_user_id,
        "falling back to current_user username for mention commands"
    );
    Some(username)
}

fn log_enabled_mention_commands_status(mention_commands: &ReviewMentionCommandsConfig) {
    match mention_commands.bot_username.as_deref() {
        Some(bot_username) => log_active_mention_commands(bot_username),
        None => warn!("mention commands enabled but inactive: bot username unavailable"),
    }
}

fn log_active_mention_commands(bot_username: &str) {
    info!(
        bot_username = bot_username,
        "mention commands enabled (scanning MR discussions for standalone comments and replies)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_builder::ConfigBuilder;
    use anyhow::anyhow;
    use std::sync::Mutex;

    struct StubBotUserResolver {
        current_user: Option<GitLabUser>,
        lookup_user: Option<GitLabUserDetail>,
        calls: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl BotUserResolver for StubBotUserResolver {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.calls.lock().expect("lock calls").push("current_user");
            self.current_user
                .clone()
                .ok_or_else(|| anyhow!("current_user failed"))
        }

        async fn get_user(&self, _user_id: u64) -> Result<GitLabUserDetail> {
            self.calls.lock().expect("lock calls").push("get_user");
            self.lookup_user
                .clone()
                .ok_or_else(|| anyhow!("get_user failed"))
        }
    }

    #[tokio::test]
    async fn resolve_and_update_bot_user_config_uses_configured_lookup_for_mentions() -> Result<()>
    {
        let mut config = test_config();
        config.gitlab.token = "secret".to_string();
        config.gitlab.bot_user_id = Some(123);
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = None;

        let resolver = StubBotUserResolver {
            current_user: Some(GitLabUser {
                id: 999,
                username: Some("runner".to_string()),
                name: None,
            }),
            lookup_user: Some(GitLabUserDetail {
                id: 123,
                username: Some("configured-bot".to_string()),
                name: None,
                public_email: None,
            }),
            calls: Mutex::default(),
        };

        let bot_user_id = resolve_and_update_bot_user_config(&mut config, &resolver).await?;

        assert_eq!(bot_user_id, 123);
        assert_eq!(
            config.review.mention_commands.bot_username.as_deref(),
            Some("configured-bot")
        );
        Ok(())
    }

    #[tokio::test]
    async fn resolve_and_update_bot_user_config_without_token_falls_back_to_zero() -> Result<()> {
        let mut config = test_config();
        config.gitlab.token.clear();
        config.gitlab.bot_user_id = None;
        config.review.mention_commands.enabled = false;

        let resolver = StubBotUserResolver {
            current_user: Some(GitLabUser {
                id: 321,
                username: Some("runner".to_string()),
                name: None,
            }),
            lookup_user: None,
            calls: Mutex::default(),
        };

        let bot_user_id = resolve_and_update_bot_user_config(&mut config, &resolver).await?;

        assert_eq!(bot_user_id, 0);
        assert!(resolver.calls.lock().expect("lock calls").is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn configured_lookup_failure_only_uses_matching_current_user() -> Result<()> {
        for (current_user_id, expected_username) in
            [(Some(123), Some("runner")), (Some(999), None), (None, None)]
        {
            let mut config = test_config();
            config.gitlab.token = "secret".to_string();
            config.gitlab.bot_user_id = Some(123);
            config.review.mention_commands.enabled = true;
            config.review.mention_commands.bot_username = None;
            let resolver = StubBotUserResolver {
                current_user: current_user_id.map(|id| GitLabUser {
                    id,
                    username: Some("runner".to_string()),
                    name: None,
                }),
                lookup_user: None,
                calls: Mutex::default(),
            };

            let bot_user_id = resolve_and_update_bot_user_config(&mut config, &resolver).await?;

            assert_eq!(bot_user_id, 123);
            assert_eq!(
                config.review.mention_commands.bot_username.as_deref(),
                expected_username
            );
            assert_eq!(
                *resolver.calls.lock().expect("lock calls"),
                ["current_user", "get_user"]
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn missing_bot_user_id_propagates_current_user_error() -> Result<()> {
        let mut config = test_config();
        config.gitlab.token = "secret".to_string();
        config.gitlab.bot_user_id = None;
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = None;
        let resolver = StubBotUserResolver {
            current_user: None,
            lookup_user: None,
            calls: Mutex::default(),
        };

        let error = resolve_and_update_bot_user_config(&mut config, &resolver)
            .await
            .expect_err("bot ID lookup failure must stop startup");

        assert_eq!(error.to_string(), "current_user failed");
        assert_eq!(config.review.mention_commands.bot_username, None);
        assert_eq!(
            *resolver.calls.lock().expect("lock calls"),
            ["current_user"]
        );
        Ok(())
    }

    fn test_config() -> Config {
        ConfigBuilder::for_service_factory_tests().build()
    }
}

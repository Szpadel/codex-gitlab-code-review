use super::api::GitLabApi;
use super::client::GitLabClient;
use super::types::{GitLabUser, GitLabUserDetail};
use crate::config::Config;
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

pub(crate) async fn resolve_and_update_bot_user_config(
    config: &mut Config,
    user_resolver: &dyn BotUserResolver,
) -> Result<u64> {
    let needs_current_user_for_bot_user_id = config.gitlab.bot_user_id.is_none();
    let needs_current_user_for_mention = config.review.mention_commands.enabled
        && config.review.mention_commands.bot_username.is_none();

    let current_user = if config.gitlab.token.is_empty() {
        None
    } else if needs_current_user_for_bot_user_id {
        Some(user_resolver.current_user().await?)
    } else if needs_current_user_for_mention {
        match user_resolver.current_user().await {
            Ok(user) => Some(user),
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to resolve bot username for mention commands; mention triggers will be skipped"
                );
                None
            }
        }
    } else {
        None
    };

    let bot_user_id = match config.gitlab.bot_user_id {
        Some(id) => id,
        None if config.gitlab.token.is_empty() => {
            warn!("missing gitlab token; cannot determine bot user id");
            0
        }
        None => current_user
            .as_ref()
            .map(|user| user.id)
            .ok_or_else(|| anyhow::anyhow!("failed to resolve bot user id"))?,
    };

    if config.review.mention_commands.enabled
        && config.review.mention_commands.bot_username.is_none()
    {
        if let Some(configured_bot_user_id) = config.gitlab.bot_user_id {
            if config.gitlab.token.is_empty() {
                warn!(
                    "mention commands enabled with configured bot_user_id but gitlab token is missing; mention triggers will be skipped"
                );
            } else {
                match user_resolver.get_user(configured_bot_user_id).await {
                    Ok(user) => {
                        config.review.mention_commands.bot_username = user.username;
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            bot_user_id = configured_bot_user_id,
                            "failed to resolve mention bot username from configured bot_user_id"
                        );
                        if let Some(username) = current_user
                            .as_ref()
                            .filter(|user| user.id == configured_bot_user_id)
                            .and_then(|user| user.username.clone())
                        {
                            warn!(
                                bot_user_id = configured_bot_user_id,
                                "falling back to current_user username for mention commands"
                            );
                            config.review.mention_commands.bot_username = Some(username);
                        }
                    }
                }
            }
        } else {
            config.review.mention_commands.bot_username =
                current_user.as_ref().and_then(|user| user.username.clone());
        }

        if config.review.mention_commands.bot_username.is_none() {
            warn!(
                "mention commands enabled but bot username could not be resolved; mention triggers will be skipped"
            );
        }
    }

    if config.review.mention_commands.enabled {
        if let Some(bot_username) = config.review.mention_commands.bot_username.as_deref() {
            info!(
                bot_username = bot_username,
                "mention commands enabled (scanning MR discussions for standalone comments and replies)"
            );
        } else {
            warn!("mention commands enabled but inactive: bot username unavailable");
        }
    } else {
        info!("mention commands disabled");
    }

    Ok(bot_user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_builder::ConfigBuilder;
    use anyhow::anyhow;

    struct StubBotUserResolver {
        current_user: Option<GitLabUser>,
        lookup_user: Option<GitLabUserDetail>,
    }

    #[async_trait]
    impl BotUserResolver for StubBotUserResolver {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.current_user
                .clone()
                .ok_or_else(|| anyhow!("current_user failed"))
        }

        async fn get_user(&self, _user_id: u64) -> Result<GitLabUserDetail> {
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
        };

        let bot_user_id = resolve_and_update_bot_user_config(&mut config, &resolver).await?;

        assert_eq!(bot_user_id, 0);
        Ok(())
    }

    fn test_config() -> Config {
        ConfigBuilder::for_service_factory_tests().build()
    }
}

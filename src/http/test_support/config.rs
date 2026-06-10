use crate::config::{Config, test_builder::ConfigBuilder};

pub(crate) fn test_config() -> Config {
    ConfigBuilder::for_http_tests().build()
}

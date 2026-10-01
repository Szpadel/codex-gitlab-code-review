//! Persisted workflow identities shared by execution and history storage.

use serde::{Deserialize, Serialize};

/// Uses stable snake-case names in stored history and serialized responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunHistoryKind {
    Review,
    Security,
    Mention,
}

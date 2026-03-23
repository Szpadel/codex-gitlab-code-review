use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLane {
    #[default]
    General,
    Security,
}

impl ReviewLane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Security => "security",
        }
    }

    pub const fn is_security(self) -> bool {
        matches!(self, Self::Security)
    }

    pub const fn review_label(self) -> &'static str {
        match self {
            Self::General => "Review",
            Self::Security => "Security review",
        }
    }
}

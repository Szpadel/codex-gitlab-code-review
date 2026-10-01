//! Structured review findings shared by output parsing and publication.

/// Identifies the first and last lines of a finding's source location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLineRange {
    pub start: usize,
    pub end: usize,
}

/// Identifies a finding's location in the review checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewCodeLocation {
    pub absolute_file_path: String,
    pub line_range: ReviewLineRange,
}

/// Carries a parsed finding for publication and duplicate detection.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewFinding {
    pub title: String,
    pub body: String,
    /// Omitted when the review output does not supply a confidence score.
    pub confidence_score: Option<f32>,
    /// Omitted when the review output does not supply a priority.
    pub priority: Option<u8>,
    pub code_location: ReviewCodeLocation,
}

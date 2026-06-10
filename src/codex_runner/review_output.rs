//! Parsing and rendering of Codex review output (structured JSON with rendered-text fallbacks).

use super::{CodexResult, ReviewCodeLocation, ReviewComment, ReviewFinding, ReviewLineRange};
use crate::review_lane::ReviewLane;
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[derive(Debug, Deserialize)]
struct ReviewOutputPayload {
    #[serde(default)]
    findings: Vec<ReviewFindingPayload>,
    #[serde(default)]
    overall_explanation: Option<String>,
    #[serde(default)]
    overall_correctness: Option<String>,
    #[serde(default)]
    overall_confidence_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct ReviewFindingPayload {
    title: String,
    body: String,
    #[serde(default)]
    confidence_score: Option<f32>,
    #[serde(default)]
    priority: Option<u8>,
    code_location: ReviewCodeLocationPayload,
}

#[derive(Debug, Deserialize)]
struct ReviewCodeLocationPayload {
    absolute_file_path: String,
    line_range: ReviewLineRangePayload,
}

#[derive(Debug, Deserialize)]
struct ReviewLineRangePayload {
    start: usize,
    end: usize,
}

const SINGLE_REVIEW_HEADER: &str = "Review comment:";
const MULTI_REVIEW_HEADER: &str = "Full review comments:";

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_review_output(text: &str) -> Result<CodexResult> {
    parse_review_output_for_lane(text, ReviewLane::General, None)
}

pub(crate) fn parse_review_output_for_lane(
    text: &str,
    lane: ReviewLane,
    min_confidence_score: Option<f32>,
) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        if lane.is_security() {
            bail!("security review output must be a structured JSON object");
        }
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if lane.is_security() {
        let parsed = serde_json::from_str::<ReviewOutputPayload>(trimmed)
            .map_err(|_| anyhow!("security review output must be a structured JSON object"))?;
        if !review_output_payload_looks_structured(&parsed) {
            bail!("security review output must be a structured JSON object");
        }
        return parse_structured_review_output(parsed, lane, min_confidence_score);
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<ReviewOutputPayload>(&json_text)
        && review_output_payload_looks_structured(&parsed)
    {
        return parse_structured_review_output(parsed, lane, min_confidence_score);
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<CodexOutput>(&json_text)
    {
        return match parsed.verdict.as_str() {
            "pass" => Ok(CodexResult::Pass {
                summary: parsed.summary,
            }),
            "comment" => Ok(CodexResult::Comment(ReviewComment {
                summary: parsed.summary,
                overall_explanation: None,
                overall_confidence_score: None,
                findings: Vec::new(),
                body: parsed.comment_markdown,
            })),
            other => Err(anyhow!("unknown verdict: {other}")),
        };
    }

    Ok(CodexResult::Comment(parse_rendered_review_comment(trimmed)))
}

pub(crate) fn extract_json_block(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn parse_structured_review_output(
    parsed: ReviewOutputPayload,
    lane: ReviewLane,
    min_confidence_score: Option<f32>,
) -> Result<CodexResult> {
    let original_findings_count = parsed.findings.len();
    if lane.is_security()
        && parsed
            .findings
            .iter()
            .any(|finding| finding.confidence_score.is_none())
    {
        bail!("security review findings must include confidence_score");
    }
    if lane.is_security()
        && parsed.findings.iter().any(|finding| {
            !matches!(
                finding.confidence_score,
                Some(score) if score.is_finite() && (0.0..=1.0).contains(&score)
            )
        })
    {
        bail!("security review findings must use confidence_score values between 0.0 and 1.0");
    }

    let findings = parsed
        .findings
        .into_iter()
        .map(|finding| ReviewFinding {
            title: finding.title,
            body: finding.body,
            confidence_score: finding.confidence_score,
            priority: finding.priority,
            code_location: ReviewCodeLocation {
                absolute_file_path: finding.code_location.absolute_file_path,
                line_range: ReviewLineRange {
                    start: finding.code_location.line_range.start,
                    end: finding.code_location.line_range.end,
                },
            },
        })
        .collect::<Vec<_>>();
    let overall_explanation = parsed.overall_explanation.and_then(trim_to_option);
    let overall_confidence_score = parsed.overall_confidence_score;
    let findings = if lane.is_security() {
        let threshold = validated_security_min_confidence_score(
            min_confidence_score,
            "security review min_confidence_score",
        )?;
        findings
            .into_iter()
            .filter(|finding| finding.confidence_score.unwrap_or(0.0) >= threshold)
            .collect::<Vec<_>>()
    } else {
        findings
    };
    if findings.is_empty() && lane.is_security() {
        if parsed.overall_correctness.is_none() {
            bail!("security review output must include overall_correctness");
        }
        if parsed.overall_correctness.as_deref() == Some("patch is incorrect")
            && original_findings_count == 0
        {
            bail!("security review marked patch incorrect without confirmed findings");
        }
        return Ok(CodexResult::Pass {
            summary: overall_explanation
                .unwrap_or_else(|| "no confirmed security issues found".to_string()),
        });
    }
    if findings.is_empty()
        && parsed
            .overall_correctness
            .as_deref()
            .is_some_and(|value| value == "patch is correct")
    {
        return Ok(CodexResult::Pass {
            summary: overall_explanation.unwrap_or_else(|| "no issues found".to_string()),
        });
    }
    let body = render_review_comment_body(overall_explanation.as_deref(), &findings);
    Ok(CodexResult::Comment(ReviewComment {
        summary: summary_from_text(body.as_str()),
        overall_explanation,
        overall_confidence_score,
        findings,
        body,
    }))
}

pub(super) fn validated_security_min_confidence_score(
    min_confidence_score: Option<f32>,
    field_name: &str,
) -> Result<f32> {
    let threshold = min_confidence_score.unwrap_or(0.85);
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(threshold)
    } else {
        bail!("{field_name} must be a finite number between 0.0 and 1.0");
    }
}

fn review_output_payload_looks_structured(payload: &ReviewOutputPayload) -> bool {
    !payload.findings.is_empty()
        || payload
            .overall_explanation
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || payload.overall_correctness.is_some()
}

fn parse_rendered_review_comment(text: &str) -> ReviewComment {
    let lines = text.lines().collect::<Vec<_>>();
    let header_idx = lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed == SINGLE_REVIEW_HEADER || trimmed == MULTI_REVIEW_HEADER
    });

    let (overall_explanation, findings) = if let Some(header_idx) = header_idx {
        let explanation = lines[..header_idx].join("\n");
        let findings = parse_rendered_review_findings(&lines[(header_idx + 1)..]);
        (trim_to_option(explanation), findings)
    } else {
        (trim_to_option(text.to_string()), Vec::new())
    };

    ReviewComment {
        summary: summary_from_text(text),
        overall_explanation,
        overall_confidence_score: None,
        findings,
        body: text.to_string(),
    }
}

fn parse_rendered_review_findings(lines: &[&str]) -> Vec<ReviewFinding> {
    let mut findings = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx];
        if !line.starts_with("- ") {
            idx += 1;
            continue;
        }

        let Some((title, location)) = line[2..].rsplit_once(" — ") else {
            idx += 1;
            continue;
        };
        let Some(code_location) = parse_rendered_location(location) else {
            idx += 1;
            continue;
        };

        idx += 1;
        let mut body_lines = Vec::new();
        while idx < lines.len() {
            let current = lines[idx];
            if current.starts_with("- ") {
                break;
            }
            if let Some(stripped) = current.strip_prefix("  ") {
                body_lines.push(stripped);
            } else if current.trim().is_empty() {
                body_lines.push("");
            }
            idx += 1;
        }

        findings.push(ReviewFinding {
            title: title.trim().to_string(),
            body: body_lines.join("\n").trim().to_string(),
            confidence_score: None,
            priority: None,
            code_location,
        });
    }
    findings
}

fn parse_rendered_location(text: &str) -> Option<ReviewCodeLocation> {
    let (path, range) = text.rsplit_once(':')?;
    let (start, end) = range.split_once('-')?;
    Some(ReviewCodeLocation {
        absolute_file_path: path.to_string(),
        line_range: ReviewLineRange {
            start: start.parse().ok()?,
            end: end.parse().ok()?,
        },
    })
}

fn render_review_comment_body(
    overall_explanation: Option<&str>,
    findings: &[ReviewFinding],
) -> String {
    let mut sections = Vec::new();
    if let Some(overall_explanation) = overall_explanation
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        sections.push(overall_explanation.to_string());
    }
    if !findings.is_empty() {
        sections.push(render_review_findings_block(findings));
    }
    if sections.is_empty() {
        "Reviewer failed to output a response.".to_string()
    } else {
        sections.join("\n\n")
    }
}

fn render_review_findings_block(findings: &[ReviewFinding]) -> String {
    let mut lines = Vec::new();
    lines.push(if findings.len() > 1 {
        MULTI_REVIEW_HEADER.to_string()
    } else {
        SINGLE_REVIEW_HEADER.to_string()
    });
    for finding in findings {
        lines.push(String::new());
        lines.push(format!(
            "- {} — {}:{}-{}",
            finding.title,
            finding.code_location.absolute_file_path,
            finding.code_location.line_range.start,
            finding.code_location.line_range.end
        ));
        if !finding.body.is_empty() {
            for body_line in finding.body.lines() {
                lines.push(format!("  {body_line}"));
            }
        }
    }
    lines.join("\n")
}

fn summary_from_text(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Codex review")
        .trim()
        .to_string()
}

fn trim_to_option(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

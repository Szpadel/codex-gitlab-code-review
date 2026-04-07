use super::*;
#[test]
fn parse_review_output_json_pass() -> Result<()> {
    let text = r#"{"verdict":"pass","summary":"ok","comment_markdown":""}"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "ok");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn security_context_output_schema_is_strict_root_object() {
    let schema = DockerCodexRunner::security_context_output_schema();
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn parse_review_output_json_comment() -> Result<()> {
    let text = r#"{"verdict":"comment","summary":"needs changes","comment_markdown":"- fix"}"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "needs changes");
            assert_eq!(comment.body, "- fix");
            assert!(comment.findings.is_empty());
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_fallback_comment() -> Result<()> {
    let text = "Looks good overall\n\n- minor nit";
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "Looks good overall");
            assert_eq!(comment.body, text);
            assert!(comment.findings.is_empty());
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_structured_findings_json() -> Result<()> {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Use safer cache invalidation",
          "body": "This can leave stale entries in the process cache.",
          "confidence_score": 0.91,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/cache.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "The patch has one correctness issue.",
      "overall_confidence_score": 0.88
    }"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "The patch has one correctness issue.");
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch has one correctness issue.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(
                comment.findings[0].title,
                "[P1] Use safer cache invalidation"
            );
            assert_eq!(
                comment.findings[0].code_location.absolute_file_path,
                "/work/repo/src/cache.rs"
            );
            assert_eq!(comment.findings[0].code_location.line_range.start, 14);
            assert_eq!(comment.findings[0].code_location.line_range.end, 16);
            assert!(comment.body.contains("Review comment:"));
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_upstream_rendered_review_text() -> Result<()> {
    let text = "The patch has one correctness issue.\n\nReview comment:\n\n- [P1] Use safer cache invalidation — /work/repo/src/cache.rs:14-16\n  This can leave stale entries in the process cache.";
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "The patch has one correctness issue.");
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch has one correctness issue.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(
                comment.findings[0].title,
                "[P1] Use safer cache invalidation"
            );
            assert_eq!(
                comment.findings[0].body,
                "This can leave stale entries in the process cache."
            );
            assert_eq!(
                comment.findings[0].code_location.absolute_file_path,
                "/work/repo/src/cache.rs"
            );
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_security_review_output_filters_low_confidence_findings() -> Result<()> {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Reject missing auth check",
          "body": "The endpoint can be reached without the intended guard.",
          "confidence_score": 0.84,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "No confirmed security issues after validation.",
      "overall_confidence_score": 0.84
    }"#;
    let result =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "No confirmed security issues after validation.");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn parse_security_review_output_rejects_unstructured_text() {
    let err = parse_review_output_for_lane(
        "This patch looks safe.",
        crate::review_lane::ReviewLane::Security,
        Some(0.85),
    )
    .expect_err("security review should reject prose output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_wrapped_json() {
    let text = r#"Security review result:
{
  "findings": [],
  "overall_correctness": "patch is correct",
  "overall_explanation": "No confirmed issues."
}"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject prose-wrapped JSON output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_empty_text() {
    let err =
        parse_review_output_for_lane("", crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject empty output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_findings_without_confidence() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject findings without confidence");
    assert!(
        err.to_string()
            .contains("security review findings must include confidence_score")
    );
}

#[test]
fn parse_security_review_output_rejects_invalid_confidence_threshold() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "confidence_score": 0.91,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(1.5))
            .expect_err("security review should reject invalid thresholds");
    assert!(err.to_string().contains(
        "security review min_confidence_score must be a finite number between 0.0 and 1.0"
    ));
}

#[test]
fn parse_security_review_output_rejects_invalid_finding_confidence_scores() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "confidence_score": 7,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject invalid finding confidence");
    assert!(
        err.to_string().contains(
            "security review findings must use confidence_score values between 0.0 and 1.0"
        )
    );
}

#[test]
fn parse_security_review_output_accepts_nullable_optional_fields() -> Result<()> {
    let text = r#"{
      "findings": [],
      "overall_correctness": "patch is correct",
      "overall_explanation": null,
      "overall_confidence_score": null
    }"#;
    let result =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "no confirmed security issues found");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn parse_security_review_output_preserves_sectioned_body() -> Result<()> {
    let finding_body = "Summary:\nUntrusted callers can reach src/auth.rs:14.\n\nSeverity:\nP1 because the missing guard exposes tenant data.\n\nReproduction:\nSend the authenticated request sequence described near src/http.rs:22.\n\nEvidence:\nsrc/auth.rs:14 skips the role check and src/http.rs:22 still reaches the handler.\n\nAttack-path analysis:\nAn attacker-controlled request crosses the HTTP boundary, bypasses the auth check, and reaches the privileged handler.\n\nLikelihood:\nHigh because the endpoint is externally reachable.\n\nImpact:\nCross-tenant data exposure.\n\nAssumptions:\nThe route remains available to normal API clients.\n\nBlindspots:\nDid not validate WAF-specific mitigations.";
    let text = json!({
        "findings": [
            {
                "title": "[P1] Missing auth guard",
                "body": finding_body,
                "confidence_score": 0.91,
                "priority": 1,
                "code_location": {
                    "absolute_file_path": "/work/repo/src/auth.rs",
                    "line_range": { "start": 14, "end": 16 }
                }
            }
        ],
        "overall_correctness": "patch is incorrect",
        "overall_explanation": "The patch introduces a confirmed auth bypass.",
        "overall_confidence_score": 0.91
    })
    .to_string();
    let result =
        parse_review_output_for_lane(&text, crate::review_lane::ReviewLane::Security, Some(0.85))?;

    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch introduces a confirmed auth bypass.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(comment.findings[0].body, finding_body);
            let expected_body = format!(
                "The patch introduces a confirmed auth bypass.\n\nReview comment:\n\n- [P1] Missing auth guard — /work/repo/src/auth.rs:14-16\n  {}",
                finding_body.replace('\n', "\n  ")
            );
            assert_eq!(comment.body, expected_body);
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_security_review_output_rejects_incorrect_verdict_without_confirmed_findings() {
    let text = r#"{
      "findings": [],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "The patch is unsafe."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject incorrect verdict without findings");
    assert!(
        err.to_string()
            .contains("security review marked patch incorrect without confirmed findings")
    );
}

#[test]
fn handle_turn_notification_enriches_agent_message_from_deltas() -> Result<()> {
    let mut client = empty_app_server_client();
    let mut capture = TurnHistoryCapture::default();
    client.handle_turn_notification(
        "item/agentMessage/delta",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "itemId": "item-1",
            "delta": "Reply from deltas"
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |_| {},
    )?;

    let mut completed = None;
    client.handle_turn_notification(
        "item/completed",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {
                "id": "item-1",
                "type": "AgentMessage",
                "phase": "final"
            }
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |item| completed = Some(item.clone()),
    )?;

    let completed = completed.context("completed agent message")?;
    assert_eq!(completed["text"], "Reply from deltas");
    let events = capture.take_pending();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload["createdAt"].is_string());
    assert_eq!(events[0].payload["text"], "Reply from deltas");
    Ok(())
}

#[test]
fn handle_turn_notification_enriches_command_output_from_deltas() -> Result<()> {
    let mut client = empty_app_server_client();
    let mut capture = TurnHistoryCapture::default();
    client.handle_turn_notification(
        "item/commandExecution/outputDelta",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "itemId": "cmd-1",
            "delta": "line one\nline two"
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |_| {},
    )?;

    let mut completed = None;
    client.handle_turn_notification(
        "item/completed",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {
                "id": "cmd-1",
                "type": "commandExecution",
                "command": "cargo test",
                "status": "completed"
            }
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |item| completed = Some(item.clone()),
    )?;

    let completed = completed.context("completed command")?;
    assert_eq!(completed["aggregatedOutput"], "line one\nline two");
    let events = capture.take_pending();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload["createdAt"].is_string());
    assert_eq!(events[0].payload["aggregatedOutput"], "line one\nline two");
    Ok(())
}

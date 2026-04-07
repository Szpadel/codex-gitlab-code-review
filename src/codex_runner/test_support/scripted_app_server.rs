use super::models::{ScriptedAppChunk, ScriptedAppServer};
use super::*;
use bollard::container::LogOutput;
use bollard::errors::Error as BollardError;
use futures::StreamExt;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::time::{Duration, sleep};
use tokio_util::io::ReaderStream;

pub(super) fn build_scripted_app_client(
    scripted: ScriptedAppServer,
    protocol_requests: Arc<Mutex<Vec<Value>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
    log_all_json: bool,
) -> AppServerClient {
    let (client_input, server_input) = duplex(16 * 1024);
    let (server_output, client_output) = duplex(16 * 1024);
    tokio::spawn(async move {
        serve_scripted_app_server(
            scripted,
            protocol_requests,
            operation_log,
            server_input,
            server_output,
        )
        .await;
    });
    let output = ReaderStream::new(client_output).map(|chunk| match chunk {
        Ok(bytes) => Ok(LogOutput::StdOut { message: bytes }),
        Err(err) => Err(BollardError::IOError { err }),
    });
    AppServerClient {
        input: Box::pin(client_input),
        output: Box::pin(output),
        buffer: Vec::new(),
        pending_notifications: VecDeque::new(),
        reasoning_buffers: HashMap::new(),
        agent_message_buffers: HashMap::new(),
        command_output_buffers: HashMap::new(),
        recent_runner_errors: VecDeque::new(),
        log_all_json,
    }
}

async fn serve_scripted_app_server(
    scripted: ScriptedAppServer,
    protocol_requests: Arc<Mutex<Vec<Value>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
    server_input: tokio::io::DuplexStream,
    mut server_output: tokio::io::DuplexStream,
) {
    let mut requests = scripted.requests;
    let mut lines = BufReader::new(server_input).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        protocol_requests.lock().unwrap().push(message.clone());
        let method = message
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        operation_log.lock().unwrap().push(format!("app:{method}"));
        let Some(id) = message.get("id").cloned() else {
            if method == "initialized" {
                continue;
            }
            continue;
        };

        let Some(expected) = requests.pop_front() else {
            let _ = write_json_line(
                &mut server_output,
                &json!({ "id": id, "error": { "message": format!("unexpected request method {method}") } }),
            )
            .await;
            return;
        };

        if expected.method != method {
            let _ = write_json_line(
                &mut server_output,
                &json!({ "id": id, "error": { "message": format!("expected request method {}, got {}", expected.method, method) } }),
            )
            .await;
            return;
        }

        let response = match (expected.result, expected.error) {
            (_, Some(error)) => json!({ "id": id, "error": error }),
            (Some(result), None) => json!({ "id": id, "result": result }),
            (None, None) => json!({ "id": id, "result": {} }),
        };
        if write_json_line(&mut server_output, &response)
            .await
            .is_err()
        {
            return;
        }
        for chunk in expected.after_response {
            let write_result = match chunk {
                ScriptedAppChunk::Json(value) => write_json_line(&mut server_output, &value).await,
                ScriptedAppChunk::Line(line) => write_text_line(&mut server_output, &line).await,
                ScriptedAppChunk::SleepMillis(millis) => {
                    sleep(Duration::from_millis(millis)).await;
                    Ok(())
                }
            };
            if write_result.is_err() {
                return;
            }
        }
        if expected.close_output_after {
            return;
        }
    }
    if !requests.is_empty() {
        let remaining_methods = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write_text_line(
            &mut server_output,
            &format!(
                "codex-runner-error: scripted app-server ended with pending requests: {}",
                remaining_methods
            ),
        )
        .await;
    }
}

async fn write_json_line(
    output: &mut tokio::io::DuplexStream,
    value: &Value,
) -> std::io::Result<()> {
    let line = serde_json::to_string(value).expect("serialize scripted app-server response");
    write_text_line(output, &line).await
}

async fn write_text_line(output: &mut tokio::io::DuplexStream, line: &str) -> std::io::Result<()> {
    output.write_all(line.as_bytes()).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}

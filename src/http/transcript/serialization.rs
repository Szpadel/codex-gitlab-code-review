//! Preserves the transcript API's string bodies at the serialization boundary.

use super::models::{FileChangeBody, ThreadItemKind, ThreadItemSnapshot};
use serde::{Serialize, Serializer};
use std::borrow::Cow;
use std::io::Write;

impl Serialize for ThreadItemSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct SerializedItem<'a> {
            title: &'a str,
            preview: Option<&'a str>,
            body: Option<Cow<'a, str>>,
            timestamp: Option<&'a str>,
            #[serde(flatten)]
            kind: &'a ThreadItemKind,
        }

        let body = match &self.kind {
            ThreadItemKind::FileChange { body, .. } => match body {
                FileChangeBody::Diff(text) => Some(Cow::Borrowed(text.as_str())),
                FileChangeBody::Mixed(sections) => Some(Cow::Owned(
                    serde_json::to_string(sections).map_err(serde::ser::Error::custom)?,
                )),
                FileChangeBody::Payload(text) => text.as_deref().map(Cow::Borrowed),
            },
            _ => self.body.as_deref().map(Cow::Borrowed),
        };
        SerializedItem {
            title: &self.title,
            preview: self.preview.as_deref(),
            body,
            timestamp: self.timestamp.as_deref(),
            kind: &self.kind,
        }
        .serialize(serializer)
    }
}

/// Emits the format without duplicating the typed body's discriminant.
pub(crate) fn serialize_file_change_format<S: Serializer>(
    body: &FileChangeBody,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    body.format().serialize(serializer)
}

/// Uses the API body size in bytes for the lazy-load threshold.
/// Counts mixed JSON bytes without allocating or parsing a JSON string.
pub(crate) fn serialized_body_len(item: &ThreadItemSnapshot) -> usize {
    match &item.kind {
        ThreadItemKind::FileChange { body, .. } => match body {
            FileChangeBody::Diff(text) => text.len(),
            FileChangeBody::Payload(text) => text.as_ref().map_or(0, String::len),
            FileChangeBody::Mixed(sections) => {
                let mut count = SerializedByteCount(0);
                serde_json::to_writer(&mut count, sections)
                    .expect("string sections and the byte counter cannot fail serialization");
                count.0
            }
        },
        _ => item.body.as_ref().map_or(0, String::len),
    }
}

struct SerializedByteCount(usize);

impl Write for SerializedByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

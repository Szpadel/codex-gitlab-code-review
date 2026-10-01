mod diff;
mod models;
mod parser;
mod renderer;
mod serialization;

pub use models::ThreadSnapshot;
pub(crate) use parser::is_auxiliary_transcript_turn_id;
pub use parser::{
    thread_snapshot_from_events, thread_snapshot_is_complete,
    thread_snapshot_only_target_turn_is_incomplete,
};
pub(crate) use renderer::{
    render_thread_stream, render_transcript_event_body, transcript_script_tag,
};

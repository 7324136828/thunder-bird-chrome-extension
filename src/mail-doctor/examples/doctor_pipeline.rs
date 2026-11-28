//! Run the Inbox Doctor report pipeline on a job directory (`<job>/inputs`
//! must exist), printing the event stream as JSON lines. Used for
//! differential testing against the original Python pipeline.
//!
//! Usage: `cargo run -p mail-doctor --example doctor_pipeline -- <job_dir> [days]`

use mail_doctor::pipeline::{
    run_pipeline, PipelineEvent, DEFAULT_MAX_ARCHIVE_MEMBERS, DEFAULT_MAX_EXPANDED_BYTES,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(job) = args.next() else {
        eprintln!("usage: doctor_pipeline <job_dir> [days]");
        std::process::exit(2);
    };
    let days = args.next().and_then(|value| value.parse::<i64>().ok());
    let mut events = Vec::new();
    let started = std::time::Instant::now();
    let result = run_pipeline(
        std::path::Path::new(&job),
        days,
        &mut |event| {
            eprintln!("{:>8} ms {event:?}", started.elapsed().as_millis());
            events.push(event)
        },
        DEFAULT_MAX_EXPANDED_BYTES,
        DEFAULT_MAX_ARCHIVE_MEMBERS,
    );
    for event in &events {
        let value = match event {
            PipelineEvent::Stage(stage) => serde_json::json!([event.kind(), stage]),
            PipelineEvent::Progress(progress) => serde_json::json!([event.kind(), progress]),
            PipelineEvent::Log(text) => serde_json::json!([event.kind(), text]),
        };
        println!("{value}");
    }
    if let Err(error) = result {
        println!("{}", serde_json::json!(["ERROR", error.to_string()]));
    }
}

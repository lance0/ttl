//! End-to-end replay/diff of a genuine recording larger than the default cap.

use std::io::{BufWriter, Write};
use std::process::Command;
use ttl::{
    config::Config,
    export::export_json,
    state::{ProbeEvent, ProbeOutcome, Session, Target},
};

#[test]
fn large_export_replays_and_diffs_with_an_explicit_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large-session.json");
    let mut session = Session::new(
        Target::new("example.test".into(), "192.0.2.1".parse().unwrap()),
        Config::default(),
    );
    session.events = vec![
        ProbeEvent {
            offset_ms: 0,
            ttl: 1,
            seq: 0,
            flow_id: 0,
            outcome: ProbeOutcome::Timeout
        };
        100_000
    ];
    let mut writer = BufWriter::new(std::fs::File::create(&path).unwrap());
    export_json(&session, &mut writer).unwrap();
    writer.flush().unwrap();
    drop(writer);
    assert!(path.metadata().unwrap().len() > 10 * 1024 * 1024);

    let refused = Command::new(env!("CARGO_BIN_EXE_ttl"))
        .arg("--replay")
        .arg(&path)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--replay-size-limit"));

    let replayed = Command::new(env!("CARGO_BIN_EXE_ttl"))
        .arg("--replay")
        .arg(&path)
        .args(["--json", "--replay-size-limit", "64"])
        .output()
        .unwrap();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let restored: Session = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(restored.events.len(), session.events.len());
    assert_eq!(restored.target.original, session.target.original);

    let diff = Command::new(env!("CARGO_BIN_EXE_ttl"))
        .arg("--diff")
        .arg(&path)
        .arg(&path)
        .args(["--json", "--replay-size-limit", "64"])
        .output()
        .unwrap();
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&diff.stdout).is_ok());
}

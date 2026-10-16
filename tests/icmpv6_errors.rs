use std::time::Duration;
use ttl::config::Config;
use ttl::export::{
    json::export_json_string, report::generate_report_string, stream::write_event_line,
};
use ttl::state::{IcmpResponseType, ProbeEvent, ProbeOutcome, Session, Target};

#[test]
fn processing_rejections_survive_json_report_stream_and_replay() {
    let target = "2001:db8::1".parse().unwrap();
    for response_type in [
        IcmpResponseType::ParameterProblem {
            code: 6,
            pointer: u32::MAX,
        },
        IcmpResponseType::HeadersTooLong {
            pointer: Some(2048),
        },
    ] {
        let mut session = Session::new(Target::new("test".into(), target), Config::default());
        let event = ProbeEvent {
            offset_ms: 10,
            ttl: 5,
            seq: 1,
            flow_id: 0,
            outcome: ProbeOutcome::IcmpError {
                addr: target,
                rtt_us: 2000,
                response_type,
                late: false,
            },
        };
        session.apply_replay_event(&event);
        session.record_event(event.clone());
        assert!(
            !session.complete,
            "a rejection from the target is not successful delivery"
        );
        assert_eq!(session.dest_ttl, None);
        let hop = session.hop(5).unwrap();
        assert_eq!((hop.sent, hop.received, hop.timeouts), (1, 1, 0));
        assert_eq!(hop.responders[&target].last_icmp_error, Some(response_type));
        assert_eq!(
            hop.responders[&target].avg_rtt(),
            Duration::from_micros(2000)
        );

        let reason = response_type.processing_error_reason().unwrap();
        let report = generate_report_string(&session);
        assert!(report.contains(reason));
        let json = export_json_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.hop(5).unwrap().responders[&target].last_icmp_error,
            Some(response_type)
        );
        let mut replay = Session::new(restored.target.clone(), restored.config.clone());
        replay.apply_replay_event(&restored.events[0]);
        assert!(!replay.complete);
        assert!(generate_report_string(&replay).contains(reason));

        let mut stream = Vec::new();
        write_event_line(&mut stream, target, &event).unwrap();
        let line: serde_json::Value = serde_json::from_slice(&stream).unwrap();
        assert_eq!(line["type"], "icmp_error");
        assert_eq!(line["late"], false);
        assert!(line.get("response_type").is_some());
    }
}

#[test]
fn late_processing_error_preserves_timeout_counters() {
    let target = "2001:db8::1".parse().unwrap();
    let mut session = Session::new(Target::new("test".into(), target), Config::default());
    session.apply_replay_event(&ProbeEvent {
        offset_ms: 1,
        ttl: 5,
        seq: 1,
        flow_id: 0,
        outcome: ProbeOutcome::Timeout,
    });
    session.apply_replay_event(&ProbeEvent {
        offset_ms: 2,
        ttl: 5,
        seq: 1,
        flow_id: 0,
        outcome: ProbeOutcome::IcmpError {
            addr: target,
            rtt_us: 0,
            late: true,
            response_type: IcmpResponseType::ParameterProblem {
                code: 10,
                pointer: 5000,
            },
        },
    });
    let hop = session.hop(5).unwrap();
    assert_eq!((hop.sent, hop.received, hop.timeouts), (1, 0, 1));
    assert_eq!(session.total_sent, 1);
    assert_eq!(hop.responders[&target].received, 0);
    assert!(hop.responders[&target].last_icmp_error.is_some());
    assert!(!session.complete);
    assert!(generate_report_string(&session).contains("Option too big"));
}

#[test]
fn old_responder_json_does_not_require_error_metadata() {
    let target = "2001:db8::1".parse().unwrap();
    let mut session = Session::new(Target::new("test".into(), target), Config::default());
    let hop = session.hop_mut(1).unwrap();
    hop.record_sent();
    hop.record_response(target, Duration::from_millis(1));
    let json = serde_json::to_value(&session).unwrap();
    let responder = &json["hops"][0]["responders"][target.to_string()];
    assert!(responder.get("last_icmp_error").is_none());
    let restored: Session = serde_json::from_value(json).unwrap();
    assert_eq!(
        restored.hop(1).unwrap().responders[&target].last_icmp_error,
        None
    );
}

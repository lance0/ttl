//! Prometheus/OpenMetrics exporter for --prometheus mode.
//!
//! Serves a hand-rolled HTTP/1.1 endpoint (GET /metrics, GET /healthz) over a
//! tokio listener — deliberately no HTTP framework dependency; the exposition
//! format is plain text and the routing is two paths.

use crate::lookup::sanitize_display;
use crate::trace::receiver::SessionMap;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// Metric definitions in output order: (name, type, help)
const METRICS: &[(&str, &str, &str)] = &[
    (
        "ttl_probes_sent_total",
        "counter",
        "Probes sent to this hop",
    ),
    (
        "ttl_responses_total",
        "counter",
        "Responses received from this hop",
    ),
    (
        "ttl_timeouts_total",
        "counter",
        "Probes that timed out at this hop",
    ),
    (
        "ttl_loss_ratio",
        "gauge",
        "Loss ratio at this hop (0-1, completed probes only)",
    ),
    (
        "ttl_rtt_avg_seconds",
        "gauge",
        "Average RTT to this hop's primary responder",
    ),
    (
        "ttl_rtt_min_seconds",
        "gauge",
        "Minimum RTT to this hop's primary responder",
    ),
    (
        "ttl_rtt_max_seconds",
        "gauge",
        "Maximum RTT to this hop's primary responder",
    ),
    (
        "ttl_rtt_stddev_seconds",
        "gauge",
        "RTT standard deviation for this hop's primary responder",
    ),
    (
        "ttl_hop_responders",
        "gauge",
        "Distinct responder IPs seen at this hop (ECMP)",
    ),
    (
        "ttl_hop_info",
        "gauge",
        "Primary responder identity for this hop (always 1)",
    ),
    (
        "ttl_target_reachable",
        "gauge",
        "Whether the destination has responded (1) or not (0)",
    ),
    (
        "ttl_path_hops",
        "gauge",
        "Hop count at which the destination responded",
    ),
    (
        "ttl_target_probes_total",
        "counter",
        "Total completed probes across all hops for this target",
    ),
];

/// Escape a label value per the Prometheus exposition format
fn escape_label(s: &str) -> String {
    sanitize_display(s)
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Render all sessions as Prometheus exposition text
pub fn render_metrics(sessions: &SessionMap) -> String {
    // Collect sample lines per metric, then emit grouped under HELP/TYPE
    // headers in METRICS order (the exposition format requires grouping).
    let mut samples: std::collections::HashMap<&str, Vec<String>> =
        std::collections::HashMap::new();
    let mut push = |metric: &'static str, labels: String, value: f64| {
        samples
            .entry(metric)
            .or_default()
            .push(format!("{}{{{}}} {}", metric, labels, value));
    };

    let sessions_read = sessions.read();
    for (target_ip, state) in sessions_read.iter() {
        let session = state.read();
        let target = format!(
            "target=\"{}\",host=\"{}\"",
            target_ip,
            escape_label(&session.target.original)
        );

        for hop in &session.hops {
            if hop.sent == 0 {
                continue;
            }
            let hop_labels = format!("{},ttl=\"{}\"", target, hop.ttl);
            push("ttl_probes_sent_total", hop_labels.clone(), hop.sent as f64);
            push(
                "ttl_responses_total",
                hop_labels.clone(),
                hop.received as f64,
            );
            push(
                "ttl_timeouts_total",
                hop_labels.clone(),
                hop.timeouts as f64,
            );
            push("ttl_loss_ratio", hop_labels.clone(), hop.loss_pct() / 100.0);
            if let Some(stats) = hop.primary_stats() {
                push(
                    "ttl_rtt_avg_seconds",
                    hop_labels.clone(),
                    stats.avg_rtt().as_secs_f64(),
                );
                push(
                    "ttl_rtt_min_seconds",
                    hop_labels.clone(),
                    stats.min_rtt.as_secs_f64(),
                );
                push(
                    "ttl_rtt_max_seconds",
                    hop_labels.clone(),
                    stats.max_rtt.as_secs_f64(),
                );
                push(
                    "ttl_rtt_stddev_seconds",
                    hop_labels.clone(),
                    stats.stddev().as_secs_f64(),
                );
                push(
                    "ttl_hop_responders",
                    hop_labels.clone(),
                    hop.responders.len() as f64,
                );
                let hostname = stats.hostname.as_deref().unwrap_or("");
                push(
                    "ttl_hop_info",
                    format!(
                        "{},ip=\"{}\",hostname=\"{}\"",
                        hop_labels,
                        stats.ip,
                        escape_label(hostname)
                    ),
                    1.0,
                );
            }
        }

        push(
            "ttl_target_reachable",
            target.clone(),
            if session.complete { 1.0 } else { 0.0 },
        );
        if let Some(dest_ttl) = session.dest_ttl {
            push("ttl_path_hops", target.clone(), dest_ttl as f64);
        }
        push(
            "ttl_target_probes_total",
            target.clone(),
            session.total_sent as f64,
        );
    }
    drop(sessions_read);

    let mut out = String::new();
    for (name, kind, help) in METRICS {
        if let Some(lines) = samples.get(name) {
            out.push_str(&format!(
                "# HELP {} {}\n# TYPE {} {}\n",
                name, help, name, kind
            ));
            for line in lines {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out
}

/// Accept loop for the exporter; runs until cancellation
pub async fn run_metrics_server(
    listener: TcpListener,
    sessions: SessionMap,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, sessions).await;
                });
            }
        }
    }
}

async fn handle_connection(mut stream: TcpStream, sessions: SessionMap) -> Result<()> {
    // Read the request head; 1KB is plenty for "GET /metrics HTTP/1.1" + headers
    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .context("request read timed out")??;
    let request = String::from_utf8_lossy(&buf[..n]);
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    let (status, content_type, body) = if method != "GET" {
        (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".to_string(),
        )
    } else {
        match path {
            "/metrics" => (
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                render_metrics(&sessions),
            ),
            "/healthz" | "/health" => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
            _ => (
                "404 Not Found",
                "text/plain; charset=utf-8",
                "not found\n".to_string(),
            ),
        }
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::{Session, SessionLock, Target};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn make_session_map() -> SessionMap {
        let target_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let target = Target::new("dns.example".to_string(), target_ip);
        let mut session = Session::new(target, Config::default());
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
            hop.record_sent();
            hop.record_timeout();
        }
        session.complete = true;
        session.dest_ttl = Some(1);
        session.total_sent = 2;

        let mut map = HashMap::new();
        map.insert(target_ip, Arc::new(SessionLock::new(session)));
        Arc::new(RwLock::new(map))
    }

    #[test]
    fn test_render_metrics_basic() {
        let sessions = make_session_map();
        let text = render_metrics(&sessions);
        assert!(text.contains("# TYPE ttl_probes_sent_total counter"));
        assert!(text.contains(
            "ttl_probes_sent_total{target=\"8.8.8.8\",host=\"dns.example\",ttl=\"1\"} 2"
        ));
        assert!(
            text.contains(
                "ttl_responses_total{target=\"8.8.8.8\",host=\"dns.example\",ttl=\"1\"} 1"
            )
        );
        assert!(
            text.contains(
                "ttl_timeouts_total{target=\"8.8.8.8\",host=\"dns.example\",ttl=\"1\"} 1"
            )
        );
        assert!(
            text.contains("ttl_loss_ratio{target=\"8.8.8.8\",host=\"dns.example\",ttl=\"1\"} 0.5")
        );
        assert!(text.contains(
            "ttl_rtt_avg_seconds{target=\"8.8.8.8\",host=\"dns.example\",ttl=\"1\"} 0.005"
        ));
        assert!(text.contains("ip=\"10.0.0.1\""));
        assert!(text.contains("ttl_target_reachable{target=\"8.8.8.8\",host=\"dns.example\"} 1"));
        assert!(text.contains("ttl_path_hops{target=\"8.8.8.8\",host=\"dns.example\"} 1"));
        assert!(
            text.contains("ttl_target_probes_total{target=\"8.8.8.8\",host=\"dns.example\"} 2")
        );
    }

    #[test]
    fn test_render_metrics_skips_unprobed_hops() {
        let sessions = make_session_map();
        let text = render_metrics(&sessions);
        // Only TTL 1 was probed; no ttl="2" series should exist
        assert!(!text.contains("ttl=\"2\""));
    }

    #[test]
    fn test_label_escaping() {
        assert_eq!(escape_label("plain"), "plain");
        assert_eq!(escape_label("with\"quote"), "with\\\"quote");
        assert_eq!(escape_label("back\\slash"), "back\\\\slash");
        // Control chars stripped by sanitize_display before escaping
        assert_eq!(escape_label("evil\x1b[31m"), "evil[31m");
    }

    #[tokio::test]
    async fn test_http_endpoints() {
        let sessions = make_session_map();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let server = tokio::spawn(run_metrics_server(listener, sessions, cancel.clone()));

        let fetch = |path: &'static str| async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\n\r\n", path).as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };

        let metrics = fetch("/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("ttl_probes_sent_total"));

        let health = fetch("/healthz").await;
        assert!(health.starts_with("HTTP/1.1 200 OK"));
        assert!(health.contains("ok"));

        let missing = fetch("/nope").await;
        assert!(missing.starts_with("HTTP/1.1 404"));

        cancel.cancel();
        server.await.unwrap();
    }
}

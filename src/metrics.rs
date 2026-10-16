//! Prometheus/OpenMetrics exporter for --prometheus mode.
//!
//! Serves a hand-rolled HTTP/1.1 endpoint (GET /metrics, GET /healthz) over a
//! tokio listener — deliberately no HTTP framework dependency; the exposition
//! format is plain text and the routing is two paths.

use crate::lookup::sanitize_display;
use crate::trace::receiver::SessionMap;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
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

// Prometheus request headers can exceed a single TCP read. Keep a bound on
// the complete head and apply one deadline to the whole read, not each chunk.
const MAX_REQUEST_HEAD_BYTES: usize = 8 * 1024;

#[derive(Debug)]
enum RequestHead {
    Complete(Vec<u8>),
    Incomplete,
    TooLarge,
}

async fn read_request_head<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<RequestHead> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while head.len() < MAX_REQUEST_HEAD_BYTES {
        let available = chunk.len().min(MAX_REQUEST_HEAD_BYTES - head.len());
        let n = stream.read(&mut chunk[..available]).await?;
        if n == 0 {
            return Ok(RequestHead::Incomplete);
        }
        let scan_from = head.len().saturating_sub(3);
        head.extend_from_slice(&chunk[..n]);
        if let Some(end) = head[scan_from..]
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
        {
            head.truncate(scan_from + end + 4);
            return Ok(RequestHead::Complete(head));
        }
    }
    Ok(RequestHead::TooLarge)
}

fn route_request(head: &[u8], sessions: &SessionMap) -> (&'static str, &'static str, String) {
    // Only the request line needs to be UTF-8/ASCII for routing. Header values
    // may contain other octets and are otherwise ignored by this endpoint.
    let line = head.split(|byte| *byte == b'\r').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return (
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "bad request\n".into(),
        );
    };
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty()
        || path.is_empty()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
    {
        return (
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "bad request\n".into(),
        );
    }
    if method != "GET" {
        return (
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n".into(),
        );
    }
    match path {
        "/metrics" => (
            "200 OK",
            "text/plain; version=0.0.4; charset=utf-8",
            render_metrics(sessions),
        ),
        "/healthz" | "/health" => ("200 OK", "text/plain; charset=utf-8", "ok\n".into()),
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".into(),
        ),
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    sessions: SessionMap,
) -> Result<()> {
    let head = tokio::time::timeout(Duration::from_secs(5), read_request_head(&mut stream))
        .await
        .context("request head read timed out")??;
    let (status, content_type, body) = match head {
        RequestHead::Complete(head) => route_request(&head, &sessions),
        RequestHead::Incomplete => (
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "incomplete request\n".into(),
        ),
        RequestHead::TooLarge => (
            "431 Request Header Fields Too Large",
            "text/plain; charset=utf-8",
            "request headers too large\n".into(),
        ),
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
    use tokio::net::TcpStream;

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

    async fn request_over_duplex(request: &[u8], capacity: usize) -> String {
        let (client, server) = tokio::io::duplex(capacity);
        let task = tokio::spawn(handle_connection(server, make_session_map()));
        let (mut reader, mut writer) = tokio::io::split(client);
        let write = async {
            let _ = writer.write_all(request).await;
            let _ = writer.shutdown().await;
        };
        let read = async {
            let mut response = String::new();
            reader.read_to_string(&mut response).await.unwrap();
            response
        };
        let (_, response) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(write, read) })
                .await
                .expect("HTTP exchange should finish");
        task.await.unwrap().unwrap();
        response
    }

    #[tokio::test]
    async fn test_http_request_arriving_one_byte_at_a_time() {
        for path in ["/metrics", "/healthz"] {
            // The one-byte duplex buffer guarantees read() cannot receive a
            // complete method, path, request line or CRLF terminator at once.
            let request = format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n");
            let response = request_over_duplex(request.as_bytes(), 1).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        }
    }

    #[tokio::test]
    async fn test_incomplete_and_malformed_requests_are_rejected() {
        for request in [
            "GET /metrics HTTP/1.1\r\nHost: x\r\n",
            "GET /metrics\r\n\r\n",
        ] {
            let response = request_over_duplex(request.as_bytes(), 1024).await;
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        }
    }

    #[tokio::test]
    async fn test_headers_larger_than_one_read_and_at_size_limit() {
        let prefix = "GET /metrics HTTP/1.1\r\nX-Test: ";
        for length in [2048, MAX_REQUEST_HEAD_BYTES] {
            let request = format!("{prefix}{}\r\n\r\n", "x".repeat(length - prefix.len() - 4));
            let response = request_over_duplex(request.as_bytes(), 64).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"));
            assert!(response.contains("ttl_probes_sent_total"));
        }
    }

    #[tokio::test]
    async fn test_headers_over_size_limit_are_rejected() {
        let request = format!(
            "GET /metrics HTTP/1.1\r\nX-Test: {}\r\n\r\n",
            "x".repeat(MAX_REQUEST_HEAD_BYTES)
        );
        let response = request_over_duplex(request.as_bytes(), 64).await;
        assert!(response.starts_with("HTTP/1.1 431"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_incomplete_request_has_a_total_read_deadline() {
        let (mut client, server) = tokio::io::duplex(64);
        let trickle = async {
            client.write_all(b"G").await.unwrap();
            tokio::time::sleep(Duration::from_secs(4)).await;
            client.write_all(b"E").await.unwrap();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(6), handle_connection(server, make_session_map())) => {
                let error = result.expect("partial reads must not restart the five-second deadline").unwrap_err();
                assert!(error.to_string().contains("timed out"));
            }
            _ = trickle => unreachable!(),
        }
    }

    #[tokio::test]
    async fn test_valid_unsupported_method_still_returns_405() {
        let response = request_over_duplex(b"POST /metrics HTTP/1.1\r\nHost: x\r\n\r\n", 1).await;
        assert!(response.starts_with("HTTP/1.1 405"));
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

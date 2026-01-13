use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

mod cli;
mod config;
mod export;
mod lookup;
mod prefs;
mod probe;
mod state;
mod trace;
mod tui;

use cli::Args;
use config::Config;
use export::{export_csv, export_json, generate_report};
use lookup::{run_asn_worker, run_dns_worker, run_geo_worker, AsnLookup, DnsLookup, GeoLookup};
use prefs::Prefs;
use probe::{check_permissions, validate_interface, InterfaceInfo};
use state::{Session, Target};
use trace::{new_pending_map, spawn_receiver, ProbeEngine, SessionMap};
use tui::{run_tui, Theme};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Handle replay mode (doesn't need permissions or target resolution)
    if let Some(ref replay_path) = args.replay {
        return run_replay_mode(&args, replay_path).await;
    }

    // Check permissions early
    if let Err(e) = check_permissions() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    // Validate interface early (before target resolution)
    let interface_info: Option<InterfaceInfo> = if let Some(ref name) = args.interface {
        match validate_interface(name) {
            Ok(info) => Some(info),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Resolve all targets
    let mut targets: Vec<IpAddr> = Vec::new();
    let mut sessions_map: HashMap<IpAddr, Arc<RwLock<Session>>> = HashMap::new();
    let config = Config::from(&args);

    for target_str in &args.targets {
        let resolved_ip = resolve_target(target_str, args.ipv4, args.ipv6)
            .with_context(|| format!("Failed to resolve target: {}", target_str))?;

        // Skip duplicate targets
        if sessions_map.contains_key(&resolved_ip) {
            eprintln!("Warning: Duplicate target {} ({}), skipping", target_str, resolved_ip);
            continue;
        }

        let target = Target::new(target_str.clone(), resolved_ip);
        let session = Session::new(target, config.clone());
        sessions_map.insert(resolved_ip, Arc::new(RwLock::new(session)));
        targets.push(resolved_ip);
    }

    if targets.is_empty() {
        anyhow::bail!("No valid targets specified");
    }

    // Create SessionMap (Arc<RwLock<HashMap>>)
    let sessions: SessionMap = Arc::new(RwLock::new(sessions_map));

    // Cancellation token for graceful shutdown
    let cancel = CancellationToken::new();

    // Setup Ctrl+C handler
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_clone.cancel();
    });

    // All targets must be same IP version for now (single receiver)
    let ipv6 = targets[0].is_ipv6();
    if targets.iter().any(|t| t.is_ipv6() != ipv6) {
        anyhow::bail!("Mixed IPv4/IPv6 targets not supported. Use -4 or -6 to force one version.");
    }

    // Validate interface has address matching target IP family
    if let Some(ref info) = interface_info {
        if ipv6 && info.ipv6.is_none() {
            eprintln!(
                "Error: Interface '{}' has no IPv6 address but targets require IPv6. \
                 Use -4 to force IPv4.",
                info.name
            );
            std::process::exit(1);
        }
        if !ipv6 && info.ipv4.is_none() {
            eprintln!(
                "Error: Interface '{}' has no IPv4 address but targets require IPv4. \
                 Use -6 to force IPv6.",
                info.name
            );
            std::process::exit(1);
        }
    }

    // Run in appropriate mode
    if args.is_batch_mode() {
        run_batch_mode(args, sessions, targets, config, cancel, interface_info).await
    } else if args.no_tui {
        run_streaming_mode(args, sessions, targets, config, cancel, interface_info).await
    } else {
        run_interactive_mode(args, sessions, targets, config, cancel, interface_info).await
    }
}

/// Load a session from a JSON file
fn load_session(path: &str) -> Result<Session> {
    const MAX_REPLAY_SIZE: u64 = 10 * 1024 * 1024; // 10MB

    let file = File::open(path)
        .with_context(|| format!("Failed to open replay file: {}", path))?;

    // Check file size to prevent DoS via huge JSON
    let metadata = file.metadata()
        .with_context(|| format!("Failed to read replay file metadata: {}", path))?;
    if metadata.len() > MAX_REPLAY_SIZE {
        anyhow::bail!("Replay file too large (max 10MB): {}", path);
    }

    let reader = BufReader::new(file);
    let session: Session = serde_json::from_reader(reader)
        .with_context(|| format!("Failed to parse replay file: {}", path))?;
    Ok(session)
}

/// Run replay mode - load a saved session and display/export it
async fn run_replay_mode(args: &Args, replay_path: &str) -> Result<()> {
    let session = load_session(replay_path)?;
    let target_ip = session.target.resolved;

    // Output based on flags
    if args.json {
        export_json(&session, std::io::stdout())?;
    } else if args.csv {
        export_csv(&session, std::io::stdout())?;
    } else if args.report || args.no_tui {
        // Default to report for replay without TUI
        generate_report(&session, std::io::stdout())?;
    } else {
        // Show in TUI (read-only)
        let state = Arc::new(RwLock::new(session));
        let cancel = CancellationToken::new();

        // Create SessionMap with single session
        let mut sessions_map: HashMap<IpAddr, Arc<RwLock<Session>>> = HashMap::new();
        sessions_map.insert(target_ip, state);
        let sessions: SessionMap = Arc::new(RwLock::new(sessions_map));
        let targets = vec![target_ip];

        // Load saved preferences
        let prefs = Prefs::load();

        // Determine theme: CLI override > saved preference > default
        let theme_name = if args.theme != "default" {
            &args.theme
        } else {
            prefs.theme.as_deref().unwrap_or("default")
        };
        let theme = Theme::by_name(theme_name);

        // Setup Ctrl+C handler
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_clone.cancel();
        });

        let final_theme = run_tui(sessions, targets, cancel, theme).await?;

        // Save theme preference (best effort, don't fail on save error)
        let mut prefs = Prefs::load();
        prefs.theme = Some(final_theme);
        let _ = prefs.save();
    }

    Ok(())
}

fn resolve_target(target: &str, force_ipv4: bool, force_ipv6: bool) -> Result<IpAddr> {
    // Try parsing as IP address first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Resolve hostname
    let addrs: Vec<_> = format!("{}:0", target)
        .to_socket_addrs()?
        .map(|s| s.ip())
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("No addresses found for hostname");
    }

    // Filter by IP version if requested
    let filtered: Vec<_> = addrs
        .iter()
        .filter(|ip| {
            if force_ipv4 {
                ip.is_ipv4()
            } else if force_ipv6 {
                ip.is_ipv6()
            } else {
                true
            }
        })
        .cloned()
        .collect();

    if filtered.is_empty() {
        anyhow::bail!("No {} addresses found", if force_ipv4 { "IPv4" } else { "IPv6" });
    }

    // Prefer IPv4 by default if no preference
    if !force_ipv6 {
        if let Some(ipv4) = filtered.iter().find(|ip| ip.is_ipv4()) {
            return Ok(*ipv4);
        }
    }

    Ok(filtered[0])
}

async fn run_interactive_mode(
    args: Args,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    config: Config,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        ipv6,
        config.src_port_base,
        config.flows,
        interface.clone(),
        config.recv_any,
    );

    // Spawn probe engine for each target
    let mut engine_handles = Vec::new();
    {
        let sessions_read = sessions.read();
        for target_ip in &targets {
            if let Some(state) = sessions_read.get(target_ip) {
                let engine = ProbeEngine::new(
                    config.clone(),
                    *target_ip,
                    state.clone(),
                    pending.clone(),
                    cancel.clone(),
                    interface.clone(),
                );
                let handle = tokio::spawn(async move { engine.run().await });
                engine_handles.push(handle);
            }
        }
    }

    // Spawn DNS worker (if enabled)
    let dns_handle = if config.dns_enabled {
        let dns = Arc::new(DnsLookup::new().await?);
        Some(tokio::spawn(run_dns_worker(dns, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(asn, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn GeoIP worker (if enabled and database available)
    let geo_handle = if config.geo_enabled {
        let geo_lookup = if let Some(ref path) = args.geoip_db {
            // Use explicit path from CLI
            match GeoLookup::new(path) {
                Ok(lookup) => Some(lookup),
                Err(e) => {
                    eprintln!("Warning: Failed to load GeoIP database '{}': {}", path, e);
                    None
                }
            }
        } else {
            // Try default paths
            GeoLookup::try_default()
        };

        if let Some(geo) = geo_lookup {
            Some(tokio::spawn(run_geo_worker(Arc::new(geo), sessions.clone(), cancel.clone())))
        } else {
            // No database found, continue without geo
            None
        }
    } else {
        None
    };

    // Load saved preferences
    let prefs = Prefs::load();

    // Determine theme: CLI override > saved preference > default
    let theme_name = if args.theme != "default" {
        &args.theme
    } else {
        prefs.theme.as_deref().unwrap_or("default")
    };
    let theme = Theme::by_name(theme_name);

    // Run TUI (with target list for cycling)
    let final_theme = run_tui(sessions.clone(), targets.clone(), cancel.clone(), theme).await?;

    // Save theme preference (best effort, don't fail on save error)
    let mut prefs = Prefs::load();
    prefs.theme = Some(final_theme);
    let _ = prefs.save();

    // Cleanup
    cancel.cancel();
    for handle in engine_handles {
        handle.await??;
    }
    receiver_handle.join().map_err(|e| {
        // This branch shouldn't be reached since we use catch_unwind in the receiver,
        // but handle it just in case something panics outside the protected region
        let msg = e.downcast_ref::<&str>().map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        anyhow::anyhow!("Receiver thread failed: {}", msg)
    })??;
    if let Some(handle) = dns_handle {
        handle.await?;
    }
    if let Some(handle) = asn_handle {
        handle.await?;
    }
    if let Some(handle) = geo_handle {
        handle.await?;
    }

    Ok(())
}

async fn run_batch_mode(
    args: Args,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    config: Config,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        ipv6,
        config.src_port_base,
        config.flows,
        interface.clone(),
        config.recv_any,
    );

    // Spawn probe engine for each target
    let mut engine_handles = Vec::new();
    {
        let sessions_read = sessions.read();
        for target_ip in &targets {
            if let Some(state) = sessions_read.get(target_ip) {
                let engine = ProbeEngine::new(
                    config.clone(),
                    *target_ip,
                    state.clone(),
                    pending.clone(),
                    cancel.clone(),
                    interface.clone(),
                );
                let handle = tokio::spawn(async move { engine.run().await });
                engine_handles.push(handle);
            }
        }
    }

    // Spawn DNS worker (if enabled)
    let dns_handle = if config.dns_enabled {
        let dns = Arc::new(DnsLookup::new().await?);
        Some(tokio::spawn(run_dns_worker(dns, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(asn, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn GeoIP worker (if enabled and database available)
    let geo_handle = if config.geo_enabled {
        let geo_lookup = if let Some(ref path) = args.geoip_db {
            match GeoLookup::new(path) {
                Ok(lookup) => Some(lookup),
                Err(e) => {
                    eprintln!("Warning: Failed to load GeoIP database '{}': {}", path, e);
                    None
                }
            }
        } else {
            GeoLookup::try_default()
        };

        if let Some(geo) = geo_lookup {
            Some(tokio::spawn(run_geo_worker(Arc::new(geo), sessions.clone(), cancel.clone())))
        } else {
            None
        }
    } else {
        None
    };

    // Wait for all engines to complete
    for handle in engine_handles {
        handle.await??;
    }

    // Wait for final responses and enrichment to settle
    tokio::time::sleep(config.timeout + Duration::from_millis(500)).await;
    cancel.cancel();

    receiver_handle.join().map_err(|e| {
        let msg = e.downcast_ref::<&str>().map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        anyhow::anyhow!("Receiver thread failed: {}", msg)
    })??;

    // Wait for enrichment workers to finish
    if let Some(handle) = dns_handle {
        handle.await?;
    }
    if let Some(handle) = asn_handle {
        handle.await?;
    }
    if let Some(handle) = geo_handle {
        handle.await?;
    }

    // Output results for all targets
    let sessions_read = sessions.read();
    for (i, target_ip) in targets.iter().enumerate() {
        if let Some(state) = sessions_read.get(target_ip) {
            let session = state.read();
            if targets.len() > 1 && !args.json {
                println!("\n=== Target {}/{}: {} ===\n", i + 1, targets.len(), target_ip);
            }
            if args.json {
                export_json(&*session, std::io::stdout())?;
            } else if args.report {
                generate_report(&*session, std::io::stdout())?;
            } else if args.csv {
                export_csv(&*session, std::io::stdout())?;
            }
        }
    }

    Ok(())
}

async fn run_streaming_mode(
    args: Args,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    config: Config,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        ipv6,
        config.src_port_base,
        config.flows,
        interface.clone(),
        config.recv_any,
    );

    // Spawn probe engine for each target
    let mut engine_handles = Vec::new();
    {
        let sessions_read = sessions.read();
        for target_ip in &targets {
            if let Some(state) = sessions_read.get(target_ip) {
                let engine = ProbeEngine::new(
                    config.clone(),
                    *target_ip,
                    state.clone(),
                    pending.clone(),
                    cancel.clone(),
                    interface.clone(),
                );
                let handle = tokio::spawn(async move { engine.run().await });
                engine_handles.push(handle);
            }
        }
    }

    // Spawn DNS worker (if enabled)
    let dns_handle = if config.dns_enabled {
        let dns = Arc::new(DnsLookup::new().await?);
        Some(tokio::spawn(run_dns_worker(dns, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(asn, sessions.clone(), cancel.clone())))
    } else {
        None
    };

    // Spawn GeoIP worker (if enabled and database available)
    let geo_handle = if config.geo_enabled {
        let geo_lookup = if let Some(ref path) = args.geoip_db {
            match GeoLookup::new(path) {
                Ok(lookup) => Some(lookup),
                Err(e) => {
                    eprintln!("Warning: Failed to load GeoIP database '{}': {}", path, e);
                    None
                }
            }
        } else {
            GeoLookup::try_default()
        };

        if let Some(geo) = geo_lookup {
            Some(tokio::spawn(run_geo_worker(Arc::new(geo), sessions.clone(), cancel.clone())))
        } else {
            None
        }
    } else {
        None
    };

    // Print results as they come in
    let mut last_total_received: HashMap<IpAddr, u64> = HashMap::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                let sessions_read = sessions.read();
                for target_ip in &targets {
                    if let Some(state) = sessions_read.get(target_ip) {
                        let session = state.read();
                        let total_received: u64 = session.hops.iter().map(|h| h.received).sum();
                        let last = last_total_received.get(target_ip).copied().unwrap_or(0);

                        if total_received > last {
                            if targets.len() > 1 {
                                println!("[{}]", target_ip);
                            }
                            // Print new results (with hostname if resolved)
                            for hop in &session.hops {
                                if hop.received > 0 {
                                    if let Some(stats) = hop.primary_stats() {
                                        let host = stats.hostname.as_deref().unwrap_or("");
                                        println!(
                                            "TTL {:2}  {:15}  {:20}  {:>6.2}ms  {:>5.1}% loss",
                                            hop.ttl,
                                            stats.ip,
                                            host,
                                            stats.avg_rtt().as_secs_f64() * 1000.0,
                                            hop.loss_pct()
                                        );
                                    }
                                }
                            }
                            println!("---");
                            last_total_received.insert(*target_ip, total_received);
                        }
                    }
                }
            }
        }
    }

    for handle in engine_handles {
        handle.await??;
    }
    receiver_handle.join().map_err(|e| {
        let msg = e.downcast_ref::<&str>().map(|s| s.to_string())
            .or_else(|| e.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        anyhow::anyhow!("Receiver thread failed: {}", msg)
    })??;

    // Wait for enrichment workers to finish
    if let Some(handle) = dns_handle {
        handle.await?;
    }
    if let Some(handle) = asn_handle {
        handle.await?;
    }
    if let Some(handle) = geo_handle {
        handle.await?;
    }

    Ok(())
}

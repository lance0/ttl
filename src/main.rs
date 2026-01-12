use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
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
use lookup::{run_dns_worker, DnsLookup};
use prefs::Prefs;
use probe::check_permissions;
use state::{Session, Target};
use trace::{new_pending_map, spawn_receiver, ProbeEngine};
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

    // Resolve target
    let target_str = &args.targets[0]; // MVP: single target
    let resolved_ip = resolve_target(target_str, args.ipv4, args.ipv6)
        .with_context(|| format!("Failed to resolve target: {}", target_str))?;

    let target = Target::new(target_str.clone(), resolved_ip);
    let config = Config::from(&args);

    // Create session
    let session = Session::new(target, config.clone());
    let state = Arc::new(RwLock::new(session));

    // Cancellation token for graceful shutdown
    let cancel = CancellationToken::new();

    // Setup Ctrl+C handler
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_clone.cancel();
    });

    // Run in appropriate mode
    if args.is_batch_mode() {
        run_batch_mode(args, state, config, resolved_ip, cancel).await
    } else if args.no_tui {
        run_streaming_mode(state, config, resolved_ip, cancel).await
    } else {
        run_interactive_mode(args, state, config, resolved_ip, cancel).await
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

        let final_theme = run_tui(state, cancel, theme).await?;

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
    state: Arc<RwLock<Session>>,
    config: Config,
    target_ip: IpAddr,
    cancel: CancellationToken,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // Spawn receiver thread
    let receiver_handle = spawn_receiver(
        state.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        target_ip.is_ipv6(),
    );

    // Spawn probe engine
    let engine = ProbeEngine::new(
        config.clone(),
        target_ip,
        state.clone(),
        pending,
        cancel.clone(),
    );
    let engine_handle = tokio::spawn(async move { engine.run().await });

    // Spawn DNS worker (if enabled)
    let dns_handle = if config.dns_enabled {
        let dns = Arc::new(DnsLookup::new().await?);
        Some(tokio::spawn(run_dns_worker(dns, state.clone(), cancel.clone())))
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

    // Run TUI
    let final_theme = run_tui(state.clone(), cancel.clone(), theme).await?;

    // Save theme preference (best effort, don't fail on save error)
    let mut prefs = Prefs::load();
    prefs.theme = Some(final_theme);
    let _ = prefs.save();

    // Cleanup
    cancel.cancel();
    engine_handle.await??;
    receiver_handle.join().map_err(|_| anyhow::anyhow!("Receiver thread panicked"))??;
    if let Some(handle) = dns_handle {
        handle.await?;
    }

    Ok(())
}

async fn run_batch_mode(
    args: Args,
    state: Arc<RwLock<Session>>,
    config: Config,
    target_ip: IpAddr,
    cancel: CancellationToken,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // Spawn receiver thread
    let receiver_handle = spawn_receiver(
        state.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        target_ip.is_ipv6(),
    );

    // Spawn probe engine
    let engine = ProbeEngine::new(
        config.clone(),
        target_ip,
        state.clone(),
        pending,
        cancel.clone(),
    );

    // Run engine to completion
    engine.run().await?;

    // Wait a bit for final responses
    tokio::time::sleep(config.timeout).await;
    cancel.cancel();

    receiver_handle.join().map_err(|_| anyhow::anyhow!("Receiver thread panicked"))??;

    // Output results
    let session = state.read();

    if args.json {
        export_json(&*session, std::io::stdout())?;
    } else if args.report {
        generate_report(&*session, std::io::stdout())?;
    } else if args.csv {
        export_csv(&*session, std::io::stdout())?;
    }

    Ok(())
}

async fn run_streaming_mode(
    state: Arc<RwLock<Session>>,
    config: Config,
    target_ip: IpAddr,
    cancel: CancellationToken,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // Spawn receiver thread
    let receiver_handle = spawn_receiver(
        state.clone(),
        pending.clone(),
        cancel.clone(),
        config.timeout,
        target_ip.is_ipv6(),
    );

    // Spawn probe engine
    let engine = ProbeEngine::new(
        config.clone(),
        target_ip,
        state.clone(),
        pending,
        cancel.clone(),
    );
    let engine_handle = tokio::spawn(async move { engine.run().await });

    // Print results as they come in
    let mut last_total_received: u64 = 0;
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                let session = state.read();
                let total_received: u64 = session.hops.iter().map(|h| h.received).sum();

                if total_received > last_total_received {
                    // Print new results
                    for hop in &session.hops {
                        if hop.received > 0 {
                            if let Some(stats) = hop.primary_stats() {
                                println!(
                                    "TTL {:2}  {:15}  {:>6.2}ms  {:>5.1}% loss",
                                    hop.ttl,
                                    stats.ip,
                                    stats.avg_rtt().as_secs_f64() * 1000.0,
                                    hop.loss_pct()
                                );
                            }
                        }
                    }
                    println!("---");
                    last_total_received = total_received;
                }
            }
        }
    }

    engine_handle.await??;
    receiver_handle.join().map_err(|_| anyhow::anyhow!("Receiver thread panicked"))??;

    Ok(())
}

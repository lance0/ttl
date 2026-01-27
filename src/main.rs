use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
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
mod update;

use cli::Args;
use config::Config;
use export::{export_csv, export_json, generate_report};
use lookup::asn::{AsnLookup, run_asn_worker};
use lookup::geo::{GeoLookup, run_geo_worker};
use lookup::ix::{IxLookup, run_ix_worker};
use lookup::rdns::{DnsLookup, run_dns_worker};
use prefs::{DisplayMode, Prefs};
use probe::{
    InterfaceInfo, check_permissions, detect_default_gateway, get_local_addr_with_interface,
    validate_interface,
};
use state::{Session, Target, run_ratelimit_worker};
use trace::engine::ProbeEngine;
use trace::pending::new_pending_map;
use trace::receiver::{ReceiverConfig, SessionMap, spawn_receiver};
use tui::app::{ReplayState, ResolveInfo, run_tui};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle shell completion generation (instant, no update check needed)
    if let Some(ref shell) = args.completions {
        generate_completions(shell);
        return Ok(());
    }

    // Handle replay mode (quick viewing operation, no update check)
    if let Some(ref replay_path) = args.replay {
        return run_replay_mode(&args, replay_path).await;
    }

    // Spawn background update check after early exits
    // Uses channel for non-blocking result retrieval at exit
    let (update_tx, update_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = update::check_for_update();
        let _ = update_tx.send(result); // Ignore if receiver dropped
    });

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
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

    // Resolve info for TUI status message
    let resolve_info = if args.resolve_all {
        // Use new resolve_targets function for --resolve-all mode
        let result = resolve_targets(&args.targets, true, args.ipv4, args.ipv6)
            .context("Failed to resolve targets")?;

        for (resolved_ip, primary, aliases) in result.targets {
            let mut target = Target::new(primary, resolved_ip);
            target.aliases = aliases;
            let mut session = Session::new(target, config.clone());

            // Set source IP and gateway for display in TUI
            let ipv6 = resolved_ip.is_ipv6();
            session.source_ip = config.source_ip.or_else(|| {
                let addr = get_local_addr_with_interface(resolved_ip, interface_info.as_ref());
                if addr.is_unspecified() {
                    None
                } else {
                    Some(addr)
                }
            });
            session.gateway = if let Some(ref info) = interface_info {
                if ipv6 {
                    info.gateway_ipv6.map(IpAddr::V6)
                } else {
                    info.gateway_ipv4.map(IpAddr::V4)
                }
            } else {
                detect_default_gateway(ipv6)
            };

            sessions_map.insert(resolved_ip, Arc::new(RwLock::new(session)));
            targets.push(resolved_ip);
        }

        Some(ResolveInfo {
            skipped_ipv4: result.skipped_ipv4,
            skipped_ipv6: result.skipped_ipv6,
        })
    } else {
        // Original behavior - resolve one IP per target
        for target_str in &args.targets {
            let resolved_ip = resolve_target(target_str, args.ipv4, args.ipv6)
                .with_context(|| format!("Failed to resolve target: {}", target_str))?;

            // Skip duplicate targets
            if sessions_map.contains_key(&resolved_ip) {
                eprintln!(
                    "Warning: Duplicate target {} ({}), skipping",
                    target_str, resolved_ip
                );
                continue;
            }

            let target = Target::new(target_str.clone(), resolved_ip);
            let mut session = Session::new(target, config.clone());

            // Set source IP and gateway for display in TUI
            let ipv6 = resolved_ip.is_ipv6();
            session.source_ip = config.source_ip.or_else(|| {
                let addr = get_local_addr_with_interface(resolved_ip, interface_info.as_ref());
                if addr.is_unspecified() {
                    None
                } else {
                    Some(addr)
                }
            });
            session.gateway = if let Some(ref info) = interface_info {
                if ipv6 {
                    info.gateway_ipv6.map(IpAddr::V6)
                } else {
                    info.gateway_ipv4.map(IpAddr::V4)
                }
            } else {
                detect_default_gateway(ipv6)
            };

            sessions_map.insert(resolved_ip, Arc::new(RwLock::new(session)));
            targets.push(resolved_ip);
        }

        None
    };

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

    // Validate source IP matches target IP family
    if let Some(source_ip) = config.source_ip
        && source_ip.is_ipv6() != ipv6
    {
        eprintln!(
            "Error: Source IP {} is {} but targets are {}. \
             Use -4 or -6 to force matching IP version.",
            source_ip,
            if source_ip.is_ipv6() { "IPv6" } else { "IPv4" },
            if ipv6 { "IPv6" } else { "IPv4" }
        );
        std::process::exit(1);
    }

    // Run in appropriate mode
    let result = if args.is_batch_mode() {
        run_batch_mode(
            args,
            sessions,
            targets,
            config,
            cancel,
            interface_info,
            resolve_info,
        )
        .await
    } else if args.no_tui {
        run_streaming_mode(
            args,
            sessions,
            targets,
            config,
            cancel,
            interface_info,
            resolve_info,
        )
        .await
    } else {
        // Interactive (TUI) mode - pass update_rx for in-app notification
        return run_interactive_mode(
            args,
            sessions,
            targets,
            config,
            cancel,
            interface_info,
            resolve_info,
            update_rx,
        )
        .await;
    };

    // Check for update notification (only for non-interactive mode)
    // Use short timeout so we don't delay exit if check is slow
    if is_terminal::is_terminal(std::io::stderr()) {
        if let Ok(Some(new_version)) = update_rx.recv_timeout(Duration::from_millis(100)) {
            update::print_update_notice(&new_version);
        }
    }

    result
}

/// Load a session from a JSON file
fn load_session(path: &str) -> Result<Session> {
    const MAX_REPLAY_SIZE: u64 = 10 * 1024 * 1024; // 10MB

    let file = File::open(path).with_context(|| format!("Failed to open replay file: {}", path))?;

    // Check file size to prevent DoS via huge JSON
    let metadata = file
        .metadata()
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
        // Check for animated replay mode
        let (session_to_display, replay_state) = if args.animate {
            if session.events.is_empty() {
                eprintln!("Note: No event timeline in session file; showing final state.");
                (session, None)
            } else {
                // Create fresh session with same config but no data
                let events = session.events.clone();
                let fresh_session = Session::new(session.target.clone(), session.config.clone());
                let replay = ReplayState::new(events, args.speed);
                (fresh_session, Some(replay))
            }
        } else {
            (session, None)
        };

        // Show in TUI
        let state = Arc::new(RwLock::new(session_to_display));
        let cancel = CancellationToken::new();

        // Create SessionMap with single session
        let mut sessions_map: HashMap<IpAddr, Arc<RwLock<Session>>> = HashMap::new();
        sessions_map.insert(target_ip, state);
        let sessions: SessionMap = Arc::new(RwLock::new(sessions_map));
        let targets = vec![target_ip];

        // Load saved preferences
        let mut prefs = Prefs::load();

        // Apply CLI overrides
        if args.theme != "default" {
            prefs.theme = Some(args.theme.clone());
        }
        if args.wide {
            prefs.display_mode = Some(DisplayMode::Wide);
        }

        // Setup Ctrl+C handler
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            cancel_clone.cancel();
        });

        let final_prefs = run_tui(
            sessions,
            targets,
            cancel,
            prefs,
            None,
            None,
            None,
            replay_state,
        )
        .await?;

        // Save preferences (best effort, don't fail on save error)
        let _ = final_prefs.save();
    }

    Ok(())
}

/// Result of resolving targets with --resolve-all
struct ResolveResult {
    /// (ip, primary_hostname, aliases) tuples
    targets: Vec<(IpAddr, String, Vec<String>)>,
    skipped_ipv4: usize,
    skipped_ipv6: usize,
}

/// Resolve all IP addresses for a hostname
fn resolve_all_ips(target: &str) -> Result<Vec<IpAddr>> {
    // Try parsing as IP address first
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    // Resolve hostname - get all addresses
    let addrs: Vec<_> = format!("{}:0", target)
        .to_socket_addrs()?
        .map(|s| s.ip())
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("No addresses found for hostname");
    }

    Ok(addrs)
}

/// Resolve targets with optional resolve-all mode
fn resolve_targets(
    target_strs: &[String],
    resolve_all: bool,
    force_ipv4: bool,
    force_ipv6: bool,
) -> Result<ResolveResult> {
    // Track insertion order
    let mut order: Vec<IpAddr> = Vec::new();
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut ip_to_hostnames: HashMap<IpAddr, Vec<String>> = HashMap::new();

    for target_str in target_strs {
        let ips = if resolve_all {
            resolve_all_ips(target_str)?
        } else {
            vec![resolve_target(target_str, force_ipv4, force_ipv6)?]
        };

        for ip in ips {
            if seen.insert(ip) {
                order.push(ip);
            }
            ip_to_hostnames
                .entry(ip)
                .or_default()
                .push(target_str.clone());
        }
    }

    if order.is_empty() {
        anyhow::bail!("No addresses found for hostnames");
    }

    let use_ipv6 = if force_ipv6 {
        true
    } else if force_ipv4 {
        false
    } else {
        // Use IPv6, if first resolved address is IPv6
        order[0].is_ipv6()
    };

    let mut targets = Vec::new();
    let mut skipped_ipv4 = 0;
    let mut skipped_ipv6 = 0;

    for ip in order {
        if ip.is_ipv6() == use_ipv6 {
            let hostnames = ip_to_hostnames.remove(&ip).unwrap();
            let primary = hostnames[0].clone();
            let aliases: Vec<String> = hostnames.into_iter().skip(1).collect();
            targets.push((ip, primary, aliases));
        } else if ip.is_ipv6() {
            skipped_ipv6 += 1;
        } else {
            skipped_ipv4 += 1;
        }
    }

    if targets.is_empty() {
        anyhow::bail!(
            "No {} addresses found for targets",
            if use_ipv6 { "IPv6" } else { "IPv4" }
        );
    }

    Ok(ResolveResult {
        targets,
        skipped_ipv4,
        skipped_ipv6,
    })
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
        anyhow::bail!(
            "No {} addresses found",
            if force_ipv4 { "IPv4" } else { "IPv6" }
        );
    }

    Ok(filtered[0])
}

#[allow(clippy::too_many_arguments)]
async fn run_interactive_mode(
    args: Args,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    config: Config,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
    resolve_info: Option<ResolveInfo>,
    update_rx: std::sync::mpsc::Receiver<Option<String>>,
) -> Result<()> {
    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_config = ReceiverConfig {
        timeout: config.timeout,
        ipv6,
        src_port_base: config.src_port_base,
        num_flows: config.flows,
        interface: interface.clone(),
        recv_any: config.recv_any,
    };
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        receiver_config,
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
        Some(tokio::spawn(run_dns_worker(
            dns,
            sessions.clone(),
            cancel.clone(),
        )))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(
            asn,
            sessions.clone(),
            cancel.clone(),
        )))
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

        geo_lookup.map(|geo| {
            tokio::spawn(run_geo_worker(
                Arc::new(geo),
                sessions.clone(),
                cancel.clone(),
            ))
        })
    } else {
        None
    };

    // Load saved preferences (before IX setup so we can use API key)
    let mut prefs = Prefs::load();

    // Apply CLI overrides
    if args.theme != "default" {
        prefs.theme = Some(args.theme.clone());
    }
    if args.wide {
        prefs.display_mode = Some(DisplayMode::Wide);
    }

    // Spawn IX worker (if enabled) - keep Arc for TUI access
    let ix_lookup: Option<Arc<IxLookup>> = if config.ix_enabled {
        match IxLookup::new() {
            Ok(ix) => {
                // Set API key from preferences (env var takes precedence in get_effective_api_key)
                if let Some(ref key) = prefs.peeringdb_api_key {
                    ix.set_api_key(Some(key.clone()));
                }
                Some(Arc::new(ix))
            }
            Err(e) => {
                eprintln!("Warning: Failed to initialize IX lookup: {}", e);
                None
            }
        }
    } else {
        None
    };

    let ix_handle = ix_lookup.as_ref().map(|ix| {
        tokio::spawn(run_ix_worker(
            Arc::clone(ix),
            sessions.clone(),
            cancel.clone(),
        ))
    });

    // Spawn rate limit detection worker (always enabled, lightweight analysis)
    let ratelimit_handle = tokio::spawn(run_ratelimit_worker(sessions.clone(), cancel.clone()));

    // Check for update result - background check runs during target resolution
    // Use short timeout since check should already be complete; don't delay startup
    let update_available = update_rx
        .recv_timeout(Duration::from_secs(1))
        .ok()
        .flatten();

    // Run TUI (with target list for cycling)
    let final_prefs = run_tui(
        sessions.clone(),
        targets.clone(),
        cancel.clone(),
        prefs,
        resolve_info,
        ix_lookup.clone(),
        update_available,
        None, // replay_state (live mode)
    )
    .await?;

    // Save preferences (best effort, don't fail on save error)
    let _ = final_prefs.save();

    // Cleanup
    cancel.cancel();
    for handle in engine_handles {
        handle.await??;
    }
    receiver_handle.join().map_err(|e| {
        // This branch shouldn't be reached since we use catch_unwind in the receiver,
        // but handle it just in case something panics outside the protected region
        let msg = e
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
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
    if let Some(handle) = ix_handle {
        handle.await?;
    }
    ratelimit_handle.await?;

    Ok(())
}

async fn run_batch_mode(
    args: Args,
    sessions: SessionMap,
    targets: Vec<IpAddr>,
    config: Config,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
    resolve_info: Option<ResolveInfo>,
) -> Result<()> {
    // Print skip warnings for non-TUI mode
    if let Some(ref info) = resolve_info {
        if info.skipped_ipv6 > 0 {
            eprintln!(
                "Note: {} IPv6 addresses skipped (using IPv4)",
                info.skipped_ipv6
            );
        }
        if info.skipped_ipv4 > 0 {
            eprintln!(
                "Note: {} IPv4 addresses skipped (using IPv6)",
                info.skipped_ipv4
            );
        }
    }

    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_config = ReceiverConfig {
        timeout: config.timeout,
        ipv6,
        src_port_base: config.src_port_base,
        num_flows: config.flows,
        interface: interface.clone(),
        recv_any: config.recv_any,
    };
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        receiver_config,
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
        Some(tokio::spawn(run_dns_worker(
            dns,
            sessions.clone(),
            cancel.clone(),
        )))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(
            asn,
            sessions.clone(),
            cancel.clone(),
        )))
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

        geo_lookup.map(|geo| {
            tokio::spawn(run_geo_worker(
                Arc::new(geo),
                sessions.clone(),
                cancel.clone(),
            ))
        })
    } else {
        None
    };

    // Spawn IX worker (if enabled)
    let ix_handle = if config.ix_enabled {
        match IxLookup::new() {
            Ok(ix) => Some(tokio::spawn(run_ix_worker(
                Arc::new(ix),
                sessions.clone(),
                cancel.clone(),
            ))),
            Err(e) => {
                eprintln!("Warning: Failed to initialize IX lookup: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Spawn rate limit detection worker (always enabled, lightweight analysis)
    let ratelimit_handle = tokio::spawn(run_ratelimit_worker(sessions.clone(), cancel.clone()));

    // Wait for all engines to complete
    for handle in engine_handles {
        handle.await??;
    }

    // Wait for final responses and enrichment to settle
    tokio::time::sleep(config.timeout + Duration::from_millis(500)).await;
    cancel.cancel();

    receiver_handle.join().map_err(|e| {
        let msg = e
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
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
    if let Some(handle) = ix_handle {
        handle.await?;
    }
    ratelimit_handle.await?;

    // Output results for all targets
    let sessions_read = sessions.read();

    // Handle JSON output separately for proper array formatting
    if args.json {
        if targets.len() > 1 {
            // Multi-target: output as JSON array
            print!("[");
            let mut first = true;
            for target_ip in targets.iter() {
                if let Some(state) = sessions_read.get(target_ip) {
                    let session = state.read();
                    if !first {
                        print!(",");
                    }
                    first = false;
                    serde_json::to_writer(std::io::stdout(), &*session)?;
                }
            }
            println!("]");
        } else if let Some(state) = sessions_read.get(&targets[0]) {
            // Single target: output as-is (backwards compatible)
            export_json(&state.read(), std::io::stdout())?;
        }
    } else {
        // Non-JSON output
        for (i, target_ip) in targets.iter().enumerate() {
            if let Some(state) = sessions_read.get(target_ip) {
                let session = state.read();
                if targets.len() > 1 {
                    println!(
                        "\n=== Target {}/{}: {} ===\n",
                        i + 1,
                        targets.len(),
                        target_ip
                    );
                }
                if args.report {
                    generate_report(&session, std::io::stdout())?;
                } else if args.csv {
                    export_csv(&session, std::io::stdout())?;
                }
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
    resolve_info: Option<ResolveInfo>,
) -> Result<()> {
    // Print skip warnings for non-TUI mode
    if let Some(ref info) = resolve_info {
        if info.skipped_ipv6 > 0 {
            eprintln!(
                "Note: {} IPv6 addresses skipped (using IPv4)",
                info.skipped_ipv6
            );
        }
        if info.skipped_ipv4 > 0 {
            eprintln!(
                "Note: {} IPv4 addresses skipped (using IPv6)",
                info.skipped_ipv4
            );
        }
    }

    // Shared pending map for probe correlation (engine writes, receiver reads)
    let pending = new_pending_map();

    // All targets must be same IP version (validated in main)
    let ipv6 = targets[0].is_ipv6();

    // Spawn receiver thread (handles all targets)
    let receiver_config = ReceiverConfig {
        timeout: config.timeout,
        ipv6,
        src_port_base: config.src_port_base,
        num_flows: config.flows,
        interface: interface.clone(),
        recv_any: config.recv_any,
    };
    let receiver_handle = spawn_receiver(
        sessions.clone(),
        pending.clone(),
        cancel.clone(),
        receiver_config,
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
        Some(tokio::spawn(run_dns_worker(
            dns,
            sessions.clone(),
            cancel.clone(),
        )))
    } else {
        None
    };

    // Spawn ASN worker (if enabled)
    let asn_handle = if config.asn_enabled {
        let asn = Arc::new(AsnLookup::new().await?);
        Some(tokio::spawn(run_asn_worker(
            asn,
            sessions.clone(),
            cancel.clone(),
        )))
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

        geo_lookup.map(|geo| {
            tokio::spawn(run_geo_worker(
                Arc::new(geo),
                sessions.clone(),
                cancel.clone(),
            ))
        })
    } else {
        None
    };

    // Spawn IX worker (if enabled)
    let ix_handle = if config.ix_enabled {
        match IxLookup::new() {
            Ok(ix) => Some(tokio::spawn(run_ix_worker(
                Arc::new(ix),
                sessions.clone(),
                cancel.clone(),
            ))),
            Err(e) => {
                eprintln!("Warning: Failed to initialize IX lookup: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Spawn rate limit detection worker (always enabled, lightweight analysis)
    let ratelimit_handle = tokio::spawn(run_ratelimit_worker(sessions.clone(), cancel.clone()));

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
                                if hop.received > 0
                                    && let Some(stats) = hop.primary_stats()
                                {
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
        let msg = e
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
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
    if let Some(handle) = ix_handle {
        handle.await?;
    }
    ratelimit_handle.await?;

    Ok(())
}

/// Generate shell completions for the specified shell
fn generate_completions(shell: &str) {
    use clap::CommandFactory;
    use clap_complete::{Shell, generate};
    let mut cmd = Args::command();
    let shell = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "powershell" => Shell::PowerShell,
        _ => unreachable!(),
    };
    generate(shell, &mut cmd, "ttl", &mut std::io::stdout());
}

mod bypass;
mod config;
mod packet;
mod tcp;
mod tor;
mod tun;
mod udp;

use anyhow::Result;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use config::Config;

fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();
}

fn get_physical_interface_index(tun_name: &str) -> Result<u32> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ip", "show", "interface"])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to list interfaces: {e}"))?;

    let text = String::from_utf8_lossy(&output.stdout);
    let mut candidates: Vec<(u32, String)> = Vec::new();

    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with("Idx") || stripped.starts_with("--") {
            continue;
        }
        let parts: Vec<&str> = stripped.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let idx: u32 = match parts[0].parse() { Ok(n) => n, Err(_) => continue };
        let name = parts.last().unwrap_or(&"");
        if name.contains("Loopback") || *name == tun_name { continue; }
        if parts[2] != "connected" { continue; }
        candidates.push((idx, name.to_string()));
    }

    candidates
        .first()
        .map(|(i, _)| *i)
        .ok_or_else(|| anyhow::anyhow!("No physical network interface found"))
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let config = Config::parse();

    info!("TorVPN v{} starting...", env!("CARGO_PKG_VERSION"));
    info!("TUN: {}/{}", config.tun_ip, config.tun_prefix_len);
    info!("Tor: {}:{}", config.tor_host, config.tor_port);

    // Start Tor
    let mut tor_manager = tor::TorManager::new(&config.tor_dir);
    tor_manager.start(&config).await?;

    // Create TUN
    let tun = tun::TunHandle::new(&config)?;
    info!("TUN interface ready");

    // Get physical interface index for IP_UNICAST_IF
    let physical_if_idx = get_physical_interface_index(&config.tun_name)?;
    info!("Physical interface index: {physical_if_idx}");

    // Create TCP proxy
    let mut tcp_proxy = tcp::TcpProxy::new(
        physical_if_idx,
        config.tor_host.clone(),
        config.tor_port,
        config.tor_outbound_ip,
        config.tun_ip,
    );

    // Create UDP forwarder
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut udp_forwarder = udp::UdpForwarder::new(physical_if_idx, shutdown.clone());

    // TUN writer closure
    let tun_writer = |data: &[u8]| {
        if let Err(e) = tun.write(data) {
            tracing::warn!("TUN write error: {e}");
        }
    };

    info!("TorVPN is running. Press Ctrl+C to stop.");
    let mut tick: u64 = 0;

    loop {
        // Read packets from TUN (non-blocking)
        while let Some(packet) = tun.try_read() {
            // Classify by IP protocol
            if let Some(info) = packet::classify_packet(&packet) {
                match info.transport {
                    packet::TransportInfo::Udp(_) => {
                        udp_forwarder.handle_packet(
                            &packet,
                            config.tun_ip,
                            config.tor_outbound_ip,
                        );
                    }
                    _ => {
                        tcp_proxy.handle_packet(&packet);
                    }
                }
            }
        }

        // Process TCP responses (data from SOCKS5 back to apps)
        tcp_proxy.process_responses(&tun_writer);

        // Poll UDP responses from NAT sockets
        udp_forwarder.poll_responses(&tun_writer);

        // Periodic logging
        tick += 1;
        if tick % 200 == 0 {
            debug!(
                "Running | TCP sessions: {} | UDP NAT: {}",
                tcp_proxy.session_count(),
                udp_forwarder.entry_count(),
            );
        }

        // Check for Ctrl+C every ~50ms
        if tick % 10 == 0 {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down...");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // Cleanup
    info!("Shutting down...");
    shutdown.store(true, Ordering::Relaxed);
    tor_manager.stop()?;
    info!("TorVPN stopped. Goodbye!");

    Ok(())
}
